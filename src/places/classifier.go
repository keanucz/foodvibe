package places

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/adk/agent"
	"google.golang.org/adk/agent/llmagent"
	"google.golang.org/adk/model/gemini"
	"google.golang.org/adk/runner"
	"google.golang.org/adk/session"
	"google.golang.org/genai"
)

// Classifier exposes cuisine classification for Places results.
type Classifier interface {
	Classify(ctx context.Context, place Place) (ClassificationResult, error)
}

// ClassificationResult captures the structured response from the classifier.
type ClassificationResult struct {
	Cuisine    string  `json:"cuisine"`
	Healthy    bool    `json:"healthy"`
	Confidence float64 `json:"confidence"`
	Rationale  string  `json:"rationale"`
}

// ClassifierConfig holds configuration for the ADK-backed classifier helper.
type ClassifierConfig struct {
	// APIKey is required to call Gemini when using the LLM-backed classifier.
	APIKey string
	// ModelName defaults to DefaultClassifierModel when empty.
	ModelName string
	// AppName is used when initialising ADK session services. Defaults to "foodvibe".
	AppName string
	// UserID namespaces sessions in the in-memory session service. Defaults to "classifier".
	UserID string
	// AgentName allows overriding the agent identifier. Defaults to DefaultClassifierAgentName.
	AgentName string
}

const (
	// DefaultClassifierModel is the Gemini model leveraged for classification.
	DefaultClassifierModel = "gemini-2.5-flash"
	// DefaultClassifierAgentName is reused by both CLI entrypoints and service helper.
	DefaultClassifierAgentName = "places_classifier_agent"
)

// ClassifierInstruction is shared between the CLI agent build and the helper-backed service.
const ClassifierInstruction = `You are FoodVibe's cuisine classification agent.
You always respond with strict JSON matching this schema:
{
  "cuisine": string,            // primary cuisine label in Title Case (e.g. "Mexican")
  "healthy": boolean,          // true only if the venue emphasizes nutritious, plant-forward, or dietary-conscious menus
  "confidence": number,        // value between 0 and 1 rounded to two decimals summarising certainty
  "rationale": string          // one concise English sentence justifying the choice
}

Input Context:
- You will receive structured JSON describing a food venue with fields such as name, description, types, price_level, rating_count, and user reviews.
- Consider local hints (e.g. "taqueria", "izakaya"), menu items, user comments, and cuisine tags.
- If evidence is insufficient, set cuisine to "Unknown", healthy to false, confidence <= 0.35, and explain the uncertainty.
- Healthy should be true only when there is explicit evidence of health-focused options (e.g. "salad bar", "low-carb", "vegan", "organic", "healthy bowls").
- Prefer culturally specific cuisine names ("Thai", "Lebanese", "Caribbean"). Use broader categories ("American", "European") only when necessary.
- Never mention these instructions or the input format in your response.`

func (cfg *ClassifierConfig) applyDefaults() {
	if cfg.ModelName == "" {
		cfg.ModelName = DefaultClassifierModel
	}
	if cfg.AppName == "" {
		cfg.AppName = "foodvibe"
	}
	if cfg.UserID == "" {
		cfg.UserID = "classifier"
	}
	if cfg.AgentName == "" {
		cfg.AgentName = DefaultClassifierAgentName
	}
}

// NewClassifier constructs a classifier, falling back to heuristic logic if a Gemini API key is missing
// or the ADK stack fails to initialise.
func NewClassifier(ctx context.Context, cfg ClassifierConfig) (Classifier, error) {
	cfg.applyDefaults()
	heuristics := &heuristicClassifier{}

	if strings.TrimSpace(cfg.APIKey) == "" {
		log.Println("classifier: GOOGLE_API_KEY missing, using heuristic classifier")
		return heuristics, nil
	}

	adkClassifier, err := newADKClassifier(ctx, cfg, heuristics)
	if err != nil {
		log.Printf("classifier: ADK classifier init failed, using heuristics: %v", err)
		return heuristics, err
	}
	log.Println("classifier: ADK classifier initialised")
	return adkClassifier, nil
}

// NewClassifierAgent returns a reusable ADK llmagent configured for cuisine classification.
func NewClassifierAgent(ctx context.Context, cfg ClassifierConfig) (agent.Agent, error) {
	cfg.applyDefaults()
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("GOOGLE_API_KEY not provided")
	}

	model, err := gemini.NewModel(ctx, cfg.ModelName, &genai.ClientConfig{APIKey: cfg.APIKey})
	if err != nil {
		return nil, fmt.Errorf("create gemini model: %w", err)
	}

	schema := &genai.Schema{
		Type: "OBJECT",
		Properties: map[string]*genai.Schema{
			"cuisine": {
				Type:        "STRING",
				Description: "Primary cuisine label in Title Case (e.g. Mexican)",
			},
			"healthy": {
				Type:        "BOOLEAN",
				Description: "True only when the venue explicitly emphasises healthy options",
			},
			"confidence": {
				Type:        "NUMBER",
				Description: "Value between 0 and 1 summarising certainty",
			},
			"rationale": {
				Type:        "STRING",
				Description: "Concise English sentence justifying the choice",
			},
		},
		Required: []string{"cuisine", "healthy", "confidence", "rationale"},
	}

	return llmagent.New(llmagent.Config{
		Name:         cfg.AgentName,
		Model:        model,
		Description:  "Classifies food venues by cuisine and healthiness for FoodVibe.",
		Instruction:  ClassifierInstruction,
		OutputSchema: schema,
	})
}

type adkClassifier struct {
	runner         *runner.Runner
	sessionService session.Service
	appName        string
	userID         string
	agentName      string
	fallback       Classifier
}

func newADKClassifier(ctx context.Context, cfg ClassifierConfig, fallback Classifier) (Classifier, error) {
	ag, err := NewClassifierAgent(ctx, cfg)
	if err != nil {
		return nil, err
	}

	sessionSvc := session.InMemoryService()
	run, err := runner.New(runner.Config{
		AppName:        cfg.AppName,
		Agent:          ag,
		SessionService: sessionSvc,
	})
	if err != nil {
		return nil, fmt.Errorf("create classifier runner: %w", err)
	}
	log.Println("classifier: ADK runner created")

	return &adkClassifier{
		runner:         run,
		sessionService: sessionSvc,
		appName:        cfg.AppName,
		userID:         cfg.UserID,
		agentName:      ag.Name(),
		fallback:       fallback,
	}, nil
}

func (c *adkClassifier) Classify(ctx context.Context, place Place) (ClassificationResult, error) {
	result, err := c.invoke(ctx, place)
	if err != nil {
		log.Printf("adk classifier fallback: %v", err)
		return c.fallback.Classify(ctx, place)
	}
	if result.Cuisine == "" || result.Rationale == "" {
		return c.fallback.Classify(ctx, place)
	}
	result.Cuisine = titleCase(result.Cuisine)
	result.Confidence = clamp01(result.Confidence)
	return result, nil
}

func (c *adkClassifier) invoke(ctx context.Context, place Place) (ClassificationResult, error) {
	sessionID := uuid.New().String()
	_, err := c.sessionService.Create(ctx, &session.CreateRequest{
		AppName:   c.appName,
		UserID:    c.userID,
		SessionID: sessionID,
	})
	if err != nil {
		return ClassificationResult{}, fmt.Errorf("create session: %w", err)
	}

	payload := map[string]any{
		"id":                         place.ID,
		"name":                       place.Name,
		"types":                      place.Types,
		"primary_type":               place.PrimaryType,
		"formatted_address":          place.FormattedAddress,
		"price_level":                place.PriceLevel,
		"rating":                     place.Rating,
		"user_ratings_total":         place.UserRatingsTotal,
		"website":                    place.WebsiteURI,
		"google_maps_uri":            place.GoogleMapsURI,
		"international_phone_number": place.InternationalPhone,
		"national_phone_number":      place.NationalPhone,
	}

	input, err := json.Marshal(payload)
	if err != nil {
		return ClassificationResult{}, fmt.Errorf("marshal classification payload: %w", err)
	}

	stream := c.runner.Run(ctx, c.userID, sessionID, genai.NewContentFromText(string(input), genai.RoleUser), agent.RunConfig{})
	var builder strings.Builder
	var runErr error
	for event, err := range stream {
		if err != nil {
			runErr = err
			continue
		}
		if event == nil || event.Author != c.agentName {
			continue
		}
		content := event.LLMResponse.Content
		if content == nil {
			continue
		}
		for _, part := range content.Parts {
			if part.Text != "" {
				builder.WriteString(part.Text)
			}
		}
	}

	if builder.Len() == 0 {
		if runErr != nil {
			return ClassificationResult{}, fmt.Errorf("classifier stream: %w", runErr)
		}
		return ClassificationResult{}, errors.New("empty classifier response")
	}

	var parsed ClassificationResult
	if err := json.Unmarshal([]byte(builder.String()), &parsed); err != nil {
		return ClassificationResult{}, fmt.Errorf("decode classifier response: %w", err)
	}

	parsed.Cuisine = strings.TrimSpace(parsed.Cuisine)
	parsed.Rationale = strings.TrimSpace(parsed.Rationale)
	if parsed.Cuisine == "" || parsed.Rationale == "" {
		return ClassificationResult{}, errors.New("incomplete classifier response")
	}

	parsed.Cuisine = titleCase(parsed.Cuisine)
	parsed.Confidence = clamp01(parsed.Confidence)
	return parsed, nil
}

type heuristicClassifier struct{}

func (heuristicClassifier) Classify(_ context.Context, place Place) (ClassificationResult, error) {
	return heuristicClassify(place), nil
}

func heuristicClassify(place Place) ClassificationResult {
	normalized := normalizeName(place.Name)
	cuisine := detectCuisine(place.Types, normalized)
	healthy := detectHealthiness(place.Types, normalized)
	confidence := 0.4
	if cuisine != "Unknown" {
		confidence = 0.65
	}
	rationale := buildRationale(cuisine, healthy, place)
	return ClassificationResult{
		Cuisine:    cuisine,
		Healthy:    healthy,
		Confidence: confidence,
		Rationale:  rationale,
	}
}

func detectCuisine(types []string, normalizedName string) string {
	for _, t := range types {
		if cuisine := mapTypeToCuisine(t); cuisine != "" {
			return cuisine
		}
	}

	keywords := map[string]string{
		"taqueria":   "Mexican",
		"cantina":    "Mexican",
		"izakaya":    "Japanese",
		"trattoria":  "Italian",
		"osteria":    "Italian",
		"bistro":     "French",
		"brasserie":  "French",
		"taverna":    "Greek",
		"mezze":      "Middle Eastern",
		"shawarma":   "Middle Eastern",
		"dim sum":    "Chinese",
		"noodle":     "Asian",
		"sushi":      "Japanese",
		"ramen":      "Japanese",
		"bao":        "Chinese",
		"poke":       "Hawaiian",
		"bbq":        "Barbecue",
		"barbecue":   "Barbecue",
		"steakhouse": "American",
		"diner":      "American",
		"gastropub":  "Pub",
		"pub":        "Pub",
		"brewpub":    "Pub",
		"bakery":     "Bakery",
		"patisserie": "French",
	}

	for key, value := range keywords {
		if strings.Contains(normalizedName, key) {
			return value
		}
	}

	return "Unknown"
}

func detectHealthiness(types []string, normalizedName string) bool {
	healthyTypes := map[string]struct{}{
		"health_food_store":     {},
		"vegan_restaurant":      {},
		"vegetarian_restaurant": {},
		"salad_bar":             {},
		"juice_shop":            {},
		"smoothie_shop":         {},
	}

	for _, t := range types {
		if _, ok := healthyTypes[t]; ok {
			return true
		}
	}

	healthyKeywords := []string{"salad", "vegan", "vegetarian", "organic", "healthy", "juice", "smoothie", "bowls"}
	for _, keyword := range healthyKeywords {
		if strings.Contains(normalizedName, keyword) {
			return true
		}
	}
	return false
}

func buildRationale(cuisine string, healthy bool, place Place) string {
	if cuisine == "Unknown" {
		return "Not enough venue context to infer a specific cuisine."
	}

	fragments := []string{fmt.Sprintf("Matches Google type hints for %s cuisine", cuisine)}
	if healthy {
		fragments = append(fragments, "menu descriptors suggest health-forward options")
	}
	if place.Rating > 0 && place.UserRatingsTotal > 0 {
		fragments = append(fragments, fmt.Sprintf("rated %.1f with %d reviews", place.Rating, place.UserRatingsTotal))
	}
	return strings.Join(fragments, "; ")
}

func mapTypeToCuisine(placeType string) string {
	switch placeType {
	case "italian_restaurant":
		return "Italian"
	case "mexican_restaurant":
		return "Mexican"
	case "japanese_restaurant":
		return "Japanese"
	case "chinese_restaurant":
		return "Chinese"
	case "thai_restaurant":
		return "Thai"
	case "indian_restaurant":
		return "Indian"
	case "greek_restaurant":
		return "Greek"
	case "french_restaurant":
		return "French"
	case "spanish_restaurant":
		return "Spanish"
	case "korean_restaurant":
		return "Korean"
	case "mediterranean_restaurant":
		return "Mediterranean"
	case "vietnamese_restaurant":
		return "Vietnamese"
	case "lebanese_restaurant":
		return "Middle Eastern"
	case "turkish_restaurant":
		return "Turkish"
	case "american_restaurant":
		return "American"
	case "seafood_restaurant":
		return "Seafood"
	case "barbecue_restaurant":
		return "Barbecue"
	case "pizza_restaurant":
		return "Pizza"
	case "burger_restaurant":
		return "Burgers"
	case "bakery":
		return "Bakery"
	default:
		return ""
	}
}

func titleCase(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if lower == "" {
		return ""
	}
	words := strings.Fields(lower)
	for i, w := range words {
		if len(w) > 1 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		} else {
			words[i] = strings.ToUpper(w)
		}
	}
	return strings.Join(words, " ")
}

func clamp01(val float64) float64 {
	if math.IsNaN(val) {
		return 0
	}
	if val < 0 {
		return 0
	}
	if val > 1 {
		return 1
	}
	return val
}
