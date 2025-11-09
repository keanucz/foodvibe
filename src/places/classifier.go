package places

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"strings"
	"unicode"

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
	Classify(ctx context.Context, place Place, prefs PreferenceProfile) (ClassificationResult, error)
}

// PreferenceProfile captures a user's stated dietary requirements and taste preferences.
type PreferenceProfile struct {
	DietaryNeeds string
	TasteProfile string
}

// ClassificationResult captures the structured response from the classifier.
type ClassificationResult struct {
	Cuisine            string  `json:"cuisine"`
	Healthy            bool    `json:"healthy"`
	Confidence         float64 `json:"confidence"`
	Rationale          string  `json:"rationale"`
	DietarySuitability string  `json:"dietarySuitability"`
	TasteMatchLevel    string  `json:"tasteMatchLevel"`
}

const (
	// DietarySuitabilityCompatible indicates that the venue can accommodate the requirement.
	DietarySuitabilityCompatible = "compatible"
	// DietarySuitabilityIncompatible indicates a clear conflict with the requirement.
	DietarySuitabilityIncompatible = "incompatible"
	// DietarySuitabilityUnknown indicates insufficient evidence either way.
	DietarySuitabilityUnknown = "unknown"
)

const (
	// TasteMatchHigh indicates a strong alignment with the user's taste preferences.
	TasteMatchHigh = "high"
	// TasteMatchMedium indicates a neutral or mixed alignment.
	TasteMatchMedium = "medium"
	// TasteMatchLow indicates the venue likely does not align with the preference.
	TasteMatchLow = "low"
)

var cuisineAliases = map[string]string{
	"unknown":       "Unknown",
	"chinese":       "Chinese",
	"szechuan":      "Chinese",
	"sichuan":       "Chinese",
	"dim sum":       "Chinese",
	"indian":        "Indian",
	"italian":       "Italian",
	"pizza":         "Italian",
	"japanese":      "Japanese",
	"sushi":         "Japanese",
	"ramen":         "Japanese",
	"korean":        "Korean",
	"pub":           "Pub",
	"irish":         "Pub",
	"greek":         "Greek",
	"mediterranean": "Mediterranean",
	"lebanese":      "Lebanese",
	"turkish":       "Turkish",
	"french":        "French",
	"spanish":       "Spanish",
	"tapas":         "Spanish",
	"american":      "American",
	"steakhouse":    "Steakhouse",
	"barbecue":      "Barbecue",
	"bbq":           "Barbecue",
	"burger":        "Burgers",
	"burgers":       "Burgers",
	"seafood":       "Seafood",
	"steak house":   "Steakhouse",
	"mexican":       "Mexican",
	"taqueria":      "Mexican",
	"cantina":       "Mexican",
	"thai":          "Thai",
	"vietnamese":    "Vietnamese",
	"bakery":        "Bakery",
	"patisserie":    "Bakery",
	"middleeastern": "Mediterranean",
	"shawarma":      "Lebanese",
	"mezze":         "Mediterranean",
	"asian":         "Unknown",
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
	"cuisine": string,             // single-word cuisine label in Title Case (e.g. "Mexican")
	"healthy": boolean,           // true only if the venue emphasizes nutritious, plant-forward, or dietary-conscious menus
	"confidence": number,         // value between 0 and 1 rounded to two decimals summarising certainty
	"rationale": string,          // one concise English sentence justifying the choice
	"dietarySuitability": string, // "compatible", "incompatible", or "unknown" when comparing to the user's dietary needs
	"tasteMatchLevel": string     // "high", "medium", or "low" alignment with the user's taste preferences
}

Input Context:
- You will receive structured JSON describing a food venue with fields such as name, description, types, price_level, rating_count, and user reviews.
- Consider local hints (e.g. "taqueria", "izakaya"), menu items, user comments, and cuisine tags.
- If evidence is insufficient, set cuisine to "Unknown", healthy to false, confidence <= 0.35, and explain the uncertainty.
- Healthy should be true only when there is explicit evidence of health-focused options (e.g. "salad bar", "low-carb", "vegan", "organic", "healthy bowls").
- Cuisine MUST be exactly one word chosen from: Unknown, Chinese, Indian, Italian, Japanese, Korean, Pub, Greek, French, Spanish, American, Mexican, Mediterranean, Lebanese, Turkish, Thai, Vietnamese, Bakery, Barbecue, Seafood, Steakhouse, Burgers.
- Always factor in the user's dietary requirements and taste preferences that accompany the venue details.
- Prefer culturally specific cuisine names ("Thai", "Lebanese"). Use broader categories ("American") only when necessary.
- Mark dietarySuitability as "compatible" only when the venue clearly satisfies the requirement, "incompatible" when there is explicit conflict (e.g. non-halal venue for halal needs), otherwise reply "unknown".
- For tasteMatchLevel, respond "high" when a preference is clearly aligned, "low" when it conflicts, and "medium" when unsure.
- Rationale must be a single concise sentence (<= 20 words).
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
			"dietarySuitability": {
				Type:        "STRING",
				Description: "One of \"compatible\", \"incompatible\", or \"unknown\" compared to the user's dietary needs",
			},
			"tasteMatchLevel": {
				Type:        "STRING",
				Description: "One of \"high\", \"medium\", or \"low\" describing alignment with the user's taste preferences",
			},
		},
		Required: []string{"cuisine", "healthy", "confidence", "rationale", "dietarySuitability", "tasteMatchLevel"},
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


func (c *adkClassifier) Classify(ctx context.Context, place Place, prefs PreferenceProfile) (ClassificationResult, error) {
	result, err := c.invoke(ctx, place, prefs)
	if err != nil {
		log.Printf("adk classifier fallback: %v", err)
		return c.fallback.Classify(ctx, place, prefs)
	}
	if result.Cuisine == "" || result.Rationale == "" {
		return c.fallback.Classify(ctx, place, prefs)
	}
	result.Cuisine = normalizeCuisineLabel(result.Cuisine)
	result.Confidence = clamp01(result.Confidence)
	result.DietarySuitability = normalizeSuitability(result.DietarySuitability)
	result.TasteMatchLevel = normalizeTasteMatch(result.TasteMatchLevel)
	return result, nil
}

func (c *adkClassifier) invoke(ctx context.Context, place Place, prefs PreferenceProfile) (ClassificationResult, error) {
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
		"user_dietary_needs":         strings.TrimSpace(prefs.DietaryNeeds),
		"user_taste_profile":         strings.TrimSpace(prefs.TasteProfile),
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

	parsed.Cuisine = normalizeCuisineLabel(parsed.Cuisine)
	parsed.Confidence = clamp01(parsed.Confidence)
	return parsed, nil
}

type heuristicClassifier struct{}

func (heuristicClassifier) Classify(_ context.Context, place Place, prefs PreferenceProfile) (ClassificationResult, error) {
	return heuristicClassify(place, prefs), nil
}

func heuristicClassify(place Place, prefs PreferenceProfile) ClassificationResult {
	normalized := normalizeName(place.Name)
	cuisine := normalizeCuisineLabel(detectCuisine(place.Types, normalized))
	healthy := detectHealthiness(place.Types, normalized)
	confidence := 0.4
	if cuisine != "Unknown" {
		confidence = 0.65
	}
	rationale := buildRationale(cuisine, healthy, place)
	result := ClassificationResult{
		Cuisine:    cuisine,
		Healthy:    healthy,
		Confidence: confidence,
		Rationale:  rationale,
	}
	result.DietarySuitability = inferDietarySuitability(place, prefs.DietaryNeeds)
	result.TasteMatchLevel = inferTasteMatch(place, cuisine, prefs.TasteProfile)
	return result
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
		"mezze":      "Mediterranean",
		"shawarma":   "Lebanese",
		"dim sum":   "Chinese",
		"noodle":     "Chinese",
		"sushi":      "Japanese",
		"ramen":      "Japanese",
		"bao":        "Chinese",
		"poke":       "Seafood",
		"bbq":        "Barbecue",
		"barbecue":   "Barbecue",
		"steakhouse": "Steakhouse",
		"diner":      "American",
		"gastropub":  "Pub",
		"pub":        "Pub",
		"brewpub":    "Pub",
		"bakery":     "Bakery",
		"patisserie": "Bakery",
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

func inferDietarySuitability(place Place, dietaryNeeds string) string {
	dietaryNeeds = strings.TrimSpace(strings.ToLower(dietaryNeeds))
	if dietaryNeeds == "" {
		return DietarySuitabilityCompatible
	}
	tokens := tokenizePreferences(dietaryNeeds)
	if len(tokens) == 0 {
		return DietarySuitabilityUnknown
	}

	normalizedName := normalizeName(place.Name)
	typesLower := lowerPlaceTypes(place.Types)
	suitability := DietarySuitabilityUnknown

	for _, token := range tokens {
		switch token {
		case "halal":
			if strings.Contains(normalizedName, "halal") || containsAny(typesLower, "halal_restaurant") {
				suitability = DietarySuitabilityCompatible
				continue
			}
			if containsAny(typesLower, "bar", "brewery", "pub") {
				return DietarySuitabilityIncompatible
			}
		case "kosher":
			if strings.Contains(normalizedName, "kosher") || containsAny(typesLower, "kosher_restaurant") {
				suitability = DietarySuitabilityCompatible
			}
		case "vegan":
			if containsAny(typesLower, "vegan_restaurant") || strings.Contains(normalizedName, "vegan") {
				suitability = DietarySuitabilityCompatible
				continue
			}
			if containsAny(typesLower, "steakhouse", "barbecue_restaurant") {
				return DietarySuitabilityIncompatible
			}
		case "vegetarian":
			if containsAny(typesLower, "vegetarian_restaurant") || strings.Contains(normalizedName, "vegetarian") {
				suitability = DietarySuitabilityCompatible
			}
		case "gluten-free", "glutenfree", "gluten free", "celiac", "coeliac":
			if strings.Contains(normalizedName, "gluten-free") || strings.Contains(normalizedName, "gluten free") {
				suitability = DietarySuitabilityCompatible
			}
		default:
			if strings.Contains(normalizedName, token) {
				suitability = DietarySuitabilityCompatible
			}
		}
	}

	return suitability
}

func inferTasteMatch(place Place, cuisine, tasteProfile string) string {
	tasteProfile = strings.TrimSpace(strings.ToLower(tasteProfile))
	if tasteProfile == "" {
		return TasteMatchMedium
	}
	tokens := tokenizePreferences(tasteProfile)
	if len(tokens) == 0 {
		return TasteMatchMedium
	}

	normalizedName := normalizeName(place.Name)
	typesLower := lowerPlaceTypes(place.Types)
	cuisineLower := strings.ToLower(strings.TrimSpace(cuisine))

	for _, token := range tokens {
		if token == "" {
			continue
		}
		if token == cuisineLower {
			return TasteMatchHigh
		}
		if strings.Contains(normalizedName, token) {
			return TasteMatchHigh
		}
		if containsAny(typesLower, token) {
			return TasteMatchHigh
		}
	}
	return TasteMatchMedium
}

func lowerPlaceTypes(types []string) []string {
	out := make([]string, 0, len(types))
	for _, t := range types {
		out = append(out, strings.ToLower(strings.TrimSpace(t)))
	}
	return out
}

func containsAny(haystack []string, needles ...string) bool {
	for _, needle := range needles {
		needle = strings.ToLower(strings.TrimSpace(needle))
		if needle == "" {
			continue
		}
		for _, item := range haystack {
			if item == needle {
				return true
			}
		}
	}
	return false
}

func tokenizePreferences(raw string) []string {
	raw = strings.ToLower(raw)
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		switch {
		case unicode.IsSpace(r):
			return true
		case r == ',', r == ';', r == '|', r == '/', r == '&':
			return true
		default:
			return false
		}
	})
	return fields
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
		return "Lebanese"
	case "turkish_restaurant":
		return "Turkish"
	case "american_restaurant":
		return "American"
	case "seafood_restaurant":
		return "Seafood"
	case "barbecue_restaurant":
		return "Barbecue"
	case "pizza_restaurant":
		return "Italian"
	case "burger_restaurant":
		return "Burgers"
	case "bakery":
		return "Bakery"
	default:
		return ""
	}
}

func normalizeCuisineLabel(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "Unknown"
	}
	normalized := normalizeName(trimmed)
	if normalized == "" {
		return "Unknown"
	}
	collapsed := strings.ReplaceAll(normalized, " ", "")
	if collapsed == "" {
		return "Unknown"
	}
	if canonical, ok := cuisineAliases[collapsed]; ok {
		return canonical
	}
	if canonical, ok := cuisineAliases[normalized]; ok {
		return canonical
	}
	for key, value := range cuisineAliases {
		keyCollapsed := strings.ReplaceAll(key, " ", "")
		if strings.Contains(collapsed, keyCollapsed) {
			return value
		}
	}
	return "Unknown"
}

func normalizeSuitability(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case DietarySuitabilityCompatible:
		return DietarySuitabilityCompatible
	case DietarySuitabilityIncompatible:
		return DietarySuitabilityIncompatible
	default:
		return DietarySuitabilityUnknown
	}
}

func normalizeTasteMatch(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case TasteMatchHigh:
		return TasteMatchHigh
	case TasteMatchLow:
		return TasteMatchLow
	case TasteMatchMedium:
		return TasteMatchMedium
	default:
		return TasteMatchMedium
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
