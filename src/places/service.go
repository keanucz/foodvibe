package places

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const (
	defaultRapidAPIHost = "google-map-places-new-v2.p.rapidapi.com"
)

// SearchOptions configures the nearby search request.
type SearchOptions struct {
	Latitude     float64
	Longitude    float64
	RadiusMeters int
	MaxResults   int
}

// Place represents a condensed set of fields returned by the Places API.
type Place struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	PrimaryType        string   `json:"primaryType"`
	Types              []string `json:"types"`
	FormattedAddress   string   `json:"formattedAddress"`
	Latitude           float64  `json:"latitude"`
	Longitude          float64  `json:"longitude"`
	Rating             float64  `json:"rating"`
	UserRatingsTotal   int      `json:"userRatingsTotal"`
	PriceLevel         string   `json:"priceLevel"`
	GoogleMapsURI      string   `json:"googleMapsUri"`
	WebsiteURI         string   `json:"websiteUri"`
	InternationalPhone string   `json:"internationalPhoneNumber"`
	NationalPhone      string   `json:"nationalPhoneNumber"`
}

// Client orchestrates calls to RapidAPI (preferred) and Google Places (fallback).
type Client struct {
	httpClient   *http.Client
	rapidAPIKey  string
	rapidAPIHost string
	googleAPIKey string
}

// NewClient builds a Places client with sane defaults.
func NewClient(rapidAPIKey, rapidAPIHost, googleAPIKey string) *Client {
	if rapidAPIHost == "" {
		rapidAPIHost = defaultRapidAPIHost
	}
	client := &Client{
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		rapidAPIKey:  rapidAPIKey,
		rapidAPIHost: rapidAPIHost,
		googleAPIKey: googleAPIKey,
	}
	log.Printf("places: client configured (rapid_host=%s rapid_key=%t google_key=%t)", rapidAPIHost, rapidAPIKey != "", googleAPIKey != "")
	return client
}

// NearbyFoodPlaces returns nearby independent food spots filtered for big chains.
func (c *Client) NearbyFoodPlaces(ctx context.Context, opts SearchOptions) ([]Place, error) {
	if opts.RadiusMeters <= 0 {
		opts.RadiusMeters = 2000
	}
	if opts.MaxResults <= 0 || opts.MaxResults > 20 {
		opts.MaxResults = 20
	}

	if opts.Latitude == 0 && opts.Longitude == 0 {
		return nil, errors.New("latitude and longitude must be provided")
	}

	log.Printf("places: nearby search lat=%.5f lng=%.5f radius=%d max=%d", opts.Latitude, opts.Longitude, opts.RadiusMeters, opts.MaxResults)

	var rapidErr error
	if c.rapidAPIKey != "" {
		if places, err := c.searchRapidAPI(ctx, opts); err == nil && len(places) > 0 {
			log.Printf("places: rapidapi returned %d venues", len(places))
			return places, nil
		} else if err != nil {
			log.Printf("places: rapidapi search error: %v", err)
			rapidErr = err
		}
	}

	if c.googleAPIKey != "" {
		if places, err := c.searchGooglePlaces(ctx, opts); err == nil {
			log.Printf("places: google places returned %d venues", len(places))
			return places, nil
		} else if rapidErr == nil {
			return nil, err
		} else {
			log.Printf("places: google places error: %v", err)
		}
	}

	if rapidErr != nil {
		return nil, rapidErr
	}

	return nil, errors.New("no places provider configured")
}

type searchNearbyRequest struct {
	IncludedPrimaryTypes []string              `json:"includedPrimaryTypes,omitempty"`
	MaxResultCount       int                   `json:"maxResultCount,omitempty"`
	RankPreference       string                `json:"rankPreference,omitempty"`
	LocationRestriction  searchLocationRequest `json:"locationRestriction"`
	LanguageCode         string                `json:"languageCode,omitempty"`
}

type searchLocationRequest struct {
	Circle struct {
		Center latLng `json:"center"`
		Radius int    `json:"radius"`
	} `json:"circle"`
}

type latLng struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

type searchNearbyResponse struct {
	Places []struct {
		ID          string `json:"id"`
		DisplayName *struct {
			Text string `json:"text"`
		} `json:"displayName"`
		PrimaryType      string   `json:"primaryType"`
		Types            []string `json:"types"`
		FormattedAddress string   `json:"formattedAddress"`
		Location         *struct {
			Latitude  float64 `json:"latitude"`
			Longitude float64 `json:"longitude"`
		} `json:"location"`
		Rating                   float64 `json:"rating"`
		UserRatingCount          int     `json:"userRatingCount"`
		PriceLevel               string  `json:"priceLevel"`
		NationalPhoneNumber      string  `json:"nationalPhoneNumber"`
		InternationalPhoneNumber string  `json:"internationalPhoneNumber"`
		GoogleMapsURI            string  `json:"googleMapsUri"`
		WebsiteURI               string  `json:"websiteUri"`
	} `json:"places"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *Client) searchRapidAPI(ctx context.Context, opts SearchOptions) ([]Place, error) {
	requestBody := searchNearbyRequest{
		IncludedPrimaryTypes: []string{"restaurant", "cafe", "bakery", "meal_takeaway", "meal_delivery", "bar"},
		MaxResultCount:       opts.MaxResults,
		RankPreference:       "POPULARITY",
		LanguageCode:         "en",
	}
	requestBody.LocationRestriction.Circle.Center = latLng{Latitude: opts.Latitude, Longitude: opts.Longitude}
	requestBody.LocationRestriction.Circle.Radius = opts.RadiusMeters

	payload, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("marshal rapidapi request: %w", err)
	}

	url := fmt.Sprintf("https://%s/v1/places:searchNearby", c.rapidAPIHost)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create rapidapi request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-rapidapi-key", c.rapidAPIKey)
	req.Header.Set("x-rapidapi-host", c.rapidAPIHost)
	req.Header.Set("X-Goog-FieldMask", fieldMask())

	return c.sendPlacesRequest(req)
}

func (c *Client) searchGooglePlaces(ctx context.Context, opts SearchOptions) ([]Place, error) {
	if c.googleAPIKey == "" {
		return nil, errors.New("google places api key not configured")
	}

	requestBody := searchNearbyRequest{
		IncludedPrimaryTypes: []string{"restaurant", "cafe", "bakery", "meal_takeaway", "meal_delivery", "bar"},
		MaxResultCount:       opts.MaxResults,
		RankPreference:       "POPULARITY",
		LanguageCode:         "en",
	}
	requestBody.LocationRestriction.Circle.Center = latLng{Latitude: opts.Latitude, Longitude: opts.Longitude}
	requestBody.LocationRestriction.Circle.Radius = opts.RadiusMeters

	payload, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("marshal google places request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://places.googleapis.com/v1/places:searchNearby", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create google places request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Goog-Api-Key", c.googleAPIKey)
	req.Header.Set("X-Goog-FieldMask", fieldMask())

	return c.sendPlacesRequest(req)
}

func (c *Client) sendPlacesRequest(req *http.Request) ([]Place, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("places: request error for %s: %v", req.URL, err)
		return nil, fmt.Errorf("places request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("places: response read error for %s: %v", req.URL, err)
		return nil, fmt.Errorf("read places response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("places: non-200 response %d for %s", resp.StatusCode, req.URL)
		return nil, fmt.Errorf("places api error (%d): %s", resp.StatusCode, string(body))
	}

	var parsed searchNearbyResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode places response: %w", err)
	}

	if parsed.Error != nil && parsed.Error.Message != "" {
		return nil, errors.New(parsed.Error.Message)
	}

	results := make([]Place, 0, len(parsed.Places))
	seen := make(map[string]struct{}, len(parsed.Places))

	for _, p := range parsed.Places {
		if p.DisplayName == nil || p.DisplayName.Text == "" {
			continue
		}
		if isBigChain(p.DisplayName.Text) {
			continue
		}

		id := p.ID
		if id == "" {
			id = normalizeName(p.DisplayName.Text)
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}

		place := Place{
			ID:                 id,
			Name:               p.DisplayName.Text,
			PrimaryType:        p.PrimaryType,
			Types:              append([]string(nil), p.Types...),
			FormattedAddress:   p.FormattedAddress,
			Rating:             p.Rating,
			UserRatingsTotal:   p.UserRatingCount,
			PriceLevel:         p.PriceLevel,
			GoogleMapsURI:      p.GoogleMapsURI,
			WebsiteURI:         p.WebsiteURI,
			InternationalPhone: p.InternationalPhoneNumber,
			NationalPhone:      p.NationalPhoneNumber,
		}
		if p.Location != nil {
			place.Latitude = p.Location.Latitude
			place.Longitude = p.Location.Longitude
		}

		results = append(results, place)
	}

	return results, nil
}

func fieldMask() string {
	return "places.id,places.displayName,places.primaryType,places.types,places.formattedAddress,places.location.latitude,places.location.longitude,places.rating,places.userRatingCount,places.priceLevel,places.nationalPhoneNumber,places.internationalPhoneNumber,places.googleMapsUri,places.websiteUri"
}

// Service orchestrates remote lookups and downstream classification of venues.
type Service struct {
	client     *Client
	classifier Classifier
}

// Result decorates a Place with classifier output.
type Result struct {
	Place
	Classification ClassificationResult `json:"classification"`
}

// NewService wires the places client with a classifier, defaulting to heuristic classification when nil.
func NewService(client *Client, classifier Classifier) *Service {
	if classifier == nil {
		classifier = &heuristicClassifier{}
	}
	return &Service{
		client:     client,
		classifier: classifier,
	}
}

// Search fetches nearby places and enriches them with classification metadata.
func (s *Service) Search(ctx context.Context, opts SearchOptions) ([]Result, error) {
	log.Printf("service: search lat=%.5f lng=%.5f radius=%d max=%d", opts.Latitude, opts.Longitude, opts.RadiusMeters, opts.MaxResults)
	places, err := s.client.NearbyFoodPlaces(ctx, opts)
	if err != nil {
		log.Printf("service: nearby search error: %v", err)
		return nil, err
	}

	results := make([]Result, 0, len(places))
	for _, place := range places {
		log.Printf("service: classifying place %s (%s)", place.Name, place.ID)
		class, err := s.classifier.Classify(ctx, place)
		if err != nil {
			log.Printf("service: classifier error for %s: %v", place.ID, err)
			class = heuristicClassify(place)
		}
		results = append(results, Result{Place: place, Classification: class})
	}
	log.Printf("service: returning %d results", len(results))
	return results, nil
}
