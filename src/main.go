package main

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/glebarez/go-sqlite"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"foodvibe/src/places"
)

type googleOauthResp struct {
	Id            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}
type Restaurant struct {
	PlaceID     string  `json:"place_id"`
	Name        string  `json:"name"`
	Address     string  `json:"address"`
	Cuisine     string  `json:"cuisine"`
	Rating      float64 `json:"rating"`
	RatingCount int     `json:"rating_count"`
	Lat         float64 `json:"lat"` // Stored as REAL in SQL
	Lng         float64 `json:"lng"` // Stored as REAL in SQL
	Healthy     int     `json:"healthy"`
}

// for concurrent access
var mux sync.Mutex
var googleOauthConf = &oauth2.Config{
	RedirectURL: "http://localhost:8080/callback",
	// fill client* with values set by env vars
	ClientID:     "",
	ClientSecret: "",
	Scopes: []string{
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile",
	},
	Endpoint: google.Endpoint,
}

//go:embed template/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

var parsedTemplates = template.Must(template.ParseFS(templateFS, "template/*.html"))

func createTables(db *sql.DB) error {
	tables := []struct {
		name  string
		query string
	}{
		{
			name: "sessions",
			query: `CREATE TABLE IF NOT EXISTS sessions (
			sid TEXT PRIMARY KEY,
			uid TEXT,
			FOREIGN KEY(uid) REFERENCES users(id)
		);`,
		},
		{
			name: "users",
			query: `CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			dietary_reqs TEXT,
			tastes TEXT
	);`,
		},
		{
			name: "places",
			query: `CREATE TABLE IF NOT EXISTS places (
			place_id TEXT PRIMARY KEY,
			name TEXT,
			address TEXT,
			cuisine TEXT,
			rating REAL,
			rating_count INTEGER,
			lat REAL,
			lng REAL,
			healthy BOOLEAN,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);`,
		},
		{
			name: "ratings",
			query: `CREATE TABLE IF NOT EXISTS ratings (
			place_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY(place_id, user_id),
			FOREIGN KEY(user_id) REFERENCES users(id)
		);`,
		},
		{
			name: "ratings_place_idx",
			query: `CREATE INDEX IF NOT EXISTS idx_ratings_place ON ratings(place_id);`,
		},
	}

	for _, tbl := range tables {
		log.Printf("db: ensuring %s table", tbl.name)
		if _, err := db.Exec(tbl.query); err != nil {
			log.Printf("db: failed ensuring %s table: %v", tbl.name, err)
			return err
		}
	}
	if err := ensureUsersColumns(db); err != nil {
		return err
	}
	if err := ensurePlacesColumns(db); err != nil {
		return err
	}
	log.Println("db: schema ensured")
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if err := godotenv.Load(); err != nil {
		log.Printf("config: no .env file loaded: %v", err)
	} else {
		log.Println("config: loaded .env file")
	}
	// get some env vars for accessing the google api
	clientid := os.Getenv("CLIENT_ID")
	clientsec := os.Getenv("CLIENT_SECRET")
	if clientid == "" || clientsec == "" {
		log.Println("config: CLIENT_ID and CLIENT_SECRET must be set as envvars, quitting")
		return
	} else {
		googleOauthConf.ClientID = clientid
		googleOauthConf.ClientSecret = clientsec
		log.Println("config: OAuth credentials loaded from environment")
	}

	// open db
	dbPath := "data/tables.db"
	log.Printf("db: ensuring directory for %s", dbPath)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		log.Printf("db: directory creation failed: %v", err)
		return
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Printf("db: open failed: %v", err)
		return
	}
	db.SetMaxOpenConns(1)
	log.Printf("db: opened sqlite database at %s", dbPath)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		log.Printf("db: failed to enable WAL mode: %v", err)
	} else {
		log.Println("db: WAL mode enabled")
	}
	if _, err := db.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
		log.Printf("db: failed to set synchronous pragma: %v", err)
	}

	// create the tables
	err = createTables(db)
	if err != nil {
		log.Println("db: schema setup failed, shutting down")
		flushAndCloseDB(db)
		return
	}
	log.Println("db: schema ready")

	classifier, classifierErr := places.NewClassifier(context.Background(), places.ClassifierConfig{
		APIKey: os.Getenv("GOOGLE_API_KEY"),
	})
	if classifierErr != nil {
		log.Printf("classifier fallback to heuristics: %v", classifierErr)
	} else {
		log.Println("classifier: ADK classifier initialised")
	}
	placeClient := places.NewClient(
		os.Getenv("RAPIDAPI_KEY"),
		os.Getenv("RAPIDAPI_HOST"),
		os.Getenv("GOOGLE_API_KEY"),
	)
	log.Println("places: client initialised")
	placeSvc := places.NewService(placeClient, classifier)

	mux := http.NewServeMux()
	staticContent, staticErr := fs.Sub(staticFS, "static")
	if staticErr != nil {
		log.Fatalf("static: failed to prepare filesystem: %v", staticErr)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticContent))))

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("auth: login request from %s", r.RemoteAddr)
		http.Redirect(w, r, googleOauthConf.AuthCodeURL("state"), http.StatusTemporaryRedirect)
	})

	// to use with google oauth2, you must register http://localhost:8080/callback as a valid redirect URL
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("auth: callback hit from %s", r.RemoteAddr)
		code := r.URL.Query().Get("code")
		if code == "" {
			log.Println("auth: missing code in callback")
			http.Error(w, "Missing code", http.StatusBadRequest)
			return
		}

		token, err := googleOauthConf.Exchange(context.Background(), code)
		if err != nil {
			log.Printf("auth: token exchange error: %v", err)
			http.Error(w, "Token exchange error: "+err.Error(), http.StatusBadRequest)
			return
		}

		client := googleOauthConf.Client(context.Background(), token)
		resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
		if err != nil {
			log.Printf("auth: userinfo error: %v", err)
			http.Error(w, "Google response error: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer resp.Body.Close()

		// copy api response into a struct
		var json_resp googleOauthResp
		err = json.NewDecoder(resp.Body).Decode(&json_resp)
		if err != nil {
			log.Printf("auth: decode userinfo error: %v", err)
			http.Error(w, "Error parsing response: "+err.Error(), http.StatusBadRequest)
			return
		}

		// we want to save this login into a cookie and add it do our db
		sessionID := uuid.New().String()

		cookie := &http.Cookie{
			Name:     "session_id",
			MaxAge:   60 * 60 * 24 * 7,
			Value:    sessionID,
			SameSite: http.SameSiteLaxMode,
		}
		preferredName := strings.TrimSpace(json_resp.GivenName)
		if preferredName == "" {
			preferredName = json_resp.Name
		}
		displayName := deriveDisplayName(preferredName, json_resp.Email)
		_, err = db.Exec(`INSERT INTO sessions (sid, uid) VALUES (?,?)`, sessionID, json_resp.Id)
		if err != nil {
			log.Printf("auth: insert session failed: %v", err)
			http.Error(w, "Error updating database: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = db.Exec(`INSERT INTO users (id, email, display_name) VALUES (?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				email = excluded.email,
				display_name = CASE
					WHEN excluded.display_name != '' THEN excluded.display_name
					ELSE users.display_name
				END`, json_resp.Id, json_resp.Email, displayName)
		if err != nil {
			log.Printf("auth: insert user failed: %v", err)
			http.Error(w, "Error updating database: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("auth: user %s logged in", json_resp.Email)
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	})

	mux.HandleFunc("/addplace", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("places: addplace request %s %s", r.Method, r.RemoteAddr)
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed. Only POST is supported.", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body.", http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		var restaurants []Restaurant
		if err := json.Unmarshal(body, &restaurants); err != nil {
			log.Printf("JSON Unmarshal error: %v", err)
			http.Error(w, "Invalid JSON format: expected an array of restaurant objects.", http.StatusBadRequest)
			return
		}
		log.Printf("places: received %d restaurants to insert", len(restaurants))

		const insertSQL = `
			INSERT INTO places(place_id, name, address, cuisine, rating, rating_count, lat, lng, healthy)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

		tx, err := db.Begin()
		if err != nil {
			log.Printf("Transaction begin error: %v", err)
			http.Error(w, "Internal server error: could not start transaction.", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()

		stmt, err := tx.Prepare(insertSQL)
		if err != nil {
			log.Printf("Database prepare error: %v", err)
			http.Error(w, "Internal server error: could not prepare statement.", http.StatusInternalServerError)
			return
		}
		defer stmt.Close()

		inserted := 0
		for _, res := range restaurants {
			_, err := stmt.Exec(res.PlaceID, res.Name, res.Address, res.Cuisine,
				res.Rating, res.RatingCount, res.Lat, res.Lng, res.Healthy)
			if err != nil {
				log.Printf("Insert error for %s: %v", res.Name, err)
				http.Error(w, fmt.Sprintf("Error inserting %s", res.Name), http.StatusInternalServerError)
				return
			}
			inserted++
		}

		if err := tx.Commit(); err != nil {
			log.Printf("places: transaction commit failed: %v", err)
			http.Error(w, "Commit failed", http.StatusInternalServerError)
			return
		}
		log.Printf("places: inserted %d restaurants", inserted)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "success",
			"inserted": inserted,
		})
	})

	// takes the user's location, cuisine prefs and risk as input from the form, and finds all the places
	// from the database that are within the radius, sorts them by keanu's ai agent, and then renders the template
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("search: request from %s", r.RemoteAddr)
		risk := r.URL.Query().Get("risk")
		cuisine := r.URL.Query().Get("cuisine")
		if risk == "" {
			log.Println("search: missing risk parameter")
			http.Error(w, "Missing risk parameter", http.StatusBadRequest)
			return
		}
		if cuisine == "" {
			log.Println("search: missing cuisine parameter")
			http.Error(w, "Missing cuisine parameter", http.StatusBadRequest)
			return
		}

		var uid string
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Error(w, "No session cookie (did you login?)", http.StatusBadRequest)
			return
		}
		err = db.QueryRow(`SELECT uid FROM sessions WHERE sid = ?`, cookie.Value).Scan(&uid)
		if err != nil {
			log.Printf("search: session lookup failed: %v", err)
			http.Error(w, "Error querying database", http.StatusBadRequest)
			return
		}

		latStr := r.URL.Query().Get("lat")
		lngStr := r.URL.Query().Get("lng")
		if latStr == "" || lngStr == "" {
			http.Error(w, "Missing lat/lng parameters", http.StatusBadRequest)
			return
		}

		lat, err := strconv.ParseFloat(latStr, 64)
		if err != nil {
			log.Printf("search: invalid latitude %q", latStr)
			http.Error(w, "Invalid latitude", http.StatusBadRequest)
			return
		}
		lng, err := strconv.ParseFloat(lngStr, 64)
		if err != nil {
			log.Printf("search: invalid longitude %q", lngStr)
			http.Error(w, "Invalid longitude", http.StatusBadRequest)
			return
		}

		radiusMeters := 2000
		if radiusStr := r.URL.Query().Get("radius"); radiusStr != "" {
			if parsed, parseErr := strconv.Atoi(radiusStr); parseErr == nil && parsed > 0 {
				radiusMeters = parsed
			}
		}

		record, err := fetchUserRecord(db, uid)
		if err != nil {
			log.Printf("search: failed to load user %s preferences: %v", uid, err)
			http.Error(w, "Failed to load user preferences", http.StatusInternalServerError)
			return
		}
		preferences := places.PreferenceProfile{}
		if record != nil {
			preferences.DietaryNeeds = strings.TrimSpace(valueOrEmpty(record.DietaryNeeds))
			preferences.TasteProfile = strings.TrimSpace(valueOrEmpty(record.TasteProfile))
		}

		results, err := placeSvc.Search(r.Context(), places.SearchOptions{
			Latitude:     lat,
			Longitude:    lng,
			RadiusMeters: radiusMeters,
			MaxResults:   10,
			CuisineCode:  cuisine,
			Preferences:  preferences,
		})
		if err != nil {
			log.Printf("place search failed: %v", err)
			http.Error(w, "Failed to search nearby venues", http.StatusBadGateway)
			return
		}
		if err := populateRatingSummaries(r.Context(), db, uid, results); err != nil {
			log.Printf("search: rating enrichment failed: %v", err)
		}
		if err := cacheSearchResults(r.Context(), db, results); err != nil {
			log.Printf("search: cache write failed: %v", err)
		}
		log.Printf("search: returning %d results for user %s at %.5f,%.5f radius %d", len(results), uid, lat, lng, radiusMeters)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"results": results,
			"user":    uid,
			"risk":    risk,
			"cuisine": cuisine,
		})
	})

	mux.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("ui: /home requested by %s", r.RemoteAddr)
		cookie, err := r.Cookie("session_id")
		if err == http.ErrNoCookie { // check if cookie is missing
			log.Println("ui: missing session cookie, redirecting to /")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		} else if err != nil {
			log.Printf("ui: read cookie error: %v", err)
			http.Error(w, "Error finding cookie: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// then check if it actually has a valid uid attached
		var uid string
		err = db.QueryRow(`SELECT uid FROM sessions WHERE sid = ?`, cookie.Value).Scan(&uid)
		if err != nil {
			http.Error(w, "Error querying database", http.StatusBadRequest)
			return
		}
		if uid == "" {
			http.Redirect(w, r, "/", http.StatusPermanentRedirect)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		pageData := PageData{Username: loadDisplayName(db, uid)}
		if err := renderTemplate(w, "home.html", pageData); err != nil {
			log.Printf("ui: template render error: %v", err)
			http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("ui: home rendered for user %s", uid)
	})

	mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("ui: /profile requested by %s", r.RemoteAddr)
		cookie, err := r.Cookie("session_id")
		if err == http.ErrNoCookie { // check if cookie is missing
			log.Println("ui: missing session cookie, redirecting to /")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		} else if err != nil {
			log.Printf("ui: read cookie error: %v", err)
			http.Error(w, "Error finding cookie: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// then check if it actually has a valid uid attached
		var uid string
		err = db.QueryRow(`SELECT uid FROM sessions WHERE sid = ?`, cookie.Value).Scan(&uid)
		if err != nil {
			http.Error(w, "Error querying database", http.StatusBadRequest)
			return
		}
		if uid == "" {
			http.Redirect(w, r, "/", http.StatusPermanentRedirect)
			return
		}
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				log.Printf("ui: profile form parse failed: %v", err)
				http.Error(w, "Invalid form submission", http.StatusBadRequest)
				return
			}
			dietary := strings.TrimSpace(r.FormValue("dietary-needs"))
			taste := strings.TrimSpace(r.FormValue("taste-profile"))
			if err := saveUserPreferences(r.Context(), db, uid, dietary, taste); err != nil {
				log.Printf("ui: failed saving preferences for user %s: %v", uid, err)
				http.Error(w, "Error saving preferences", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/profile?saved=1", http.StatusSeeOther)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		record, err := fetchUserRecord(db, uid)
		if err != nil {
			log.Printf("ui: failed fetching user %s record: %v", uid, err)
			http.Error(w, "Error loading profile", http.StatusInternalServerError)
			return
		}
		username := resolveDisplayName(db, uid, record)
		pageData := PageData{
			Username:     username,
			DietaryNeeds: strings.TrimSpace(valueOrEmpty(record.DietaryNeeds)),
			TasteProfile: strings.TrimSpace(valueOrEmpty(record.TasteProfile)),
		}
		if r.URL.Query().Get("saved") == "1" {
			pageData.FlashMessage = "Preferences saved successfully."
		}
		if err := renderTemplate(w, "profile.html", pageData); err != nil {
			log.Printf("ui: profile template render error: %v", err)
			http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("ui: profile rendered for user %s", uid)
	})

	mux.HandleFunc("/rate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		cookie, err := r.Cookie("session_id")
		if err == http.ErrNoCookie {
			http.Error(w, "Unauthorised", http.StatusUnauthorized)
			return
		} else if err != nil {
			http.Error(w, "Error reading cookie", http.StatusInternalServerError)
			return
		}

		var uid string
		if err := db.QueryRow(`SELECT uid FROM sessions WHERE sid = ?`, cookie.Value).Scan(&uid); err != nil {
			http.Error(w, "Session invalid", http.StatusUnauthorized)
			return
		}
		uid = strings.TrimSpace(uid)
		if uid == "" {
			http.Error(w, "Session invalid", http.StatusUnauthorized)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form payload", http.StatusBadRequest)
			return
		}

		placeID := strings.TrimSpace(r.FormValue("restaurant_id"))
		ratingStr := strings.TrimSpace(r.FormValue("rating"))
		if placeID == "" || ratingStr == "" {
			http.Error(w, "Missing rating data", http.StatusBadRequest)
			return
		}
		ratingVal, err := strconv.Atoi(ratingStr)
		if err != nil {
			http.Error(w, "Invalid rating value", http.StatusBadRequest)
			return
		}
		if err := saveUserRating(r.Context(), db, uid, placeID, ratingVal); err != nil {
			log.Printf("ratings: failed to persist rating for user %s place %s: %v", uid, placeID, err)
			http.Error(w, "Failed to save rating", http.StatusInternalServerError)
			return
		}

		summary, err := ratingSummaryForPlace(r.Context(), db, placeID, uid)
		if err != nil {
			log.Printf("ratings: failed to compute summary for %s: %v", placeID, err)
			http.Error(w, "Failed to compute rating summary", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"summary": summary,
		})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("ui: root requested by %s", r.RemoteAddr)
		cookie, err := r.Cookie("session_id")
		if err == http.ErrNoCookie { // check if cookie is missing
			log.Println("ui: no session cookie, serving index")
			if err := renderTemplate(w, "index.html", nil); err != nil {
				log.Printf("ui: index template render error: %v", err)
				http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else if err != nil {
			log.Printf("ui: read cookie error: %v", err)
			http.Error(w, "Error finding cookie: "+err.Error(), http.StatusInternalServerError)
			return
		} else {
			// then check if it actually has a valid uid attached
			var uid string
			err = db.QueryRow(`SELECT uid FROM sessions WHERE sid = ?`, cookie.Value).Scan(&uid)
			if err != nil {
				log.Printf("ui: session lookup failed: %v", err)
				http.Error(w, "Error querying database", http.StatusBadRequest)
				return
			} else if uid != "" {
				log.Printf("ui: user %s already logged in, redirecting to /home", uid)
				http.Redirect(w, r, "/home", http.StatusPermanentRedirect)
			}
		}
	})

	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Println("server: listening on :8080")
		errCh <- server.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Printf("server: listener error: %v", err)
		}
	case <-shutdownCtx.Done():
		log.Println("server: shutdown signal received")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("server: graceful shutdown failed: %v", err)
		}
		if err := <-errCh; err != nil && err != http.ErrServerClosed {
			log.Printf("server: listener error after shutdown: %v", err)
		}
	}

	if err := flushAndCloseDB(db); err != nil {
		log.Printf("db: flush on shutdown error: %v", err)
	} else {
		log.Println("db: clean shutdown complete")
	}
	log.Println("server: shutdown complete")
}

func renderTemplate(w http.ResponseWriter, name string, data any) error {
	tmpl := parsedTemplates.Lookup(name)
	if tmpl == nil {
		return fmt.Errorf("template %q not found", name)
	}
	return tmpl.Execute(w, data)
}

type PageData struct {
	Username     string
	Cards        []HomeCard
	DietaryNeeds string
	TasteProfile string
	FlashMessage string
}

type HomeCard struct {
	Name         string
	Cuisine      string
	Address      string
	RestaurantID string
}

func ensureUsersColumns(db *sql.DB) error {
	alterStatements := []string{
		"ALTER TABLE users ADD COLUMN email TEXT",
		"ALTER TABLE users ADD COLUMN display_name TEXT",
	}
	for _, stmt := range alterStatements {
		if _, err := db.Exec(stmt); err != nil {
			errText := strings.ToLower(err.Error())
			if !strings.Contains(errText, "duplicate column") {
				return err
			}
		}
	}
	return nil
}

func ensurePlacesColumns(db *sql.DB) error {
	alterStatements := []string{
		"ALTER TABLE places ADD COLUMN rating REAL",
	}
	for _, stmt := range alterStatements {
		if _, err := db.Exec(stmt); err != nil {
			errText := strings.ToLower(err.Error())
			if !strings.Contains(errText, "duplicate column") {
				return err
			}
		}
	}
	return nil
}

func deriveDisplayName(name, email string) string {
	name = strings.TrimSpace(name)
	if name != "" {
		return name
	}
	email = strings.TrimSpace(email)
	if email == "" {
		return ""
	}
	if at := strings.Index(email, "@"); at >= 0 {
		email = email[:at]
	}
	replacer := strings.NewReplacer(".", " ", "_", " ", "-", " ")
	email = replacer.Replace(email)
	words := strings.Fields(email)
	if len(words) == 0 {
		return ""
	}
	for i, word := range words {
		if len(word) == 0 {
			continue
		}
		lower := strings.ToLower(word)
		words[i] = strings.ToUpper(lower[:1]) + lower[1:]
	}
	return strings.Join(words, " ")
}

func loadDisplayName(db *sql.DB, userID string) string {
	record, err := fetchUserRecord(db, userID)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("db: failed to load user %s profile: %v", userID, err)
		}
		return ""
	}
	return resolveDisplayName(db, userID, record)
}

func valueOrEmpty(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

type userRecord struct {
	DisplayName  sql.NullString
	Email        sql.NullString
	DietaryNeeds sql.NullString
	TasteProfile sql.NullString
}

func fetchUserRecord(db *sql.DB, userID string) (*userRecord, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, sql.ErrNoRows
	}
	record := &userRecord{}
	err := db.QueryRow(
		`SELECT display_name, email, dietary_reqs, tastes FROM users WHERE id = ?`,
		userID,
	).Scan(&record.DisplayName, &record.Email, &record.DietaryNeeds, &record.TasteProfile)
	if err != nil {
		if err == sql.ErrNoRows {
			return &userRecord{}, nil
		}
		return nil, err
	}
	return record, nil
}

func resolveDisplayName(db *sql.DB, userID string, record *userRecord) string {
	if record == nil {
		return ""
	}
	name := strings.TrimSpace(valueOrEmpty(record.DisplayName))
	if name != "" {
		return name
	}

	emailVal := strings.TrimSpace(valueOrEmpty(record.Email))
	if emailVal != "" {
		if fallback := deriveDisplayName("", emailVal); fallback != "" {
			if _, err := db.Exec(`UPDATE users SET display_name = ? WHERE id = ?`, fallback, userID); err != nil {
				log.Printf("db: failed to backfill display name for %s: %v", userID, err)
			} else {
				record.DisplayName = sql.NullString{String: fallback, Valid: true}
			}
			return fallback
		}
	}

	return userID
}

func withTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		return context.WithTimeout(context.Background(), timeout)
	}
	return context.WithTimeout(ctx, timeout)
}

func saveUserPreferences(ctx context.Context, db *sql.DB, userID, dietary, taste string) error {
	if db == nil {
		return errors.New("database handle is nil")
	}
	trimmedID := strings.TrimSpace(userID)
	if trimmedID == "" {
		return errors.New("user id is required")
	}

	execCtx, cancel := withTimeout(ctx, 2*time.Second)
	defer cancel()

	_, err := db.ExecContext(execCtx,
		`INSERT INTO users (id, dietary_reqs, tastes)
			VALUES (?, NULLIF(?, ''), NULLIF(?, ''))
			ON CONFLICT(id) DO UPDATE SET
				dietary_reqs = excluded.dietary_reqs,
				tastes = excluded.tastes`,
		trimmedID,
		strings.TrimSpace(dietary),
		strings.TrimSpace(taste),
	)
	return err
}

func saveUserRating(ctx context.Context, db *sql.DB, userID, placeID string, rating int) error {
	if db == nil {
		return errors.New("database handle is nil")
	}
	trimmedUser := strings.TrimSpace(userID)
	trimmedPlace := strings.TrimSpace(placeID)
	if trimmedUser == "" || trimmedPlace == "" {
		return errors.New("user id and place id are required")
	}
	if rating < 1 || rating > 5 {
		return fmt.Errorf("rating %d out of range", rating)
	}

	execCtx, cancel := withTimeout(ctx, 2*time.Second)
	defer cancel()

	_, err := db.ExecContext(execCtx,
		`INSERT INTO ratings (place_id, user_id, rating, created_at, updated_at)
			VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
			ON CONFLICT(place_id, user_id) DO UPDATE SET
				rating = excluded.rating,
				updated_at = CURRENT_TIMESTAMP`,
		trimmedPlace,
		trimmedUser,
		rating,
	)
	return err
}

func ratingSummaryForPlace(ctx context.Context, db *sql.DB, placeID, userID string) (places.RatingSummary, error) {
	summary := places.RatingSummary{}
	if db == nil {
		return summary, errors.New("database handle is nil")
	}
	trimmedPlace := strings.TrimSpace(placeID)
	if trimmedPlace == "" {
		return summary, errors.New("place id is required")
	}

	queryCtx, cancel := withTimeout(ctx, 3*time.Second)
	defer cancel()

	var googleRating sql.NullFloat64
	var googleCount sql.NullInt64
	if err := db.QueryRowContext(queryCtx, `SELECT rating, rating_count FROM places WHERE place_id = ?`, trimmedPlace).
		Scan(&googleRating, &googleCount); err != nil {
		if err != sql.ErrNoRows {
			return summary, err
		}
	} else {
		if googleRating.Valid {
			summary.GoogleRating = googleRating.Float64
		}
		if googleCount.Valid {
			summary.GoogleRatingCount = int(googleCount.Int64)
		}
	}

	var localAvg sql.NullFloat64
	var localCount int64
	if err := db.QueryRowContext(queryCtx, `SELECT AVG(rating), COUNT(*) FROM ratings WHERE place_id = ?`, trimmedPlace).
		Scan(&localAvg, &localCount); err != nil {
		if err != sql.ErrNoRows {
			return summary, err
		}
	}
	if localAvg.Valid {
		summary.LocalAverage = localAvg.Float64
	}
	summary.LocalCount = int(localCount)

	if trimmedUser := strings.TrimSpace(userID); trimmedUser != "" {
		var userRating sql.NullInt64
		if err := db.QueryRowContext(queryCtx, `SELECT rating FROM ratings WHERE place_id = ? AND user_id = ?`, trimmedPlace, trimmedUser).
			Scan(&userRating); err != nil {
			if err != sql.ErrNoRows {
				return summary, err
			}
		} else if userRating.Valid {
			summary.UserRating = int(userRating.Int64)
		}
	}

	combinedCount := summary.GoogleRatingCount + summary.LocalCount
	summary.CombinedCount = combinedCount
	if combinedCount > 0 {
		total := summary.GoogleRating*float64(summary.GoogleRatingCount) + summary.LocalAverage*float64(summary.LocalCount)
		summary.CombinedRating = total / float64(combinedCount)
	}

	return summary, nil
}

func populateRatingSummaries(ctx context.Context, db *sql.DB, userID string, results []places.Result) error {
	if db == nil {
		return errors.New("database handle is nil")
	}
	if len(results) == 0 {
		return nil
	}

	idSet := make(map[string]struct{}, len(results))
	ids := make([]string, 0, len(results))
	for _, res := range results {
		id := strings.TrimSpace(res.Place.ID)
		if id == "" {
			continue
		}
		if _, exists := idSet[id]; exists {
			continue
		}
		idSet[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil
	}

	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]

	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}

	queryCtx, cancel := withTimeout(ctx, 3*time.Second)
	defer cancel()

	aggregates := make(map[string]struct {
		avg   float64
		count int
	})

	aggregateQuery := fmt.Sprintf(`SELECT place_id, AVG(rating) AS avg_rating, COUNT(*) AS cnt FROM ratings WHERE place_id IN (%s) GROUP BY place_id`, placeholders)
	rows, err := db.QueryContext(queryCtx, aggregateQuery, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var placeID string
		var avg sql.NullFloat64
		var cnt int
		if err := rows.Scan(&placeID, &avg, &cnt); err != nil {
			return err
		}
		if avg.Valid {
			aggregates[placeID] = struct {
				avg   float64
				count int
			}{avg: avg.Float64, count: cnt}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	userRatings := make(map[string]int)
	trimmedUser := strings.TrimSpace(userID)
	if trimmedUser != "" {
		userQuery := fmt.Sprintf(`SELECT place_id, rating FROM ratings WHERE user_id = ? AND place_id IN (%s)`, placeholders)
		userArgs := append([]any{trimmedUser}, args...)
		userRows, err := db.QueryContext(queryCtx, userQuery, userArgs...)
		if err != nil {
			return err
		}
		defer userRows.Close()
		for userRows.Next() {
			var placeID string
			var rating int
			if err := userRows.Scan(&placeID, &rating); err != nil {
				return err
			}
			userRatings[placeID] = rating
		}
		if err := userRows.Err(); err != nil {
			return err
		}
	}

	for i := range results {
		placeID := strings.TrimSpace(results[i].Place.ID)
		if placeID == "" {
			continue
		}
		summary := places.RatingSummary{
			GoogleRating:      results[i].Place.Rating,
			GoogleRatingCount: results[i].Place.UserRatingsTotal,
		}
		if agg, ok := aggregates[placeID]; ok {
			summary.LocalAverage = agg.avg
			summary.LocalCount = agg.count
		}
		if rating, ok := userRatings[placeID]; ok {
			summary.UserRating = rating
		}
		combinedCount := summary.GoogleRatingCount + summary.LocalCount
		summary.CombinedCount = combinedCount
		if combinedCount > 0 {
			total := summary.GoogleRating*float64(summary.GoogleRatingCount) + summary.LocalAverage*float64(summary.LocalCount)
			summary.CombinedRating = total / float64(combinedCount)
		}
		results[i].RatingSummary = summary
	}

	return nil
}

func cacheSearchResults(ctx context.Context, db *sql.DB, results []places.Result) error {
	if db == nil || len(results) == 0 {
		return nil
	}
	cacheCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	tx, err := db.BeginTx(cacheCtx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(cacheCtx, `INSERT INTO places (place_id, name, address, cuisine, rating, rating_count, lat, lng, healthy)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(place_id) DO UPDATE SET
			name = excluded.name,
			address = excluded.address,
			cuisine = excluded.cuisine,
			rating = excluded.rating,
			rating_count = excluded.rating_count,
			lat = excluded.lat,
			lng = excluded.lng,
			healthy = excluded.healthy`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, result := range results {
		if result.Place.ID == "" {
			continue
		}
		_, err := stmt.ExecContext(cacheCtx,
			result.Place.ID,
			result.Place.Name,
			result.Place.FormattedAddress,
			result.Classification.Cuisine,
			result.Place.Rating,
			result.Place.UserRatingsTotal,
			result.Place.Latitude,
			result.Place.Longitude,
			boolToInt(result.Classification.Healthy),
		)
		if err != nil {
			stmt.Close()
			tx.Rollback()
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func flushAndCloseDB(db *sql.DB) error {
	if db == nil {
		return nil
	}
	if _, err := db.Exec(`PRAGMA wal_checkpoint(FULL)`); err != nil {
		log.Printf("db: wal checkpoint failed: %v", err)
	}
	return db.Close()
}
