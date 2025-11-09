package main

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"

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
	Picture       string `json:"picture"`
}
type Restaurant struct {
	PlaceID     string  `json:"place_id"`
	Name        string  `json:"name"`
	Address     string  `json:"address"`
	Cuisine     string  `json:"cuisine"`
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
	Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
	Endpoint:     google.Endpoint,
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
			rating_count INTEGER,
			lat REAL,
			lng REAL,
			healthy BOOLEAN,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);`,
		},
	}

	for _, tbl := range tables {
		log.Printf("db: ensuring %s table", tbl.name)
		if _, err := db.Exec(tbl.query); err != nil {
			log.Printf("db: failed ensuring %s table: %v", tbl.name, err)
			return err
		}
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
	log.Printf("db: opened sqlite database at %s", dbPath)
	defer db.Close()

	// create the tables
	err = createTables(db)
	if err != nil {
		log.Println("db: schema setup failed, shutting down")
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
		_, err = db.Exec(`INSERT INTO sessions (sid, uid) VALUES (?,?)`, sessionID, json_resp.Id)
		if err != nil {
			log.Printf("auth: insert session failed: %v", err)
			http.Error(w, "Error updating database: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = db.Exec(`INSERT OR IGNORE INTO users (id) VALUES (?)`, json_resp.Id)
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
			INSERT INTO places(place_id, name, address, cuisine, rating_count, lat, lng, healthy)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

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
				res.RatingCount, res.Lat, res.Lng, res.Healthy)
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

		results, err := placeSvc.Search(r.Context(), places.SearchOptions{
			Latitude:     lat,
			Longitude:    lng,
			RadiusMeters: radiusMeters,
			MaxResults:   10,
		})
		if err != nil {
			log.Printf("place search failed: %v", err)
			http.Error(w, "Failed to search nearby venues", http.StatusBadGateway)
			return
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
		}

		if err := renderTemplate(w, "home.html", nil); err != nil {
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
		}

		if err := renderTemplate(w, "profile.html", nil); err != nil {
			log.Printf("ui: profile template render error: %v", err)
			http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("ui: profile rendered for user %s", uid)
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

	log.Println("server: listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("server: shutdown due to error: %v", err)
	}
}

func renderTemplate(w http.ResponseWriter, name string, data any) error {
	tmpl := parsedTemplates.Lookup(name)
	if tmpl == nil {
		return fmt.Errorf("template %q not found", name)
	}
	return tmpl.Execute(w, data)
}
