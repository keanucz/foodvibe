package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	_ "github.com/glebarez/go-sqlite"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
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

func createTables(db *sql.DB) error {
	tables := [3]string{`CREATE TABLE IF NOT EXISTS sessions (
		sid TEXT PRIMARY KEY,
		uid TEXT,
		FOREIGN KEY(uid) REFERENCES users(id)
	);`,
		`CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		dietary_reqs TEXT,
		tastes TEXT
	);`,
		`CREATE TABLE IF NOT EXISTS places (
  		place_id TEXT PRIMARY KEY,
    	name TEXT,
     	address TEXT,
      	cuisine TEXT,
       	rating_count INTEGER,
       	lat REAL,
       	lng REAL,
        healthy BOOLEAN,
       	timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );`}

	for _, v := range tables {
		_, err := db.Exec(v)
		if err != nil {
			println("Error creating sqlite sessions database: " + err.Error())
			return err
		}
	}
	return nil
}

func main() {
	// get some env vars for accessing the google api
	clientid := os.Getenv("CLIENT_ID")
	clientsec := os.Getenv("CLIENT_SECRET")
	if clientid == "" || clientsec == "" {
		println("CLIENT_ID and CLIENT_SECRET must be set as envvars, quitting")
		return
	} else {
		googleOauthConf.ClientID = clientid
		googleOauthConf.ClientSecret = clientsec
	}

	// open db
	db, err := sql.Open("sqlite", "data/tables.db")
	if err != nil {
		println("Error opening sqlite database: " + err.Error())
		return
	}
	defer db.Close()

	// create the tables
	err = createTables(db)
	if err != nil {
		return
	}

	mux := http.NewServeMux()
	mux.Handle("/static/styles.css", http.FileServer(http.Dir(".")))

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, googleOauthConf.AuthCodeURL("state"), http.StatusTemporaryRedirect)
	})

	// to use with google oauth2, you must register http://localhost:8080/callback as a valid redirect URL
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Missing code", http.StatusBadRequest)
			return
		}

		token, err := googleOauthConf.Exchange(context.Background(), code)
		if err != nil {
			http.Error(w, "Token exchange error: "+err.Error(), http.StatusBadRequest)
			return
		}

		client := googleOauthConf.Client(context.Background(), token)
		resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
		if err != nil {
			http.Error(w, "Google response error: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer resp.Body.Close()

		// copy api response into a struct
		var json_resp googleOauthResp
		err = json.NewDecoder(resp.Body).Decode(&json_resp)
		if err != nil {
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
			http.Error(w, "Error updating database: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = db.Exec(`INSERT OR IGNORE INTO users (id) VALUES (?)`, json_resp.Id)
		if err != nil {
			http.Error(w, "Error updating database: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	})

	mux.HandleFunc("/addplace", func(w http.ResponseWriter, r *http.Request) {
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
			http.Error(w, "Commit failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "success",
			"inserted": inserted,
		})
	})

	// takes the user's location, cuisine prefs and risk as input from the form, and finds all the places
	// from the database that are within the radius, sorts them by keanu's ai agent, and then renders the template
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		risk := r.URL.Query().Get("risk")
		cuisine := r.URL.Query().Get("cuisine")
		if risk == "" {
			http.Error(w, "Missing risk parameter", http.StatusBadRequest)
			return
		}
		if cuisine == "" {
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
			http.Error(w, "Error querying database", http.StatusBadRequest)
			return
		}

		//rows, err := db.Query(`SELECT name, address, cuisine, lat, lng FROM places WHERE
		//	(3959 * ACOS(COS(RADIANS(:lat)) * COS(RADIANS(lat)) * COS(RADIANS(lng) - RADIANS(:lng)) + SIN(RADIANS(:lat)) * SIN(RADIANS(lat)))) <= :radius_miles`)
	})

	mux.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err == http.ErrNoCookie { // check if cookie is missing
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		} else if err != nil {
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

		templ, err := template.ParseFiles("template/home.html")
		if err != nil {
			http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
			return
		}

		err = templ.Execute(w, nil)
		if err != nil {
			println("Error loading template: "+err.Error(), http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err == http.ErrNoCookie { // check if cookie is missing
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		} else if err != nil {
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

		templ, err := template.ParseFiles("template/profile.html")
		if err != nil {
			http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
			return
		}

		err = templ.Execute(w, nil)
		if err != nil {
			println("Error loading template: "+err.Error(), http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err == http.ErrNoCookie { // check if cookie is missing
			templ, err := template.ParseFiles("template/index.html")
			if err != nil {
				http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
				return
			}
			err = templ.Execute(w, nil)
			if err != nil {
				println("Error loading template: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else if err != nil {
			http.Error(w, "Error finding cookie: "+err.Error(), http.StatusInternalServerError)
			return
		} else {
			// then check if it actually has a valid uid attached
			var uid string
			err = db.QueryRow(`SELECT uid FROM sessions WHERE sid = ?`, cookie.Value).Scan(&uid)
			if err != nil {
				http.Error(w, "Error querying database", http.StatusBadRequest)
				return
			} else if uid != "" {
				http.Redirect(w, r, "/home", http.StatusPermanentRedirect)
			}
		}
	})

	http.ListenAndServe(":8080", mux)
}
