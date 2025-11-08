package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"html/template"
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
	tables := [2]string{`CREATE TABLE IF NOT EXISTS sessions (
		sid TEXT PRIMARY KEY,
		uid TEXT,
		FOREIGN KEY(uid) REFERENCES users(id)
	);`,
		`CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		picture TEXT
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
		_, err = db.Exec(`INSERT OR IGNORE INTO users (id, picture) VALUES (?,?)`, json_resp.Id, json_resp.Picture)
		if err != nil {
			http.Error(w, "Error updating database: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	})

	mux.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err == http.ErrNoCookie {
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		} else if err != nil {
			http.Error(w, "Error finding cookie: "+err.Error(), http.StatusInternalServerError)
			return
		}

		var uid string
		err = db.QueryRow(`SELECT uid FROM sessions WHERE sid = ?`, cookie.Value).Scan(&uid)
		if err != nil {
			http.Error(w, "Error querying database", http.StatusBadRequest)
			return
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

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
	})

	http.ListenAndServe(":8080", mux)
}
