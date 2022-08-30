package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io"
	"net/http"
	"os"
	"time"
)

var PORT = os.Getenv("PORT")
var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))

func init() {
	if PORT == "" {
		PORT = "8080"
	}
}

func main() {
	db, err := sqlx.Open("sqlite3", "authentication.db")
	if err != nil {
		log.WithField("error", err).Fatal("Failed to create database connection")
		panic(err)
	}

	router := mux.NewRouter()
	router.Handle("/current-user", AuthMiddleware(GetCurrentUser())).Methods(http.MethodGet)
	router.HandleFunc("/login", GoogleLogin())
	router.HandleFunc("/logout", GoogleLogout)
	router.Handle("/auth/google/callback", GoogleCallback(db))

	server := http.Server{
		Addr:         "0.0.0.0:" + PORT,
		Handler:      router,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	err = server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

func AuthMiddleware(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session")
		if err != nil {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		code, err := r.Cookie("code")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token_timestamp, ok := session.Values["token_timestamp"].(string)
		if !ok {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		timestamp, err := time.Parse(time.RFC3339, token_timestamp)
		if err != nil {
			log.Errorf("Error parsing timestamp: %s", err)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		if time.Now().Sub(timestamp) > time.Hour*24*7 {
			GoogleLogout(w, r)
			return
		}

		session_code, ok := session.Values["code"].(string)
		if ok {
			if code.Value == session_code {
				handler.ServeHTTP(w, r)
				return
			}
		}

		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
}

var OauthConfig = &oauth2.Config{
	RedirectURL:  "http://localhost:8080/auth/google/callback",
	ClientID:     os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
	ClientSecret: os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
	Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
	Endpoint:     google.Endpoint,
}

func GoogleLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Generate Oauth State and set cookie
		var expiration = time.Now().Add(365 * 24 * time.Hour)
		b := make([]byte, 16)
		rand.Read(b)
		state := base64.URLEncoding.EncodeToString(b)
		cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
		http.SetCookie(w, &cookie)

		auth_url := OauthConfig.AuthCodeURL(state)
		http.Redirect(w, r, auth_url, http.StatusTemporaryRedirect)
	}
}

// User is a struct to receive the data from a FetchUserData request
type User struct {
	Id             *string `json:"id,omitempty"`
	Email          *string `json:"email,omitempty"`
	Picture        *string `json:"picture,omitempty"`
	TokenTimestamp *string `json:"token_timestamp,omitempty"`
}

// FetchUserData grabs the user's data for a given OAuth code. It generates
// a token and then uses it to make the request.
func FetchUserData(code string) (*User, error) {
	// Use code to get token and get user info from Google.
	token, err := OauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, err
	}
	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	user := &User{}
	err = json.Unmarshal(contents, user)
	return user, err
}

func GoogleCallback(db *sqlx.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Read oauthState from Cookie
		oauthState, _ := r.Cookie("oauthstate")

		if r.FormValue("state") != oauthState.Value {
			log.
				WithField("expected", oauthState.Value).
				WithField("actual", r.FormValue("state")).
				Info("invalid oauth google state")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		userdata, err := FetchUserData(r.FormValue("code"))
		if err != nil {
			log.Println(err.Error())
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		_, err = db.Exec(
			"insert into users(id, email, picture) values(?, ?, ?)",
			userdata.Id, userdata.Email, userdata.Picture,
		)
		if err != nil && err.Error() != "UNIQUE constraint failed: USERS.ID" {
			log.Errorf("%q", err.Error())
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		cookie := http.Cookie{Name: "code", Value: r.FormValue("code"), Expires: time.Now().Add(time.Hour * 24 * 7), Path: "/"}
		http.SetCookie(w, &cookie)

		session, _ := store.Get(r, "session")
		session.Values["code"] = r.FormValue("code")
		session.Values["id"] = userdata.Id
		session.Values["email"] = userdata.Email
		session.Values["token_timestamp"] = time.Now().Format(time.RFC3339)

		err = session.Save(r, w)
		if err != nil {
			log.Errorf("%q", err.Error())
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}
}
func GetCurrentUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session")
		if err != nil {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		user := &User{}
		id := session.Values["id"].(string)
		user.Id = &id
		email := session.Values["email"].(string)
		user.Email = &email
		token_timestamp := session.Values["token_timestamp"].(string)
		user.TokenTimestamp = &token_timestamp
		json.NewEncoder(w).Encode(user)
	}
}

func GoogleLogout(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{Name: "code", Value: "", Path: "/", Expires: time.Unix(0, 0)}
	http.SetCookie(w, cookie)
	cookie = &http.Cookie{Name: "session", Value: "", Path: "/", Expires: time.Unix(0, 0)}
	http.SetCookie(w, cookie)

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
