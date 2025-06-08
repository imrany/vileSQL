package middleware

import (
	"log"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/imrany/vilesql/config"
)

// Middleware to authenticate users
func AuthMiddleware(next http.Handler) http.Handler {
	SESSION_KEY := config.GetValue("SESSION_KEY")
	if SESSION_KEY == "" {
		log.Fatal("SESSION_KEY is empty")
	}

	COOKIE_STORE_KEY := config.GetValue("COOKIE_STORE_KEY")
	if COOKIE_STORE_KEY == "" {
		log.Fatal("COOKIE_STORE_KEY is empty")
	}

	store := sessions.NewCookieStore([]byte(COOKIE_STORE_KEY))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for share_token in URL query
		shareToken := r.URL.Query().Get("share_token")
		if shareToken != "" {
			next.ServeHTTP(w, r)
			return
		}

		// Fallback to session authentication
		session, _ := store.Get(r, SESSION_KEY)
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs the incoming HTTP requests
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}