package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/imrany/vileSQL/config"
	"github.com/imrany/vileSQL/router"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/cors"
)

func main() {
	r := mux.NewRouter()
	router.SetupRoutes(r)

	r.Use(loggingMiddleware)
	// Serve static files for frontend
	fs:=http.FileServer(http.Dir("./static"))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))

	// Set up CORS
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"}, // In production, replace with your domain
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Content-Type", "Authorization, Origin, Accept"},
		AllowCredentials: true,
	}).Handler(r)

	PORT := config.GetValue("PORT")
	if PORT == ""{
		PORT = "8000"
	}
	log.Printf("Server running on port %v...", PORT)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("0.0.0.0:%v", PORT), corsHandler))
}

// loggingMiddleware logs the incoming HTTP requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}