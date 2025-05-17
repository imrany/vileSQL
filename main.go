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

	// Serve static files for frontend
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static")))

	// Set up CORS
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"}, // In production, replace with your domain
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Content-Type", "Authorization, Origin, Accept"},
		AllowCredentials: true,
	}).Handler(r)

	PORT := config.GetValue("PORT")
	if PORT == ""{
		log.Fatal("PORT is empty")
	}

	log.Printf("Server running on port %d...", PORT)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", PORT), corsHandler))
}