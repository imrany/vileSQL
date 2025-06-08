package main

import (
	"embed"
	"fmt"
	"log"
	"net/http"
	"html/template"
	"io/fs"
	"github.com/gorilla/mux"
	"github.com/imrany/vilesql/config"
	"github.com/imrany/vilesql/internal/middleware"
	"github.com/imrany/vilesql/internal/router"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/cors"
)

//go:embed static/*
var staticFolder embed.FS

//go:embed templates/*.html
var templateFolder embed.FS

func main() {
	r := mux.NewRouter()
	r.Use(middleware.LoggingMiddleware)
	r.HandleFunc("/", controlPanel).Methods("GET")
	r.HandleFunc("/welcome", welcomePage).Methods("GET")
	router.SetupRoutes(r)

	// Fix: Create a sub-filesystem for the static folder
	staticSub, err := fs.Sub(staticFolder, "static")
	if err != nil {
		log.Fatal("Failed to create static sub-filesystem:", err)
	}
	staticFs := http.FileServer(http.FS(staticSub))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", staticFs))

	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Content-Type", "Authorization", "Origin", "Accept"}, // Fixed: removed comma
		AllowCredentials: true,
	}).Handler(r)

	PORT := config.GetValue("PORT")
	if PORT == "" {
		PORT = "5000"
	}
	serverAddr := fmt.Sprintf("0.0.0.0:%v", PORT)
	log.Printf("Open vilesql at http://localhost:%v", PORT)
	log.Fatal(http.ListenAndServe(serverAddr, corsHandler))
}

func welcomePage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(templateFolder, "templates/cpanel2.html")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
		return
	}
	data := map[string]interface{}{
		"Title": "Welcome to vileSQL",
		"User":  "Guest",
	}
	w.WriteHeader(http.StatusOK)
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
	}
}

func controlPanel(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(templateFolder, "templates/index.html")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
		return
	}
	data := map[string]interface{}{
		"Title": "VileSQL - SQLite Control Panel",
	}
	w.WriteHeader(http.StatusOK)
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
	}
}