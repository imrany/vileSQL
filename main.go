package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/imrany/vileSQL/router"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/cors"
)

// Configuration
const (
	PORT              = 8080
	DB_STORAGE_PATH   = "./data/user_dbs"
	SESSION_KEY       = "sqlite-web-manager-session" // Replace with a strong random key in production
	COOKIE_STORE_KEY  = "replace-with-secure-key"    // Replace with a strong random key in production
	MAX_DB_SIZE       = 50 * 1024 * 1024             // 50MB max database size
	TOKEN_EXPIRY_DAYS = 30
)

// Global variables
var (
	store = sessions.NewCookieStore([]byte(COOKIE_STORE_KEY))
	// Main SQLite database to store user information and database metadata
	systemDB *sql.DB
)

// Models
type User struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Email        string    `json:"email"`
	CreatedAt    time.Time `json:"created_at"`
}



// func executeSharedQueryHandler(w http.ResponseWriter, r *http.Request) {
// 	vars := mux.Vars(r)
// 	token := vars["token"]

// 	// Get the query from the request body
// 	var queryRequest struct {
// 		SQL string `json:"sql"`
// 	}
// 	if err := json.NewDecoder(r.Body).Decode(&queryRequest); err != nil {
// 		respondWithJSON(w, http.StatusBadRequest, ApiResponse{
// 			Success: false,
// 			Message: "Invalid request format",
// 		})
// 		return

func main() {
	r := mux.NewRouter()
	router.SetupRoutes(r)

	// Serve static files for frontend
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static")))

	// Set up CORS
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"}, // In production, replace with your domain
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}).Handler(r)

	// Start the server
	log.Printf("Server starting on port %d...", PORT)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", PORT), corsHandler))
}