package database

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
	"github.com/imrany/vileSQL/config"
	"github.com/imrany/vileSQL/internal/helper"
)

type Database struct {
	ID          int       `json:"id"`
	UserID      int       `json:"user_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	FilePath    string    `json:"-"`
	ShareToken  string    `json:"share_token,omitempty"`
	TokenExpiry time.Time `json:"token_expiry,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type TableInfo struct {
	Name    string   `json:"name"`
	Columns []Column `json:"columns"`
	RowCount int `json:"row_count"`
}

type Column struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	NotNull  bool   `json:"not_null"`
	PK       bool   `json:"pk"`
	DefaultValue interface{} `json:"default_value"`
}

// Helper to convert columns array to SQL string
func ColumnsToSQL(columns []Column) string {
	defs := make([]string, len(columns))
	for i, col := range columns {
		def := fmt.Sprintf("%s %s", col.Name, col.Type)
		if col.NotNull {
			def += " NOT NULL"
		}
		if col.PK {
			def += " PRIMARY KEY"
		}
		if col.DefaultValue != nil {
			def += fmt.Sprintf(" DEFAULT %v", col.DefaultValue)
		}
		defs[i] = def
	}
	return strings.Join(defs, ", ")
}
type ApiResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}


// Configuration
const (
	MAX_DB_SIZE       = 50 * 1024 * 1024             // 50MB max database size
	TOKEN_EXPIRY_DAYS = 30
)

// Main SQLite database to store user information and database metadata
var SystemDB *sql.DB

// Initialize the application
func init() {
	DB_STORAGE_PATH := config.GetValue("DB_STORAGE_PATH")
	if DB_STORAGE_PATH == ""{
		log.Fatal("DB_STORAGE_PATH is empty")
	}
	
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(DB_STORAGE_PATH, 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	// Initialize the system database
	var err error
	SystemDB, err = sql.Open("sqlite3", "./data/system.db")
	if err != nil {
		log.Fatalf("Failed to open system database: %v", err)
	}

	// Create tables in the system database if they don't exist
	setupSystemDB()
}

func setupSystemDB() {
	// Create users table
	_, err := SystemDB.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			email TEXT UNIQUE NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		log.Fatalf("Failed to create users table: %v", err)
	}

	// Create billing table
	_, err = SystemDB.Exec(`
		CREATE TABLE IF NOT EXISTS billing (
			external_reference TEXT NOT NULL PRIMARY KEY,
			mpesa_receipt_number TEXT,
			checkout_request_id TEXT,
			merchant_request_id TEXT,
			amount INTEGER NOT NULL,
			result_code TEXT,
			result_description TEXT,
			status TEXT,
			user_id INTEGER NOT NULL,
			plan TEXT NOT NULL,
			start_date TIMESTAMP NOT NULL,
			end_date TIMESTAMP NOT NULL,
			payment_method TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)
	`)
	if err != nil {
		log.Fatalf("Failed to create billing table: %v", err)
	}

	// Create databases table
	_, err = SystemDB.Exec(`
		CREATE TABLE IF NOT EXISTS databases (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			file_path TEXT NOT NULL,
			share_token TEXT,
			token_expiry TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id),
			UNIQUE(user_id, name)
		)
	`)
	if err != nil {
		log.Fatalf("Failed to create databases table: %v", err)
	}
}

// Database Management API
func CreateDatabaseHandler(w http.ResponseWriter, r *http.Request) {
	SESSION_KEY := config.GetValue("SESSION_KEY")
	if SESSION_KEY ==""{
		log.Fatal("SESSION_KEY is empty")
	}

	DB_STORAGE_PATH := config.GetValue("DB_STORAGE_PATH")
	if DB_STORAGE_PATH == ""{
		log.Fatal("DB_STORAGE_PATH is empty")
	}

	COOKIE_STORE_KEY := config.GetValue("COOKIE_STORE_KEY")
	if COOKIE_STORE_KEY == ""{
		log.Fatal("COOKIE_STORE_KEY is empty")
	}

	store := sessions.NewCookieStore([]byte(COOKIE_STORE_KEY))
	session, _ := store.Get(r, SESSION_KEY)
	userID := session.Values["user_id"].(int)
	username := session.Values["username"].(string)

	var dbInfo Database
	if err := json.NewDecoder(r.Body).Decode(&dbInfo); err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid request format",
		})
		return
	}

	if dbInfo.Name == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Database name is required",
		})
		return
	}

	// Sanitize database name (keep it alphanumeric with underscores)
	sanitizedName := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, dbInfo.Name)

	// Create file path for the new database
	userDir := filepath.Join(DB_STORAGE_PATH, username)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to create user directory",
		})
		return
	}

	dbFilePath := filepath.Join(userDir, sanitizedName+".db")

	// Check if database already exists
	if _, err := os.Stat(dbFilePath); err == nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Database with this name already exists",
		})
		return
	}

	// Create a new SQLite database file
	db, err := sql.Open("sqlite3", dbFilePath)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to create database file",
		})
		return
	}
	defer db.Close()

	// Test the database connection
	if err := db.Ping(); err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to connect to new database",
		})
		return
	}

	// Record the database in the system database
	result, err := SystemDB.Exec(
		"INSERT INTO databases (user_id, name, description, file_path) VALUES (?, ?, ?, ?)",
		userID,
		sanitizedName,
		dbInfo.Description,
		dbFilePath,
	)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to register database",
		})
		os.Remove(dbFilePath) // Clean up the file if registration fails
		return
	}

	// Get the newly created database ID
	dbID, _ := result.LastInsertId()
	dbInfo.ID = int(dbID)
	dbInfo.UserID = userID
	dbInfo.FilePath = dbFilePath
	dbInfo.CreatedAt = time.Now()
	dbInfo.UpdatedAt = time.Now()

	helper.RespondWithJSON(w, http.StatusCreated, ApiResponse{
		Success: true,
		Message: "Database created successfully",
		Data:    dbInfo,
	})
}

func GetUserDatabasesHandler(w http.ResponseWriter, r *http.Request) {
	SESSION_KEY := config.GetValue("SESSION_KEY")
	if SESSION_KEY ==""{
		log.Fatal("SESSION_KEY is empty")
	}

	COOKIE_STORE_KEY := config.GetValue("COOKIE_STORE_KEY")
	if COOKIE_STORE_KEY == ""{
		log.Fatal("COOKIE_STORE_KEY is empty")
	}
	
	store := sessions.NewCookieStore([]byte(COOKIE_STORE_KEY))
	session, _ := store.Get(r, SESSION_KEY)
	userID := session.Values["user_id"].(int)

	rows, err := SystemDB.Query(
		"SELECT id, name, description, share_token, token_expiry, created_at, updated_at FROM databases WHERE user_id = ?",
		userID,
	)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to retrieve databases",
		})
		return
	}
	defer rows.Close()

	var databases []Database
	for rows.Next() {
		var db Database
		var shareToken, tokenExpiry sql.NullString
		err := rows.Scan(
			&db.ID,
			&db.Name,
			&db.Description,
			&shareToken,
			&tokenExpiry,
			&db.CreatedAt,
			&db.UpdatedAt,
		)
		if err != nil {
			log.Printf("Error scanning database row: %v", err)
			continue
		}

		db.UserID = userID
		if shareToken.Valid {
			db.ShareToken = shareToken.String
		}
		if tokenExpiry.Valid {
			expiry, err := time.Parse(time.RFC3339, tokenExpiry.String)
			if err == nil {
				db.TokenExpiry = expiry
			}
		}

		databases = append(databases, db)
	}

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Data:    databases,
	})
}

func ShareDatabaseHandler(w http.ResponseWriter, r *http.Request) {
	SESSION_KEY := config.GetValue("SESSION_KEY")
	if SESSION_KEY ==""{
		log.Fatal("SESSION_KEY is empty")
	}
	
	COOKIE_STORE_KEY := config.GetValue("COOKIE_STORE_KEY")
	if COOKIE_STORE_KEY == ""{
		log.Fatal("COOKIE_STORE_KEY is empty")
	}
	
	store := sessions.NewCookieStore([]byte(COOKIE_STORE_KEY))
	session, _ := store.Get(r, SESSION_KEY)
	userID := session.Values["user_id"].(int)

	vars := mux.Vars(r)
	dbID, err := strconv.Atoi(vars["id"])
	if err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid database ID",
		})
		return
	}

	// Generate a random share token
	token := fmt.Sprintf("%d-%d", time.Now().UnixNano(), dbID)
	tokenExpiry := time.Now().AddDate(0, 0, TOKEN_EXPIRY_DAYS)

	// First, check if the database belongs to the user
	var count int
	err = SystemDB.QueryRow(
		"SELECT COUNT(*) FROM databases WHERE id = ? AND user_id = ?",
		dbID, userID,
	).Scan(&count)

	if err != nil || count == 0 {
		helper.RespondWithJSON(w, http.StatusForbidden, ApiResponse{
			Success: false,
			Message: "You don't have permission to share this database",
		})
		return
	}

	// Update the database with the share token
	_, err = SystemDB.Exec(
		"UPDATE databases SET share_token = ?, token_expiry = ? WHERE id = ?",
		token, tokenExpiry.Format(time.RFC3339), dbID,
	)

	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to generate share link",
		})
		return
	}

	shareURL := fmt.Sprintf("/shared/%s", token)

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: "Database shared successfully",
		Data: map[string]interface{}{
			"share_token":  token,
			"token_expiry": tokenExpiry,
			"share_url":    shareURL,
		},
	})
}

func DisableSharingHandler(w http.ResponseWriter, r *http.Request) {
	SESSION_KEY := config.GetValue("SESSION_KEY")
	if SESSION_KEY ==""{
		log.Fatal("SESSION_KEY is empty")
	}

	COOKIE_STORE_KEY := config.GetValue("COOKIE_STORE_KEY")
	if COOKIE_STORE_KEY == ""{
		log.Fatal("COOKIE_STORE_KEY is empty")
	}
	
	store := sessions.NewCookieStore([]byte(COOKIE_STORE_KEY))
	session, _ := store.Get(r, SESSION_KEY)
	userID := session.Values["user_id"].(int)

	vars := mux.Vars(r)
	dbID, err := strconv.Atoi(vars["id"])
	if err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid database ID",
		})
		return
	}

	// Check if the database belongs to the user
	var count int
	err = SystemDB.QueryRow(
		"SELECT COUNT(*) FROM databases WHERE id = ? AND user_id = ?",
		dbID, userID,
	).Scan(&count)

	if err != nil || count == 0 {
		helper.RespondWithJSON(w, http.StatusForbidden, ApiResponse{
			Success: false,
			Message: "You don't have permission to modify this database",
		})
		return
	}

	// Remove the share token
	_, err = SystemDB.Exec(
		"UPDATE databases SET share_token = NULL, token_expiry = NULL WHERE id = ?",
		dbID,
	)

	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to disable sharing",
		})
		return
	}

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: "Sharing disabled successfully",
	})
}

func GetSharedDatabaseHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]

	var db Database
	var tokenExpiry time.Time
	err := SystemDB.QueryRow(
		`SELECT id, user_id, name, description, file_path, token_expiry, created_at, updated_at 
         FROM databases WHERE share_token = ?`,
		token,
	).Scan(
		&db.ID,
		&db.UserID,
		&db.Name,
		&db.Description,
		&db.FilePath,
		&tokenExpiry,
		&db.CreatedAt,
		&db.UpdatedAt,
	)

	if err != nil {
		helper.RespondWithJSON(w, http.StatusNotFound, ApiResponse{
			Success: false,
			Message: "Shared database not found or link expired",
		})
		return
	}

	// Check if the token has expired
	if time.Now().After(tokenExpiry) {
		helper.RespondWithJSON(w, http.StatusForbidden, ApiResponse{
			Success: false,
			Message: "Share link has expired",
		})
		return
	}

	// Get the database schema (tables and columns) in read-only mode
	userDB, err := sql.Open("sqlite3", db.FilePath+"?mode=ro")
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to open database",
		})
		return
	}
	defer userDB.Close()

	// Query for table names
	rows, err := userDB.Query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to retrieve database schema",
		})
		return
	}
	defer rows.Close()

	tables := []TableInfo{}
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			continue
		}

		// Get columns for each table
		tableInfo := TableInfo{Name: tableName}
		pragmaRows, err := userDB.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
		if err == nil {
			defer pragmaRows.Close()
			for pragmaRows.Next() {
				var cid int
				var name string
				var dataType string
				var notNull int
				var defaultValue interface{}
				var pk int

				if err := pragmaRows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
					continue
				}

				column := Column{
					Name:         name,
					Type:         dataType,
					NotNull:      notNull == 1,
					PK:           pk > 0,
					DefaultValue: defaultValue,
				}
				tableInfo.Columns = append(tableInfo.Columns, column)
			}
		}

		tables = append(tables, tableInfo)
	}

	response := struct {
		Database Database    `json:"database"`
		Tables   []TableInfo `json:"tables"`
		ReadOnly bool        `json:"read_only"`
	}{
		Database: db,
		Tables:   tables,
		ReadOnly: true,
	}

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Data:    response,
	})
}

// Database Query API
func ExecuteQueryHandler(w http.ResponseWriter, r *http.Request) {
	SESSION_KEY := config.GetValue("SESSION_KEY")
	if SESSION_KEY ==""{
		log.Fatal("SESSION_KEY is empty")
	}

	COOKIE_STORE_KEY := config.GetValue("COOKIE_STORE_KEY")
	if COOKIE_STORE_KEY == ""{
		log.Fatal("COOKIE_STORE_KEY is empty")
	}
	
	store := sessions.NewCookieStore([]byte(COOKIE_STORE_KEY))
	session, _ := store.Get(r, SESSION_KEY)
	userID := session.Values["user_id"].(int)

	vars := mux.Vars(r)
	dbID, err := strconv.Atoi(vars["id"])
	if err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid database ID",
		})
		return
	}

	// Get the query from the request body
	var queryRequest struct {
		SQL string `json:"sql"`
	}
	log.Printf("Executing query for database ID %d by user ID %d, %v", dbID, userID, r.Body)
	if err := json.NewDecoder(r.Body).Decode(&queryRequest); err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid request format",
		})
		return
	}

	if queryRequest.SQL == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "SQL query is required",
		})
		return
	}

	// Get the database file path
	var filePath string
	var dbUserID int
	err = SystemDB.QueryRow(
		"SELECT file_path, user_id FROM databases WHERE id = ?",
		dbID,
	).Scan(&filePath, &dbUserID)

	if err != nil {
		helper.RespondWithJSON(w, http.StatusNotFound, ApiResponse{
			Success: false,
			Message: "Database not found",
		})
		return
	}

	// Check if the database belongs to the user
	if dbUserID != userID {
		helper.RespondWithJSON(w, http.StatusForbidden, ApiResponse{
			Success: false,
			Message: "You don't have permission to query this database",
		})
		return
	}

	// Open the user's database
	userDB, err := sql.Open("sqlite3", filePath)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to open database",
		})
		return
	}
	defer userDB.Close()

	// Execute the query
	rows, err := userDB.Query(queryRequest.SQL)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Query execution failed: %v", err),
		})
		return
	}
	defer rows.Close()

	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to get column information",
		})
		return
	}

	// Prepare the result set
	result := make([]map[string]interface{}, 0)
	columnTypes, _ := rows.ColumnTypes()
	
	// Prepare values holder
	values := make([]interface{}, len(columns))
	valuePtrs := make([]interface{}, len(columns))
	for i := range values {
		valuePtrs[i] = &values[i]
	}

	// Fetch rows
	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}

		entry := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			
			// Handle SQLite specific types
			switch v := val.(type) {
			case []byte:
				// Try to convert []byte to string if it looks like text
				entry[col] = string(v)
			case nil:
				entry[col] = nil
			default:
				entry[col] = v
			}
		}
		result = append(result, entry)
	}

	// Check for errors from iterating over rows
	if err := rows.Err(); err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Error processing results: %v", err),
		})
		return
	}

	queryResult := struct {
		Columns []string                  `json:"columns"`
		Types   []string                  `json:"types"`
		Rows    []map[string]interface{}  `json:"rows"`
	}{
		Columns: columns,
		Types:   make([]string, len(columnTypes)),
		Rows:    result,
	}

	// Extract column types
	for i, ct := range columnTypes {
		queryResult.Types[i] = ct.DatabaseTypeName()
	}

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Data:    queryResult,
	})
}

func CreateTableHandler(w http.ResponseWriter, r *http.Request) {
	SESSION_KEY := config.GetValue("SESSION_KEY")
	if SESSION_KEY ==""{
		log.Fatal("SESSION_KEY is empty")
	}

	COOKIE_STORE_KEY := config.GetValue("COOKIE_STORE_KEY")
	if COOKIE_STORE_KEY == ""{
		log.Fatal("COOKIE_STORE_KEY is empty")
	}
	
	store := sessions.NewCookieStore([]byte(COOKIE_STORE_KEY))
	session, _ := store.Get(r, SESSION_KEY)
	userID := session.Values["user_id"].(int)

	vars := mux.Vars(r)
	dbID, err := strconv.Atoi(vars["id"])
	if err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid database ID",
		})
		return
	}

	// Parse the table creation request
	var tableRequest struct {
		Name    string   `json:"name"`
		Columns string `json:"columns"`
	}
	if err := json.NewDecoder(r.Body).Decode(&tableRequest); err != nil {
		log.Printf("Error decoding request body: %v", err)
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid request format",
		})
		return
	}

	// Validate the table name
	if tableRequest.Name == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Table name is required",
		})
		return
	}

	// Validate the columns
	if len(tableRequest.Columns) == 0 {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "At least one column is required",
		})
		return
	}

	// Get the database file path
	var filePath string
	var dbUserID int
	err = SystemDB.QueryRow(
		"SELECT file_path, user_id FROM databases WHERE id = ?",
		dbID,
	).Scan(&filePath, &dbUserID)

	if err != nil {
		helper.RespondWithJSON(w, http.StatusNotFound, ApiResponse{
			Success: false,
			Message: "Database not found",
		})
		return
	}

	// Check if the database belongs to the user
	if dbUserID != userID {
		helper.RespondWithJSON(w, http.StatusForbidden, ApiResponse{
			Success: false,
			Message: "You don't have permission to modify this database",
		})
		return
	}

	// Open the user's database
	userDB, err := sql.Open("sqlite3", filePath)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to open database",
		})
		return
	}
	defer userDB.Close()

	// Build the CREATE TABLE SQL statement
	createSQL := fmt.Sprintf("CREATE TABLE %s (%s)", tableRequest.Name, tableRequest.Columns)
	// Execute the CREATE TABLE statement
	_, err = userDB.Exec(createSQL)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to create table: %v", err),
		})
		return
	}

	helper.RespondWithJSON(w, http.StatusCreated, ApiResponse{
		Success: true,
		Message: "Table created successfully",
		Data: map[string]interface{}{
			"name":    tableRequest.Name,
			"columns": tableRequest.Columns,
		},
	})
}

func InsertDataHandler(w http.ResponseWriter, r *http.Request) {
	SESSION_KEY := config.GetValue("SESSION_KEY")
	if SESSION_KEY ==""{
		log.Fatal("SESSION_KEY is empty")
	}

	COOKIE_STORE_KEY := config.GetValue("COOKIE_STORE_KEY")
	if COOKIE_STORE_KEY == ""{
		log.Fatal("COOKIE_STORE_KEY is empty")
	}
	
	store := sessions.NewCookieStore([]byte(COOKIE_STORE_KEY))
	session, _ := store.Get(r, SESSION_KEY)
	userID := session.Values["user_id"].(int)

	vars := mux.Vars(r)
	dbID, err := strconv.Atoi(vars["id"])
	if err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid database ID",
		})
		return
	}

	// Parse the data insertion request
	var insertRequest struct {
		Table  string       				`json:"table"`
		Columns string      				`json:"columns,omitempty"` // Optional, can be used to specify columns
		Values string `json:"values"`
	}
	if err := json.NewDecoder(r.Body).Decode(&insertRequest); err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid request format",
		})
		return
	}

	// Validate the request
	if insertRequest.Table == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Table name is required",
		})
		return
	}

	if len(insertRequest.Values) == 0 {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "At least one row of values is required",
		})
		return
	}

	if len(insertRequest.Columns) == 0 {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Columns are required for data insertion",
		})
		return
	}
	
	// Get the database file path
	var filePath string
	var dbUserID int
	err = SystemDB.QueryRow(
		"SELECT file_path, user_id FROM databases WHERE id = ?",
		dbID,
	).Scan(&filePath, &dbUserID)

	if err != nil {
		helper.RespondWithJSON(w, http.StatusNotFound, ApiResponse{
			Success: false,
			Message: "Database not found",
		})
		return
	}

	// Check if the database belongs to the user
	if dbUserID != userID {
		helper.RespondWithJSON(w, http.StatusForbidden, ApiResponse{
			Success: false,
			Message: "You don't have permission to modify this database",
		})
		return
	}

	// Open the user's database
	userDB, err := sql.Open("sqlite3", filePath)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to open database",
		})
		return
	}
	defer userDB.Close()

	// Start a transaction
	tx, err := userDB.Begin()
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to start transaction",
		})
		return
	}
	defer tx.Rollback()

	// Insert each row of data
	// columns and values are comma-separated strings
	columns := strings.Split(insertRequest.Columns, ",")
	valuesList := strings.Split(insertRequest.Values, ",") // assume rows are separated by semicolons

	if len(columns) == 0 || len(valuesList) == 0 {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Columns and values cannot be empty",
		})
		return
	}

	if len(columns) != len(valuesList) {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Number of columns and values must match",
		})
		return
	}

	insertSQL := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s)",
		insertRequest.Table,
		insertRequest.Columns,
		insertRequest.Values,
	)

	result, err := tx.Exec(insertSQL)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to insert data: %v", err),
		})
		return
	}
	// Get the number of rows affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to get number of affected rows",
		})
		return
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to commit transaction",
		})
		return
	}

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully inserted %d rows", rowsAffected),
		Data: map[string]interface{}{
			"rows_affected": rowsAffected,
		},
	})
}

func DeleteTableHandler(w http.ResponseWriter, r *http.Request) {
	SESSION_KEY := config.GetValue("SESSION_KEY")
	if SESSION_KEY ==""{
		log.Fatal("SESSION_KEY is empty")
	}

	COOKIE_STORE_KEY := config.GetValue("COOKIE_STORE_KEY")
	if COOKIE_STORE_KEY == ""{
		log.Fatal("COOKIE_STORE_KEY is empty")
	}
	
	store := sessions.NewCookieStore([]byte(COOKIE_STORE_KEY))
	session, _ := store.Get(r, SESSION_KEY)
	userID := session.Values["user_id"].(int)

	vars := mux.Vars(r)
	dbID, err := strconv.Atoi(vars["id"])
	if err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid database ID",
		})
		return
	}

	tableName := vars["table"]
	if tableName == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Table name is required",
		})
		return
	}

	// Get the database file path
	var filePath string
	var dbUserID int
	err = SystemDB.QueryRow(
		"SELECT file_path, user_id FROM databases WHERE id = ?",
		dbID,
	).Scan(&filePath, &dbUserID)

	if err != nil {
		helper.RespondWithJSON(w, http.StatusNotFound, ApiResponse{
			Success: false,
			Message: "Database not found",
		})
		return
	}

	// Check if the database belongs to the user
	if dbUserID != userID {
		helper.RespondWithJSON(w, http.StatusForbidden, ApiResponse{
			Success: false,
			Message: "You don't have permission to modify this database",
		})
		return
	}

	// Open the user's database
	userDB, err := sql.Open("sqlite3", filePath)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to open database",
		})
		return
	}
	defer userDB.Close()

	// Execute the DROP TABLE statement
	_, err = userDB.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", tableName))
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to delete table: %v", err),
		})
		return
	}

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: fmt.Sprintf("Table '%s' deleted successfully", tableName),
	})
}

func DeleteDatabaseHandler(w http.ResponseWriter, r *http.Request) {
	SESSION_KEY := config.GetValue("SESSION_KEY")
	if SESSION_KEY ==""{
		log.Fatal("SESSION_KEY is empty")
	}

	COOKIE_STORE_KEY := config.GetValue("COOKIE_STORE_KEY")
	if COOKIE_STORE_KEY == ""{
		log.Fatal("COOKIE_STORE_KEY is empty")
	}
	
	store := sessions.NewCookieStore([]byte(COOKIE_STORE_KEY))
	session, _ := store.Get(r, SESSION_KEY)
	userID := session.Values["user_id"].(int)

	vars := mux.Vars(r)
	dbID, err := strconv.Atoi(vars["id"])
	if err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid database ID",
		})
		return
	}

	// Get the database file path
	var filePath string
	var dbUserID int
	err = SystemDB.QueryRow(
		"SELECT file_path, user_id FROM databases WHERE id = ?",
		dbID,
	).Scan(&filePath, &dbUserID)

	if err != nil {
		helper.RespondWithJSON(w, http.StatusNotFound, ApiResponse{
			Success: false,
			Message: "Database not found",
		})
		return
	}

	// Check if the database belongs to the user
	if dbUserID != userID {
		helper.RespondWithJSON(w, http.StatusForbidden, ApiResponse{
			Success: false,
			Message: "You don't have permission to delete this database",
		})
		return
	}

	// Delete the database record from the system database
	_, err = SystemDB.Exec("DELETE FROM databases WHERE id = ?", dbID)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to delete database record",
		})
		return
	}

	// Delete the database file
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: Failed to delete database file %s: %v", filePath, err)
	}

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: "Database deleted successfully",
	})
}

func ExecuteSharedQueryHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]

	// Get the query from the request body
	var queryRequest struct {
		SQL string `json:"sql"`
	}
	if err := json.NewDecoder(r.Body).Decode(&queryRequest); err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid request format",
		})
		return
	}

	if queryRequest.SQL == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "SQL query is required",
		})
		return
	}

	// Verify that the share token is valid and not expired
	var filePath string
	var tokenExpiry time.Time
	err := SystemDB.QueryRow(
		"SELECT file_path, token_expiry FROM databases WHERE share_token = ?",
		token,
	).Scan(&filePath, &tokenExpiry)

	if err != nil {
		helper.RespondWithJSON(w, http.StatusNotFound, ApiResponse{
			Success: false,
			Message: "Shared database not found",
		})
		return
	}

	// Check if the token has expired
	if time.Now().After(tokenExpiry) {
		helper.RespondWithJSON(w, http.StatusForbidden, ApiResponse{
			Success: false,
			Message: "Share link has expired",
		})
		return
	}

	// Open the user's database in read-only mode
	userDB, err := sql.Open("sqlite3", filePath+"?mode=ro")
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to open database",
		})
		return
	}
	defer userDB.Close()

	// Block any write operations for shared databases
	lowercaseSQL := strings.ToLower(strings.TrimSpace(queryRequest.SQL))
	if strings.HasPrefix(lowercaseSQL, "insert") ||
		strings.HasPrefix(lowercaseSQL, "update") ||
		strings.HasPrefix(lowercaseSQL, "delete") ||
		strings.HasPrefix(lowercaseSQL, "drop") ||
		strings.HasPrefix(lowercaseSQL, "alter") ||
		strings.HasPrefix(lowercaseSQL, "create") {
		helper.RespondWithJSON(w, http.StatusForbidden, ApiResponse{
			Success: false,
			Message: "Write operations are not allowed for shared databases",
		})
		return
	}

	// Execute the query
	rows, err := userDB.Query(queryRequest.SQL)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Query execution failed: %v", err),
		})
		return
	}
	defer rows.Close()

	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to get column information",
		})
		return
	}

	// Prepare the result set
	result := make([]map[string]interface{}, 0)
	columnTypes, _ := rows.ColumnTypes()
	
	// Prepare values holder
	values := make([]interface{}, len(columns))
	valuePtrs := make([]interface{}, len(columns))
	for i := range values {
		valuePtrs[i] = &values[i]
	}

	// Fetch rows with a reasonable limit
	rowCount := 0
	maxRows := 10000 // Limit to prevent excessive memory usage
	
	for rows.Next() {
		if rowCount >= maxRows {
			break
		}
		
		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}

		entry := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			
			// Handle SQLite specific types
			switch v := val.(type) {
			case []byte:
				// Try to convert []byte to string if it looks like text
				entry[col] = string(v)
			case nil:
				entry[col] = nil
			default:
				entry[col] = v
			}
		}
		result = append(result, entry)
		rowCount++
	}

	// Check for errors from iterating over rows
	if err := rows.Err(); err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Error processing results: %v", err),
		})
		return
	}

	queryResult := struct {
		Columns  []string                 `json:"columns"`
		Types    []string                 `json:"types"`
		Rows     []map[string]interface{} `json:"rows"`
		ReadOnly bool                     `json:"read_only"`
		RowCount int                      `json:"row_count"`
		Limited  bool                     `json:"limited"`
	}{
		Columns:  columns,
		Types:    make([]string, len(columnTypes)),
		Rows:     result,
		ReadOnly: true,
		RowCount: rowCount,
		Limited:  rowCount >= maxRows,
	}

	// Extract column types
	for i, ct := range columnTypes {
		queryResult.Types[i] = ct.DatabaseTypeName()
	}

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Data:    queryResult,
	})
}

func GetDatabaseHandler(w http.ResponseWriter, r *http.Request) {
	SESSION_KEY := config.GetValue("SESSION_KEY")
	if SESSION_KEY ==""{
		log.Fatal("SESSION_KEY is empty")
	}

	COOKIE_STORE_KEY := config.GetValue("COOKIE_STORE_KEY")
	if COOKIE_STORE_KEY == ""{
		log.Fatal("COOKIE_STORE_KEY is empty")
	}
	
	store := sessions.NewCookieStore([]byte(COOKIE_STORE_KEY))
	session, err := store.Get(r, SESSION_KEY)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusUnauthorized, ApiResponse{
			Success: false,
			Message: "Invalid session",
		})
		return
	}
	
	userID, ok := session.Values["user_id"].(int)
	if !ok {
		helper.RespondWithJSON(w, http.StatusUnauthorized, ApiResponse{
			Success: false,
			Message: "Invalid user session",
		})
		return
	}

	vars := mux.Vars(r)
	dbID, err := strconv.Atoi(vars["id"])
	if err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid database ID",
		})
		return
	}

	var db Database
	var shareToken, tokenExpiry sql.NullString
	err = SystemDB.QueryRow(
		`SELECT id, user_id, name, description, file_path, share_token, token_expiry, created_at, updated_at 
         FROM databases WHERE id = ?`,
		dbID,
	).Scan(
		&db.ID,
		&db.UserID,
		&db.Name,
		&db.Description,
		&db.FilePath,
		&shareToken,
		&tokenExpiry,
		&db.CreatedAt,
		&db.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			helper.RespondWithJSON(w, http.StatusNotFound, ApiResponse{
				Success: false,
				Message: "Database not found",
			})
		} else {
			helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
				Success: false,
				Message: "Database query error",
			})
			log.Fatal("Database query error", err)
		}
		return
	}

	// Check if the database belongs to the user
	if db.UserID != userID {
		helper.RespondWithJSON(w, http.StatusForbidden, ApiResponse{
			Success: false,
			Message: "You don't have permission to access this database",
		})
		return
	}

	if shareToken.Valid {
		db.ShareToken = shareToken.String
	}
	if tokenExpiry.Valid {
		expiry, err := time.Parse(time.RFC3339, tokenExpiry.String)
		if err == nil {
			db.TokenExpiry = expiry
		}
	}

	// Check if database file exists
	if _, err := os.Stat(db.FilePath); os.IsNotExist(err) {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Database file not found",
		})
		log.Fatal("Database file not found", db.FilePath)
		return
	}

	// Get the database schema (tables and columns)
	userDB, err := sql.Open("sqlite3", db.FilePath)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to open database",
		})
		log.Fatal("Failed to open database", err)
		return
	}
	defer userDB.Close()

	// Validate DB connection
	if err := userDB.Ping(); err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Database connection error",
		})
		log.Fatal("Database connection error", err)
		return
	}

	// Query for table names - exclude SQLite internal tables
	rows, err := userDB.Query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to retrieve database schema",
		})
		log.Fatal("Failed to retrieve schema", err)
		return
	}
	defer rows.Close()

	tables := []TableInfo{}
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			log.Fatal("Error scanning table name", err)
			continue
		}

		// Get columns for each table
		tableInfo := TableInfo{Name: tableName}
		pragmaRows, err := userDB.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
		if err == nil {
			defer pragmaRows.Close()
			for pragmaRows.Next() {
				var cid int
				var name string
				var dataType string
				var notNull int
				var defaultValue interface{}
				var pk int

				if err := pragmaRows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
					log.Fatal("Error scanning column info", err)
					continue
				}

				column := Column{
					Name:         name,
					Type:         dataType,
					NotNull:      notNull == 1,
					PK:           pk > 0,
					DefaultValue: defaultValue,
				}
				tableInfo.Columns = append(tableInfo.Columns, column)
			}
		}

		// Get the row count for each table
		var rowCount int
		countRow := userDB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName))
		if err := countRow.Scan(&rowCount); err == nil {
			tableInfo.RowCount = rowCount
		}

		tables = append(tables, tableInfo)
	}

	// Get database size
	fileInfo, err := os.Stat(db.FilePath)
	var dbSize int64
	if err == nil {
		dbSize = fileInfo.Size()
	}

	response := struct {
		Database    Database    `json:"database"`
		Tables      []TableInfo `json:"tables"`
		Size        int64       `json:"size_bytes"`
		SizeDisplay string      `json:"size_display"`
	}{
		Database:    db,
		Tables:      tables,
		Size:        dbSize,
		SizeDisplay: strconv.FormatInt(dbSize, 10),
	}

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Data:    response,
	})
}

func GetTableHandler(w http.ResponseWriter, r *http.Request) {
	SESSION_KEY := config.GetValue("SESSION_KEY")
	COOKIE_STORE_KEY := config.GetValue("COOKIE_STORE_KEY")
	if SESSION_KEY == "" || COOKIE_STORE_KEY == "" {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Server configuration error",
		})
		return
	}
	store := sessions.NewCookieStore([]byte(COOKIE_STORE_KEY))
	session, _ := store.Get(r, SESSION_KEY)
	userID := session.Values["user_id"].(int)

	vars := mux.Vars(r)
	dbID, err := strconv.Atoi(vars["id"])
	tableName := vars["table"]
	if err != nil || tableName == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid database ID or table name",
		})
		return
	}

	var filePath string
	var dbUserID int
	err = SystemDB.QueryRow("SELECT file_path, user_id FROM databases WHERE id = ?", dbID).Scan(&filePath, &dbUserID)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusNotFound, ApiResponse{
			Success: false,
			Message: "Database not found",
		})
		return
	}
	if dbUserID != userID {
		helper.RespondWithJSON(w, http.StatusForbidden, ApiResponse{
			Success: false,
			Message: "You don't have permission to access this database",
		})
		return
	}

	userDB, err := sql.Open("sqlite3", filePath)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to open database",
		})
		return
	}
	defer userDB.Close()

	pragmaRows, err := userDB.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Failed to get table info",
		})
		return
	}
	defer pragmaRows.Close()

	var columns []Column
	for pragmaRows.Next() {
		var cid int
		var name, dataType string
		var notNull, pk int
		var defaultValue interface{}
		if err := pragmaRows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
			continue
		}
		columns = append(columns, Column{
			Name:         name,
			Type:         dataType,
			NotNull:      notNull == 1,
			PK:           pk > 0,
			DefaultValue: defaultValue,
		})
	}

	var rowCount int
	countRow := userDB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName))
	_ = countRow.Scan(&rowCount)

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Data: TableInfo{
			Name:     tableName,
			Columns:  columns,
			RowCount: rowCount,
		},
	})
}

func InsertTableDataHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dbID := vars["id"]
	tableName := vars["table"]

	if tableName == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid table name",
		})
		return
	}

	userDB, _, _, ok := authenticateAndGetDB(w, r, dbID)
	if !ok {
		return
	}
	defer userDB.Close()

	var insertRequest struct {
		Values []map[string]interface{} `json:"values"`
	}
	if err := json.NewDecoder(r.Body).Decode(&insertRequest); err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid request format",
		})
		return
	}

	if len(insertRequest.Values) == 0 {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "At least one row of values is required",
		})
		return
	}

	tx, err := userDB.Begin()
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to start transaction",
		})
		return
	}
	defer tx.Rollback()

	var rowsAffected int64
	for _, rowData := range insertRequest.Values {
		if len(rowData) == 0 {
			continue
		}
		columns := make([]string, 0, len(rowData))
		placeholders := make([]string, 0, len(rowData))
		values := make([]interface{}, 0, len(rowData))
		for col, val := range rowData {
			columns = append(columns, col)
			placeholders = append(placeholders, "?")
			values = append(values, val)
		}
		insertSQL := fmt.Sprintf(
			"INSERT INTO %s (%s) VALUES (%s)",
			tableName,
			strings.Join(columns, ", "),
			strings.Join(placeholders, ", "),
		)
		result, err := tx.Exec(insertSQL, values...)
		if err != nil {
			helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
				Success: false,
				Message: fmt.Sprintf("Failed to insert data: %v", err),
			})
			return
		}
		affected, _ := result.RowsAffected()
		rowsAffected += affected
	}

	if err := tx.Commit(); err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to commit transaction",
		})
		return
	}

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully inserted %d rows", rowsAffected),
		Data: map[string]interface{}{
			"rows_affected": rowsAffected,
		},
	})
}

func GetTableDataHandler(w http.ResponseWriter, r *http.Request) {
	SESSION_KEY := config.GetValue("SESSION_KEY")
	COOKIE_STORE_KEY := config.GetValue("COOKIE_STORE_KEY")
	if SESSION_KEY == "" || COOKIE_STORE_KEY == "" {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Server configuration error",
		})
		return
	}
	store := sessions.NewCookieStore([]byte(COOKIE_STORE_KEY))
	session, _ := store.Get(r, SESSION_KEY)
	userID := session.Values["user_id"].(int)

	vars := mux.Vars(r)
	dbID, err := strconv.Atoi(vars["id"])
	tableName := vars["table"]
	if err != nil || tableName == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid database ID or table name",
		})
		return
	}

	var filePath string
	var dbUserID int
	err = SystemDB.QueryRow("SELECT file_path, user_id FROM databases WHERE id = ?", dbID).Scan(&filePath, &dbUserID)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusNotFound, ApiResponse{
			Success: false,
			Message: "Database not found",
		})
		return
	}
	if dbUserID != userID {
		helper.RespondWithJSON(w, http.StatusForbidden, ApiResponse{
			Success: false,
			Message: "You don't have permission to access this database",
		})
		return
	}

	userDB, err := sql.Open("sqlite3", filePath)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to open database",
		})
		return
	}
	defer userDB.Close()

	rows, err := userDB.Query(fmt.Sprintf("SELECT * FROM %s", tableName))
	if err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Failed to get table data",
		})
		return
	}
	defer rows.Close()

	columns, _ := rows.Columns()
	columnType, _:=rows.ColumnTypes()

	result := make([]map[string]interface{}, 0)
	values := make([]interface{}, len(columns))
	valuePtrs := make([]interface{}, len(columns))
	for i := range values {
		valuePtrs[i] = &values[i]
	}
	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}
		entry := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			switch v := val.(type) {
			case []byte:
				entry[col] = string(v)
			default:
				entry[col] = v
			}
		}
		result = append(result, entry)
	}

	valuesArr := make([][]interface{}, 0, len(result))
	for _, row := range result {
		rowArr := make([]interface{}, len(columns))
		for i, col := range columns {
			rowArr[i] = row[col]
		}
		valuesArr = append(valuesArr, rowArr)
	}

	// Build columns info array with name and constraint/type
	columnsInfo := make([]map[string]interface{}, len(columns))
	for i, col := range columns {
		leng, _:=columnType[i].Length()
		isNull, _:=columnType[i].Nullable()
		columnsInfo[i] = map[string]any{
			"name": col,
			"constraint": map[string]any{
				"type":     columnType[i].DatabaseTypeName(),
				"length":   leng,
				"not_null": !isNull, // NOT NULL constraint
				// Add more constraints below
				"primary_key": false,
				"default":     nil,
				"unique":      false,
			},
		}

		// Get PRIMARY KEY and DEFAULT constraints from PRAGMA table_info
		pragmaRows2, err := userDB.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
		if err == nil {
			for pragmaRows2.Next() {
				var cid int
				var name, dataType string
				var notNull, pk int
				var defaultValue interface{}
				if err := pragmaRows2.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err == nil {
					if name == col {
						columnsInfo[i]["constraint"].(map[string]any)["primary_key"] = pk > 0
						columnsInfo[i]["constraint"].(map[string]any)["default"] = defaultValue
						break
					}
				}
			}
			pragmaRows2.Close()
		}

		// Try to get UNIQUE constraint from PRAGMA index_list and index_info
		var isUnique bool
		indexRows, err := userDB.Query(fmt.Sprintf("PRAGMA index_list(%s)", tableName))
		if err == nil {
			for indexRows.Next() {
				var idxSeq int
				var idxName string
				var unique int
				var origin, partial interface{}
				if err := indexRows.Scan(&idxSeq, &idxName, &unique, &origin, &partial); err == nil && unique == 1 {
					// Check if this index covers the current column
					infoRows, err := userDB.Query(fmt.Sprintf("PRAGMA index_info(%s)", idxName))
					if err == nil {
						for infoRows.Next() {
							var seqno, cid int
							var idxColName string
							if err := infoRows.Scan(&seqno, &cid, &idxColName); err == nil && idxColName == col {
								isUnique = true
							}
						}
						infoRows.Close()
					}
				}
			}
			indexRows.Close()
		}
		columnsInfo[i]["constraint"].(map[string]any)["unique"] = isUnique
	}

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Data: map[string]interface{}{
			"columns": columnsInfo,
			"values":  valuesArr,
		},
	})
}

func authenticateAndGetDB(w http.ResponseWriter, r *http.Request, dbID string) (*sql.DB, int, string, bool) {
	SESSION_KEY := config.GetValue("SESSION_KEY")
	COOKIE_STORE_KEY := config.GetValue("COOKIE_STORE_KEY")
	if SESSION_KEY == "" || COOKIE_STORE_KEY == "" {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Server configuration error",
		})
		return nil, 0, "", false
	}

	store := sessions.NewCookieStore([]byte(COOKIE_STORE_KEY))
	session, _ := store.Get(r, SESSION_KEY)
	userID := session.Values["user_id"].(int)

	dbIDInt, err := strconv.Atoi(dbID)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid database ID",
		})
		return nil, 0, "", false
	}

	var filePath string
	var dbUserID int
	err = SystemDB.QueryRow("SELECT file_path, user_id FROM databases WHERE id = ?", dbIDInt).Scan(&filePath, &dbUserID)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusNotFound, ApiResponse{
			Success: false,
			Message: "Database not found",
		})
		return nil, 0, "", false
	}

	if dbUserID != userID {
		helper.RespondWithJSON(w, http.StatusForbidden, ApiResponse{
			Success: false,
			Message: "You don't have permission to access this database",
		})
		return nil, 0, "", false
	}

	userDB, err := sql.Open("sqlite3", filePath)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to open database",
		})
		return nil, 0, "", false
	}

	return userDB, userID, filePath, true
}

func UpdateTableDataHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dbID := vars["id"]
	tableName := vars["table"]

	if tableName == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid table name",
		})
		return
	}

	userDB, _, _, ok := authenticateAndGetDB(w, r, dbID)
	if !ok {
		return
	}
	defer userDB.Close()

	var updateData map[string]any
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid JSON data",
		})
		return
	}

	condition, ok := updateData["condition"].(map[string]any)
	if !ok {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Missing condition for update",
		})
		return
	}

	data, ok := updateData["data"].(map[string]any)
	if !ok {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Missing data for update",
		})
		return
	}

	var setClauses []string
	var setValues []any
	for key, value := range data {
		setClauses = append(setClauses, fmt.Sprintf("%s = ?", key))
		setValues = append(setValues, value)
	}

	var whereClauses []string
	var whereValues []any
	for key, value := range condition {
		whereClauses = append(whereClauses, fmt.Sprintf("%s = ?", key))
		whereValues = append(whereValues, value)
	}

	allValues := append(setValues, whereValues...)

	query := fmt.Sprintf("UPDATE %s SET %s WHERE %s",
		tableName,
		strings.Join(setClauses, ", "),
		strings.Join(whereClauses, " AND "))

	log.Printf("Executing query: %s with values: %v", query, allValues)

	result, err := userDB.Exec(query, allValues...)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to update data: " + err.Error(),
		})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: fmt.Sprintf("Updated %d row(s)", rowsAffected),
		Data:    map[string]int64{"rows_affected": rowsAffected},
	})
}

func DeleteTableDataHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dbID := vars["id"]
	tableName := vars["table"]

	if tableName == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid table name",
		})
		return
	}

	userDB, _, _, ok := authenticateAndGetDB(w, r, dbID)
	if !ok {
		return
	}
	defer userDB.Close()

	var condition map[string]any
	if err := json.NewDecoder(r.Body).Decode(&condition); err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid JSON data",
		})
		return
	}

	var whereClauses []string
	var whereValues []any
	for key, value := range condition {
		whereClauses = append(whereClauses, fmt.Sprintf("%s = ?", key))
		whereValues = append(whereValues, value)
	}

	if len(whereClauses) == 0 {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "No condition provided for deletion",
		})
		return
	}

	query := fmt.Sprintf("DELETE FROM %s WHERE %s",
		tableName,
		strings.Join(whereClauses, " AND "))

	result, err := userDB.Exec(query, whereValues...)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to delete data: " + err.Error(),
		})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: fmt.Sprintf("Deleted %d row(s)", rowsAffected),
		Data:    map[string]int64{"rows_affected": rowsAffected},
	})
}

func GetTablesHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dbID := vars["id"]

	userDB, _, _, ok := authenticateAndGetDB(w, r, dbID)
	if !ok {
		return
	}
	defer userDB.Close()

	rows, err := userDB.Query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Failed to get tables",
		})
		return
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			continue
		}
		tables = append(tables, tableName)
	}

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Data:    tables,
	})
}

func GetTableDataWithPaginationHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dbID := vars["id"]
	tableName := vars["table"]

	if tableName == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid table name",
		})
		return
	}

	userDB, _, _, ok := authenticateAndGetDB(w, r, dbID)
	if !ok {
		return
	}
	defer userDB.Close()

	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 50
	}

	offset := (page - 1) * limit

	var totalCount int
	countRow := userDB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName))
	_ = countRow.Scan(&totalCount)

	query := fmt.Sprintf("SELECT * FROM %s LIMIT ? OFFSET ?", tableName)
	rows, err := userDB.Query(query, limit, offset)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Failed to get table data",
		})
		return
	}
	defer rows.Close()

	columns, _ := rows.Columns()
	result := make([]map[string]any, 0)
	values := make([]any, len(columns))
	valuePtrs := make([]any, len(columns))
	for i := range values {
		valuePtrs[i] = &values[i]
	}
	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}
		entry := make(map[string]any)
		for i, col := range columns {
			val := values[i]
			switch v := val.(type) {
			case []byte:
				entry[col] = string(v)
			default:
				entry[col] = v
			}
		}
		result = append(result, entry)
	}

	totalPages := (totalCount + limit - 1) / limit

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Data: map[string]any{
			"data":        result,
			"page":        page,
			"limit":       limit,
			"total_count": totalCount,
			"total_pages": totalPages,
			"has_next":    page < totalPages,
			"has_prev":    page > 1,
		},
	})
}

func GetFilteredTableDataHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dbID := vars["id"]
	tableName := vars["table"]

	if tableName == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid table name",
		})
		return
	}

	userDB, _, _, ok := authenticateAndGetDB(w, r, dbID)
	if !ok {
		return
	}
	defer userDB.Close()

	filters := make(map[string]string)
	for key, values := range r.URL.Query() {
		if key != "page" && key != "limit" && len(values) > 0 {
			filters[key] = values[0]
		}
	}

	if len(filters) == 0 {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "No filters provided",
		})
		return
	}

	var whereClauses []string
	var whereValues []any
	for key, value := range filters {
		whereClauses = append(whereClauses, fmt.Sprintf("%s LIKE ?", key))
		whereValues = append(whereValues, "%"+value+"%")
	}

	query := fmt.Sprintf("SELECT * FROM %s WHERE %s",
		tableName,
		strings.Join(whereClauses, " AND "))

	rows, err := userDB.Query(query, whereValues...)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Failed to get filtered data: " + err.Error(),
		})
		return
	}
	defer rows.Close()

	columns, _ := rows.Columns()
	result := make([]map[string]any, 0)
	values := make([]any, len(columns))
	valuePtrs := make([]any, len(columns))
	for i := range values {
		valuePtrs[i] = &values[i]
	}
	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}
		entry := make(map[string]any)
		for i, col := range columns {
			val := values[i]
			switch v := val.(type) {
			case []byte:
				entry[col] = string(v)
			default:
				entry[col] = v
			}
		}
		result = append(result, entry)
	}

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Data:    result,
	})
}

func GetSortedTableDataHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dbID := vars["id"]
	tableName := vars["table"]

	if tableName == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid table name",
		})
		return
	}

	userDB, _, _, ok := authenticateAndGetDB(w, r, dbID)
	if !ok {
		return
	}
	defer userDB.Close()

	sortBy := r.URL.Query().Get("sort_by")
	sortOrder := r.URL.Query().Get("sort_order")

	if sortBy == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Missing sort_by parameter",
		})
		return
	}

	if sortOrder != "ASC" && sortOrder != "DESC" {
		sortOrder = "ASC"
	}

	query := fmt.Sprintf("SELECT * FROM %s ORDER BY %s %s", tableName, sortBy, sortOrder)
	rows, err := userDB.Query(query)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Failed to get sorted data: " + err.Error(),
		})
		return
	}
	defer rows.Close()

	columns, _ := rows.Columns()
	result := make([]map[string]any, 0)
	values := make([]any, len(columns))
	valuePtrs := make([]any, len(columns))
	for i := range values {
		valuePtrs[i] = &values[i]
	}
	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}
		entry := make(map[string]any)
		for i, col := range columns {
			val := values[i]
			switch v := val.(type) {
			case []byte:
				entry[col] = string(v)
			default:
				entry[col] = v
			}
		}
		result = append(result, entry)
	}

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Data:    result,
	})
}

func GetSearchedTableDataHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dbID := vars["id"]
	tableName := vars["table"]

	if tableName == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid table name",
		})
		return
	}

	userDB, _, _, ok := authenticateAndGetDB(w, r, dbID)
	if !ok {
		return
	}
	defer userDB.Close()

	searchTerm := r.URL.Query().Get("q")
	searchColumns := r.URL.Query()["columns"]

	if searchTerm == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Missing search term (q parameter)",
		})
		return
	}

	if len(searchColumns) == 0 {
		pragmaRows, err := userDB.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
		if err != nil {
			helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
				Success: false,
				Message: "Failed to get table info",
			})
			return
		}
		defer pragmaRows.Close()

		for pragmaRows.Next() {
			var cid int
			var name, dataType string
			var notNull, pk int
			var defaultValue any
			if err := pragmaRows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
				continue
			}
			if strings.Contains(strings.ToUpper(dataType), "TEXT") ||
				strings.Contains(strings.ToUpper(dataType), "VARCHAR") ||
				strings.Contains(strings.ToUpper(dataType), "CHAR") {
				searchColumns = append(searchColumns, name)
			}
		}
	}

	if len(searchColumns) == 0 {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "No searchable columns found",
		})
		return
	}

	var searchClauses []string
	var searchValues []any
	for _, column := range searchColumns {
		searchClauses = append(searchClauses, fmt.Sprintf("%s LIKE ?", column))
		searchValues = append(searchValues, "%"+searchTerm+"%")
	}

	query := fmt.Sprintf("SELECT * FROM %s WHERE %s",
		tableName,
		strings.Join(searchClauses, " OR "))

	rows, err := userDB.Query(query, searchValues...)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Failed to search data: " + err.Error(),
		})
		return
	}
	defer rows.Close()

	columns, _ := rows.Columns()
	result := make([]map[string]any, 0)
	values := make([]any, len(columns))
	valuePtrs := make([]any, len(columns))
	for i := range values {
		valuePtrs[i] = &values[i]
	}
	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}
		entry := make(map[string]any)
		for i, col := range columns {
			val := values[i]
			switch v := val.(type) {
			case []byte:
				entry[col] = string(v)
			default:
				entry[col] = v
			}
		}
		result = append(result, entry)
	}

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Data: map[string]any{
			"results":        result,
			"search_term":    searchTerm,
			"search_columns": searchColumns,
			"count":          len(result),
		},
	})
}
