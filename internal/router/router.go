package router

import (
	"github.com/gorilla/mux"

	"github.com/imrany/vilesql/internal/handlers/database"
	"github.com/imrany/vilesql/internal/handlers/user"
	"github.com/imrany/vilesql/internal/middleware"
)

func SetupRoutes(r *mux.Router){
	// API subrouter
	api := r.PathPrefix("/api").Subrouter()
	
	// Authentication routes
	api.HandleFunc("/register", user.RegisterHandler).Methods("POST")
	api.HandleFunc("/login", user.LoginHandler).Methods("POST")
	api.HandleFunc("/logout", user.LogoutHandler).Methods("POST")
	api.HandleFunc("/authenticate", user.AuthenticateHandler).Methods("GET")

	// Protected routes - require authentication
	protected := api.PathPrefix("/").Subrouter()
	protected.Use(middleware.AuthMiddleware)

	// Database management routes
	protected.HandleFunc("/databases", database.CreateDatabaseHandler).Methods("POST")
	protected.HandleFunc("/databases", database.GetUserDatabasesHandler).Methods("GET")
	protected.HandleFunc("/databases/{id:[0-9]+}", database.GetDatabaseHandler).Methods("GET")
	protected.HandleFunc("/databases/{id:[0-9]+}", database.DeleteDatabaseHandler).Methods("DELETE")
	protected.HandleFunc("/databases/{id:[0-9]+}/share", database.ShareDatabaseHandler).Methods("POST")
	protected.HandleFunc("/databases/{id:[0-9]+}/share", database.DisableSharingHandler).Methods("DELETE")
	protected.HandleFunc("/databases/{id:[0-9]+}/share/renew", database.ShareDatabaseRenewShareTokenExpiryHandler).Methods("PATCH")
	protected.HandleFunc("/databases/{id:[0-9]+}/share/renew", database.ShareDatabaseRenewShareTokenHandler).Methods("POST")
	
	// Database content manipulation routes
	protected.HandleFunc("/databases/{id:[0-9]+}/query", database.ExecuteQueryHandler).Methods("POST")
	protected.HandleFunc("/databases/{id:[0-9]+}/tables", database.CreateTableHandler).Methods("POST")
	protected.HandleFunc("/databases/{id:[0-9]+}/tables/{table}", database.DeleteTableHandler).Methods("DELETE")
	// backup and download database
	protected.HandleFunc("/databases/{id:[0-9]+}/backup", database.BackupDatabaseHandler).Methods("POST")
	// insert table data
	protected.HandleFunc("/databases/{id:[0-9]+}/data", database.InsertDataHandler).Methods("POST")

	protected.HandleFunc("/databases/{id:[0-9]+}/tables/{table}", database.GetTableHandler).Methods("GET")
	// Get table data
	protected.HandleFunc("/databases/{id:[0-9]+}/tables/{table}/data", database.GetTableDataHandler).Methods("GET")
	// Update table data
	protected.HandleFunc("/databases/{id:[0-9]+}/tables/{table}/data", database.UpdateTableDataHandler).Methods("PUT")
	// Delete table data
	protected.HandleFunc("/databases/{id:[0-9]+}/tables/{table}/data", database.DeleteTableDataHandler).Methods("DELETE")
	// Get all tables in a database
	protected.HandleFunc("/databases/{id:[0-9]+}/tables", database.GetTablesHandler).Methods("GET")
	// Get table data with pagination
	protected.HandleFunc("/databases/{id:[0-9]+}/tables/{table}/data", database.GetTableDataWithPaginationHandler).Methods("GET")
	// Get table data with filtering
	protected.HandleFunc("/databases/{id:[0-9]+}/tables/{table}/data/filter", database.GetFilteredTableDataHandler).Methods("POST")
	// Get table data with sorting
	protected.HandleFunc("/databases/{id:[0-9]+}/tables/{table}/data/sort", database.GetSortedTableDataHandler).Methods("POST")
	// Get table data with search
	protected.HandleFunc("/databases/{id:[0-9]+}/tables/{table}/data/search", database.GetSearchedTableDataHandler).Methods("POST")

	// Shared database access - no authentication required
	api.HandleFunc("/shared/{token}", database.GetSharedDatabaseHandler).Methods("GET")
	api.HandleFunc("/shared/{token}/query", database.ExecuteSharedQueryHandler).Methods("POST")
}