package router

import (
	"github.com/gorilla/mux"

	"github.com/imrany/vileSQL/internal/handlers/database"
	"github.com/imrany/vileSQL/internal/handlers/user"
	"github.com/imrany/vileSQL/internal/middleware"
	"github.com/imrany/vileSQL/internal/views"
)

func SetupRoutes(r *mux.Router){
	// API subrouter
	api := r.PathPrefix("/api").Subrouter()
	viewsRouter := r.PathPrefix("/").Subrouter()


	viewsRouter.HandleFunc("/", views.IndexPage).Methods("GET")
	viewsRouter.HandleFunc("/welcome", views.WelcomePage).Methods("GET")

	// Authentication routes
	api.HandleFunc("/register", user.RegisterHandler).Methods("POST")
	api.HandleFunc("/login", user.LoginHandler).Methods("POST")
	api.HandleFunc("/logout", user.LogoutHandler).Methods("POST")

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
	
	// Database content manipulation routes
	protected.HandleFunc("/databases/{id:[0-9]+}/query", database.ExecuteQueryHandler).Methods("POST")
	protected.HandleFunc("/databases/{id:[0-9]+}/tables", database.CreateTableHandler).Methods("POST")
	protected.HandleFunc("/databases/{id:[0-9]+}/tables/{table}", database.DeleteTableHandler).Methods("DELETE")
	protected.HandleFunc("/databases/{id:[0-9]+}/data", database.InsertDataHandler).Methods("POST")

	// Shared database access - no authentication required
	api.HandleFunc("/shared/{token}", database.GetSharedDatabaseHandler).Methods("GET")
	api.HandleFunc("/shared/{token}/query", database.ExecuteSharedQueryHandler).Methods("POST")
}