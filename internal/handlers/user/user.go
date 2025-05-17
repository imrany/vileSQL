package user

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/imrany/vileSQL/internal/helper"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID  		 int  	    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Email        string    `json:"email"`
	CreatedAt    time.Time `json:"created_at"`
}

type ApiResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// User Authentication API
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid request format",
		})
		return
	}

	// Basic validation
	if user.Username == "" || user.Email == "" || user.PasswordHash == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Username, email, and password are required",
		})
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.PasswordHash), bcrypt.DefaultCost)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Error creating user",
		})
		return
	}

	// Insert the user into the database
	_, err = systemDB.Exec(
		"INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
		user.Username,
		string(hashedPassword),
		user.Email,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
				Success: false,
				Message: "Username or email already exists",
			})
		} else {
			helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
				Success: false,
				Message: "Error creating user",
			})
		}
		return
	}

	// Create user directory for databases
	userDir := filepath.Join(DB_STORAGE_PATH, user.Username)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		log.Printf("Failed to create user directory: %v", err)
	}

	helper.RespondWithJSON(w, http.StatusCreated, ApiResponse{
		Success: true,
		Message: "User registered successfully",
	})
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var loginData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid request format",
		})
		return
	}

	// Retrieve user from database
	var user User
	var hashedPassword string
	err := systemDB.QueryRow(
		"SELECT id, username, password_hash, email FROM users WHERE username = ?",
		loginData.Username,
	).Scan(&user.ID, &user.Username, &hashedPassword, &user.Email)

	if err != nil {
		helper.RespondWithJSON(w, http.StatusUnauthorized, ApiResponse{
			Success: false,
			Message: "Invalid username or password",
		})
		return
	}

	// Compare password with hash
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(loginData.Password)); err != nil {
		helper.RespondWithJSON(w, http.StatusUnauthorized, ApiResponse{
			Success: false,
			Message: "Invalid username or password",
		})
		return
	}

	// Create session
	session, _ := store.Get(r, SESSION_KEY)
	session.Values["authenticated"] = true
	session.Values["user_id"] = user.ID
	session.Values["username"] = user.Username
	if err := session.Save(r, w); err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Error creating session",
		})
		return
	}

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: "Login successful",
		Data:    user,
	})
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, SESSION_KEY)
	session.Values["authenticated"] = false
	session.Save(r, w)

	respondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: "Logout successful",
	})
}