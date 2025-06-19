package user

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/imrany/vilesql/config"
	"github.com/imrany/vilesql/internal/handlers/database"
	"github.com/imrany/vilesql/internal/handlers/email"
	"github.com/imrany/vilesql/internal/helper"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID  		 int  	    `json:"id"`
	Username     string    `json:"username"`
	Password string    `json:"password"`
	PasswordHash string    `json:"-"`
	Email        string    `json:"email"`
	CreatedAt    time.Time `json:"created_at"`
}

type ApiResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

var dataDir = database.GetDataDir()
var SESSION_KEY = config.GetValue("SESSION_KEY")
var	COOKIE_STORE_KEY = config.GetValue("COOKIE_STORE_KEY")

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
	if user.Username == "" || user.Email == "" || user.Password== "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Username, email, and password are required",
		})
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Error creating user",
		})
		return
	}

	// Insert the user into the database
	_, err = database.SystemDB.Exec(
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
	userDir := filepath.Join(dataDir, user.Username)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		log.Printf("Failed to create user directory: %v", err)
	}

	// Send a welcome email
    emailData := email.EmailData{
        To:      []string{user.Email},
        Subject: "Welcome to vileSQL!",
        Body:    fmt.Sprintf(`
			<p>Dear %s</p> <br/>
			<p>Welcome to our service!</p>
		`, user.Username),
        IsHTML:  true,
    }
    
    err = email.SendEmail(emailData)
    if err != nil {
        log.Fatal(err)
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
	err := database.SystemDB.QueryRow(
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
	store := sessions.NewCookieStore([]byte(COOKIE_STORE_KEY))
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
	store := sessions.NewCookieStore([]byte(COOKIE_STORE_KEY))
	session, _ := store.Get(r, SESSION_KEY)
	session.Values["authenticated"] = false
	session.Save(r, w)

	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: "Logout successful",
	})
}

func AuthenticateHandler(w http.ResponseWriter, r *http.Request) {
	store := sessions.NewCookieStore([]byte(COOKIE_STORE_KEY))
	session, _ := store.Get(r, SESSION_KEY)
	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		userID, _ := session.Values["user_id"].(int)
		username, _ := session.Values["username"].(string)

		// Retrieve user details from the database
		var user User
		err := database.SystemDB.QueryRow(
			"SELECT id, username, email FROM users WHERE id = ?",
			userID,
		).Scan(&user.ID, &user.Username, &user.Email)

		if err != nil {
			helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
				Success: false,
				Message: "Error retrieving user information",
			})
			return
		}

		user.Username = username // Set the username from session
		user.CreatedAt = time.Now() // Set current time as created_at

		data:=make(map[string]interface{})
		data["user"] = user
		data["authenticated"] = true

		helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
			Success: true,
			Data:    data,
		})
	} else {
		helper.RespondWithJSON(w, http.StatusUnauthorized, ApiResponse{
			Success: false,
			Message: "User not authenticated",
		})
	}
}

// VerifyEmailHandler handles email confirmation requests 
func VerifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	var confirmData struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&confirmData); err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid request format",
		})
		return
	}
	if confirmData.Email == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Email is required",
		})
		return	
	}

	err := database.SystemDB.QueryRow(
		"SELECT email FROM users WHERE email = ?",
		confirmData.Email,
	).Scan(&confirmData.Email)

	if err != nil {
		log.Printf("Error checking email existence: %v", err)
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Error confirming email",
		})
		return
	}
    
    // Send OTP
    otp, err := email.SendOTP(confirmData.Email, "password_reset")
    if err != nil {
        log.Fatal(err)
    }
    
	type OTPData struct {
		Email string `json:"email"`
		OTP   string `json:"otp"`
	}
	helper.RespondWithJSON(w, http.StatusOK, OTPData{
		Email: confirmData.Email,
		OTP:   otp,
	})
}

// PasswodResetHandler handles password reset requests
func PasswodResetHandler(w http.ResponseWriter, r *http.Request) {
	var resetData struct {
		Email    string `json:"email"`
		NewPassword string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&resetData); err != nil {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Invalid request format",
		})
		return
	}

	if resetData.Email == "" || resetData.NewPassword == "" {
		helper.RespondWithJSON(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "Username and new password are required",
		})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(resetData.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Error resetting password",
		})
		return
	}

	result, err := database.SystemDB.Exec(
		"UPDATE users SET password_hash = ? WHERE email = ?",
		string(hashedPassword),
		resetData.Email,
	)
	if err != nil {
		if strings.Contains(err.Error(), "no rows updated") {
			helper.RespondWithJSON(w, http.StatusNotFound, ApiResponse{
				Success: false,
				Message: "User not found",
			})
			return
		}
		
		log.Printf("Error updating password: %v", err)
		
		helper.RespondWithJSON(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: "Error resetting password",
		})
		
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("No user found with email: %s", resetData.Email)
		
		helper.RespondWithJSON(w, http.StatusNotFound, ApiResponse{
			Success: false,
			Message: "User not found",
		})
		
		return
	}

	log.Printf("Password reset successful for user with email: %s", resetData.Email)

	
	data:=make(map[string]interface{})
	data["email"] = resetData.Email

	
	helper.RespondWithJSON(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: "Password reset successful",
		Data:    data,
	})
}