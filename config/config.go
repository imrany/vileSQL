package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

func GetValue(key string) string {
	err := godotenv.Load()
	if err != nil {
		log.Print("⚠️ Warning: .env file not found, using default values.")
	}
	// Set default values if variables are missing
    setDefaultEnv("SESSION_KEY", "default-session-key")
    setDefaultEnv("COOKIE_STORE_KEY", "default-cookie-key")
	return os.Getenv(key)
}

func setDefaultEnv(key, defaultValue string) {
    if os.Getenv(key) == "" {
        os.Setenv(key, defaultValue)
    }
}