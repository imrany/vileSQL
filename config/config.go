package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

var ConfigFiles =[]string{
	".env",
	"/etc/vilesql/.env",
}

func GetValue(key string) string {
	var configFile string
	for _, file := range ConfigFiles {
		if _, err := os.Stat(file); err == nil {
			configFile = file
			break		
		} else {
			log.Printf("Error accessing configuration file %s: %v", file, err)
		}
	}
	err := godotenv.Load(configFile)
	if err != nil {
		log.Printf("⚠️ Warning: %s, using default variables", err.Error())
		// Set default values if variables are missing
		setDefaultEnv("SESSION_KEY", "default-session-key")
		setDefaultEnv("COOKIE_STORE_KEY", "default-cookie-key")
	}
	return os.Getenv(key)
}

func setDefaultEnv(key, defaultValue string) {
    if os.Getenv(key) == "" {
        os.Setenv(key, defaultValue)
    }
}