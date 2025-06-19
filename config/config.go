package config

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

var ConfigFiles =[]string{
	"/var/lib/vilesql/.env",
	".env",
}

func getConfigFile() (string, error){
	var count = 0
	for count < len(ConfigFiles) {
		file := ConfigFiles[count]
		if _, err := os.Stat(file); err == nil {
			return file, nil
		}
		count++
	}
	return "", fmt.Errorf("⚠️ Warning: using default variables")
}

func GetValue(key string) string {
	var configFile, err = getConfigFile()
	if err != nil {
		log.Printf("%s", err.Error())
		godotenv.Load()

		// Set default values if variables are missing
		setDefaultEnv("SESSION_KEY", "default-session-key")
		setDefaultEnv("COOKIE_STORE_KEY", "default-cookie-key")
		setDefaultEnv("SMTP_HOST", "smtp.gmail.com")
		setDefaultEnv("SMTP_PORT", "587")
		setDefaultEnv("SMTP_USERNAME", "")
		setDefaultEnv("SMTP_PASSWORD", "")
		setDefaultEnv("SMTP_FROM", "")
		return os.Getenv(key)
	}
	godotenv.Load(configFile)
	// log.Printf("Key: %s, env: %s, file: %s", key, os.Getenv(key), configFile)
	return os.Getenv(key)
}

func setDefaultEnv(key, defaultValue string) {
    if os.Getenv(key) == "" {
        os.Setenv(key, defaultValue)
    }
}