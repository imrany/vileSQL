package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

func GetValue(key string) string {
	err := godotenv.Load(".env")
	if err != nil {
		log.Printf("Failed to load env file %v", err.Error())
		return ""
	}
	return os.Getenv(key)
}