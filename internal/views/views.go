package views

import (
	"html/template"
	"net/http"
	"path/filepath"
)

func WelcomePage(w http.ResponseWriter, r *http.Request) {
	tmplPath := filepath.Join("templates", "welcome.html")
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Title": "Welcome to vileSQL",
		"User":  "Guest",
	}

	w.WriteHeader(http.StatusOK)
	tmpl.Execute(w, data)
}

func ControlPanel(w http.ResponseWriter, r *http.Request) {
	tmplPath := filepath.Join("templates", "index.html")
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Title": "VileSQL - SQLite Control Panel",
	}

	w.WriteHeader(http.StatusOK)
	tmpl.Execute(w, data)
}