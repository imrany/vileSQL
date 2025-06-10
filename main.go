package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/imrany/vilesql/config"
	"github.com/imrany/vilesql/internal/handlers/database"
	"github.com/imrany/vilesql/internal/middleware"
	"github.com/imrany/vilesql/internal/router"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	_ "modernc.org/sqlite"
)

//go:embed static/*
var staticFolder embed.FS

//go:embed templates/*.html
var templateFolder embed.FS

var version = "dev" // Will be set by GoReleaser

func main() {
	rootCmd := &cobra.Command{
		Use:   "vilesql",
		Short: "VileSQL - SQLite Database Management Tool",
		Long:  "A powerful web-based SQLite database management interface",
		Run:   runServer,
	}

	// Add flags for server command
	rootCmd.Flags().StringP("port", "p", "5000", "Port to run the server on")
	rootCmd.Flags().StringP("host", "H", "0.0.0.0", "Host to bind the server to")
	rootCmd.Flags().String("data-dir", "", "Custom data directory path")
	rootCmd.Flags().BoolP("version", "v", false, "Show version information")

	// Add uninstall command
	rootCmd.AddCommand(uninstallCommand())

	// Handle version flag
	if v, _ := rootCmd.Flags().GetBool("version"); v {
		fmt.Printf("VileSQL version %s\n", version)
		return
	}

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runServer(cmd *cobra.Command, args []string) {
	// Handle version flag
	if v, _ := cmd.Flags().GetBool("version"); v {
		fmt.Printf("VileSQL version %s\n", version)
		return
	}

	// Get custom data directory if specified
	if dataDir, _ := cmd.Flags().GetString("data-dir"); dataDir != "" {
		// Set custom data directory (you'll need to implement this in your database package)
		os.Setenv("VILESQL_DATA_DIR", dataDir)
	}

	// Ensure data directory exists
	if err := ensureDataDir(); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	r := mux.NewRouter()
	r.Use(middleware.LoggingMiddleware)
	r.HandleFunc("/", controlPanel).Methods("GET")
	r.HandleFunc("/welcome", welcomePage).Methods("GET")
	router.SetupRoutes(r)

	// Fix: Create a sub-filesystem for the static folder
	staticSub, err := fs.Sub(staticFolder, "static")
	if err != nil {
		log.Fatal("Failed to create static sub-filesystem:", err)
	}
	staticFs := http.FileServer(http.FS(staticSub))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", staticFs))

	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Content-Type", "Authorization", "Origin", "Accept"},
		AllowCredentials: true,
	}).Handler(r)

	// Get port and host from flags or environment
	port, _ := cmd.Flags().GetString("port")
	host, _ := cmd.Flags().GetString("host")
	
	if envPort := config.GetValue("PORT"); envPort != "" {
		port = envPort
	}
	if envHost := config.GetValue("HOST"); envHost != "" {
		host = envHost
	}

	serverAddr := fmt.Sprintf("%s:%s", host, port)
	log.Printf("VileSQL server starting on http://localhost:%s", port)
	log.Printf("Data directory: %s", database.GetDataDir())
	log.Fatal(http.ListenAndServe(serverAddr, corsHandler))
}

func welcomePage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(templateFolder, "templates/cpanel2.html")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
		return
	}
	data := map[string]interface{}{
		"Title":   "Welcome to VileSQL",
		"User":    "Guest",
		"Version": version,
	}
	w.WriteHeader(http.StatusOK)
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
	}
}

func controlPanel(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(templateFolder, "templates/index.html")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
		return
	}
	data := map[string]interface{}{
		"Title":   "VileSQL - SQLite Control Panel",
		"Version": version,
	}
	w.WriteHeader(http.StatusOK)
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
	}
}

// ensureDataDir creates the data directory if it doesn't exist
func ensureDataDir() error {
	dataDir := database.GetDataDir()
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return fmt.Errorf("failed to create data directory %s: %w", dataDir, err)
		}
		log.Printf("Created data directory: %s", dataDir)
	}
	return nil
}

// uninstallCommand creates the uninstall subcommand
func uninstallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall vilesql and optionally remove data",
		Long:  "Remove vilesql configuration and optionally user data directories",
		RunE:  runUninstall,
	}

	cmd.Flags().Bool("remove-data", false, "Also remove all user data directories")
	cmd.Flags().Bool("backup-data", true, "Create backup before removing data")
	cmd.Flags().Bool("dry-run", false, "Show what would be removed without actually removing")

	return cmd
}

func runUninstall(cmd *cobra.Command, args []string) error {
	removeData, _ := cmd.Flags().GetBool("remove-data")
	backupData, _ := cmd.Flags().GetBool("backup-data")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	// Find the binary path using "which" (if available)
	binaryPath := os.Args[0]
	if path, err := execLookPath("vilesql"); err == nil {
		binaryPath = path
	}

	// Get data directories
	dataDirs := []string{
		database.GetDataDir(), // User data dir
	}

	// Add system directories for Linux
	if runtime.GOOS == "linux" {
		dataDirs = append(dataDirs, "/var/lib/vilesql", "/etc/vilesql")
	}

	// Show what would be removed
	fmt.Println("VileSQL Uninstall")
	fmt.Println("================")
	fmt.Printf("Version: %s\n", version)
	fmt.Println()

	if removeData {
		fmt.Println("The following directories will be removed:")
		for _, dir := range dataDirs {
			if exists(dir) {
				fmt.Printf("  ✓ %s\n", dir)
			} else {
				fmt.Printf("  - %s (not found)\n", dir)
			}
		}

		if !dryRun {
			if !confirmRemoval() {
				fmt.Println("Uninstall cancelled.")
				return nil
			}

			if backupData {
				if err := createBackup(dataDirs); err != nil {
					fmt.Printf("Warning: Could not create backup: %v\n", err)
				}
			}

			for _, dir := range dataDirs {
				if exists(dir) {
					if err := os.RemoveAll(dir); err != nil {
						fmt.Printf("Warning: Could not remove %s: %v\n", dir, err)
					} else {
						fmt.Printf("Removed: %s\n", dir)
					}
				}
			}
		}
	} else {
		fmt.Println("Data directories preserved:")
		for _, dir := range dataDirs {
			if exists(dir) {
				fmt.Printf("  ✓ %s\n", dir)
			}
		}
		fmt.Println("\nTo remove data directories later, run:")
		fmt.Println("  vilesql uninstall --remove-data")
	}

	// Remove the binary itself
	if !dryRun {
		if err := os.Remove(binaryPath); err != nil {
			fmt.Printf("Warning: Could not remove binary %s: %v\n", binaryPath, err)
			fmt.Println("\nTo complete uninstall, remove the vilesql binary:")
			fmt.Printf("  sudo rm %s\n", binaryPath)
		} else {
			fmt.Printf("Removed binary: %s\n", binaryPath)
		}
	}

	return nil
}

// execLookPath is a helper to find the binary path (like "which" command)
func execLookPath(file string) (string, error) {
	return exec.LookPath(file)
}

// exists checks if a file or directory exists
func exists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// confirmRemoval prompts the user for confirmation before removing directories
func confirmRemoval() bool {
	fmt.Print("Are you sure you want to remove the above directories? (y/N): ")
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

// createBackup creates a backup of the specified directories
func createBackup(dirs []string) error {
	timestamp := time.Now().Format("20060102-150405")
	backupFile := fmt.Sprintf("vilesql-backup-%s.tar.gz", timestamp)

	file, err := os.Create(backupFile)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer file.Close()

	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	for _, dir := range dirs {
		if exists(dir) {
			if err := addToTar(tarWriter, dir, filepath.Base(dir)); err != nil {
				fmt.Printf("Warning: Could not backup %s: %v\n", dir, err)
			} else {
				fmt.Printf("Backed up: %s\n", dir)
			}
		}
	}

	fmt.Printf("Backup created: %s\n", backupFile)
	return nil
}

// addToTar adds a directory to a tar archive
func addToTar(tarWriter *tar.Writer, source, target string) error {
	return filepath.Walk(source, func(file string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(fi, file)
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(source, file)
		if err != nil {
			return err
		}
		header.Name = filepath.Join(target, relPath)

		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		if !fi.Mode().IsRegular() {
			return nil
		}

		data, err := os.Open(file)
		if err != nil {
			return err
		}
		defer data.Close()

		_, err = io.Copy(tarWriter, data)
		return err
	})
}