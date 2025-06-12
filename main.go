package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"embed"
	"encoding/json"
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

// GitHub Release API response structure
type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
	Prerelease bool `json:"prerelease"`
}

// Global verbose flag
var verboseMode bool

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
	rootCmd.Flags().Bool("verbose", false, "Enable verbose logging and run in foreground")
	rootCmd.Flags().Bool("foreground", false, "Run in foreground (don't daemonize)")

	// Add subcommands
	rootCmd.AddCommand(uninstallCommand())
	rootCmd.AddCommand(upgradeCommand())
	rootCmd.AddCommand(migrateCommand())

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

	// Get verbose flag
	verboseMode, _ = cmd.Flags().GetBool("verbose")
	foregroundMode, _ := cmd.Flags().GetBool("foreground")

	// Setup logging based on verbose mode
	setupLogging(verboseMode)

	// Get custom data directory if specified
	if dataDir, _ := cmd.Flags().GetString("data-dir"); dataDir != "" {
		os.Setenv("VILESQL_DATA_DIR", dataDir)
	}

	// Ensure data directory exists and run migrations
	if err := ensureDataDir(); err != nil {
		if verboseMode {
			log.Fatalf("Failed to create data directory: %v", err)
		} else {
			fmt.Fprintf(os.Stderr, "Error: Failed to create data directory: %v\n", err)
			os.Exit(1)
		}
	}

	port, _ := cmd.Flags().GetString("port")
	host, _ := cmd.Flags().GetString("host")
	
	if envPort := config.GetValue("PORT"); envPort != "" {
		port = envPort
	}
	if envHost := config.GetValue("HOST"); envHost != "" {
		host = envHost
	}

	serverAddr := fmt.Sprintf("%s:%s", host, port)

	// Run in background unless verbose or foreground mode is enabled
	if !verboseMode && !foregroundMode {
		if err := daemonize(serverAddr); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting server: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Foreground mode - show startup messages
	if verboseMode {
		log.Printf("VileSQL server starting on http://localhost:%s", port)
		log.Printf("Data directory: %s", database.GetDataDir())
	} else {
		fmt.Printf("VileSQL server starting on http://localhost:%s\n", port)
	}

	// Check for updates on startup (non-blocking)
	if verboseMode {
		go func() {
			if hasUpdate, latestVersion := checkForUpdates(); hasUpdate {
				log.Printf("📦 New version available: %s (current: %s)", latestVersion, version)
				log.Printf("Run 'vilesql upgrade' to update")
			}
		}()
	}

	startServer(serverAddr)
}

func setupLogging(verbose bool) {
	if !verbose {
		// Disable default logging by setting output to discard
		log.SetOutput(io.Discard)
	} else {
		// Keep default logging behavior for verbose mode
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}
}

func daemonize(serverAddr string) error {
	// Check if already running as daemon
	if os.Getenv("VILESQL_DAEMON") == "1" {
		// We are the daemon process, start the server
		startServer(serverAddr)
		return nil
	}

	// Fork the process to run in background
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), "VILESQL_DAEMON=1")
	
	// Redirect stdout/stderr to /dev/null on Unix systems
	if runtime.GOOS != "windows" {
		cmd.Stdout = nil
		cmd.Stderr = nil
		cmd.Stdin = nil
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start daemon: %w", err)
	}

	// Give the daemon a moment to start
	time.Sleep(500 * time.Millisecond)

	fmt.Printf("VileSQL server started in background (PID: %d)\n", cmd.Process.Pid)
	fmt.Printf("Access the interface at: http://localhost:%s\n", strings.Split(serverAddr, ":")[1])
	fmt.Println("Use --verbose flag to run in foreground with logging")
	
	return nil
}

func startServer(serverAddr string) {
	r := mux.NewRouter()
	
	// Only add logging middleware in verbose mode
	if verboseMode {
		r.Use(middleware.LoggingMiddleware)
	}
	
	r.HandleFunc("/", controlPanel).Methods("GET")
	r.HandleFunc("/welcome", welcomePage).Methods("GET")
	router.SetupRoutes(r)

	staticSub, err := fs.Sub(staticFolder, "static")
	if err != nil {
		if verboseMode {
			log.Fatal("Failed to create static sub-filesystem:", err)
		} else {
			fmt.Fprintf(os.Stderr, "Error: Failed to create static sub-filesystem: %v\n", err)
			os.Exit(1)
		}
	}
	staticFs := http.FileServer(http.FS(staticSub))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", staticFs))

	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Content-Type", "Authorization", "Origin", "Accept"},
		AllowCredentials: true,
	}).Handler(r)

	if verboseMode {
		log.Fatal(http.ListenAndServe(serverAddr, corsHandler))
	} else {
		// Silent error handling for background mode
		if err := http.ListenAndServe(serverAddr, corsHandler); err != nil {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			os.Exit(1)
		}
	}
}

func welcomePage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(templateFolder, "templates/cpanel2.html")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		if verboseMode {
			log.Printf("Template error: %v", err)
		}
		return
	}
	data := map[string]interface{}{
		"Title":   "Welcome to VileSQL",
		"User":    "Guest",
		"Version": version,
	}
	w.WriteHeader(http.StatusOK)
	if err := tmpl.Execute(w, data); err != nil {
		if verboseMode {
			log.Printf("Template execution error: %v", err)
		}
	}
}

func controlPanel(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(templateFolder, "templates/index.html")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		if verboseMode {
			log.Printf("Template error: %v", err)
		}
		return
	}
	data := map[string]interface{}{
		"Title":   "VileSQL - SQLite Control Panel",
		"Version": version,
	}
	w.WriteHeader(http.StatusOK)
	if err := tmpl.Execute(w, data); err != nil {
		if verboseMode {
			log.Printf("Template execution error: %v", err)
		}
	}
}

// Enhanced ensureDataDir with migration support
func ensureDataDir() error {
	dataDir := database.GetDataDir()
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return fmt.Errorf("failed to create data directory %s: %w", dataDir, err)
		}
		if verboseMode {
			log.Printf("Created data directory: %s", dataDir)
		}
		
		// Write initial version file
		if err := writeVersionFile(dataDir, version); err != nil {
			if verboseMode {
				log.Printf("Warning: Could not write version file: %v", err)
			}
		}
	}

	// Run migrations
	if err := runMigrations(dataDir); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	return nil
}

// upgradeCommand creates the upgrade subcommand
func upgradeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade vilesql to the latest version",
		Long:  "Download and install the latest version of vilesql from GitHub releases",
		RunE:  runUpgrade,
	}

	cmd.Flags().Bool("backup-data", true, "Create backup before upgrade")
	cmd.Flags().Bool("check-only", false, "Only check for updates, don't install")
	cmd.Flags().Bool("pre-release", false, "Include pre-release versions")
	cmd.Flags().Bool("force", false, "Force upgrade even if same version")

	return cmd
}

func runUpgrade(cmd *cobra.Command, args []string) error {
	checkOnly, _ := cmd.Flags().GetBool("check-only")
	backupData, _ := cmd.Flags().GetBool("backup-data")
	preRelease, _ := cmd.Flags().GetBool("pre-release")
	force, _ := cmd.Flags().GetBool("force")

	fmt.Println("VileSQL Upgrade Manager")
	fmt.Println("======================")
	fmt.Printf("Current version: %s\n", version)

	// Check for latest version
	latestRelease, err := getLatestRelease(preRelease)
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}

	latestVersion := strings.TrimPrefix(latestRelease.TagName, "v")
	currentVersion := strings.TrimPrefix(version, "v")

	fmt.Printf("Latest version: %s\n", latestVersion)

	if !force && currentVersion == latestVersion {
		fmt.Println("✅ You're already running the latest version!")
		return nil
	}

	if checkOnly {
		fmt.Printf("🔄 Update available: %s → %s\n", currentVersion, latestVersion)
		fmt.Println("Run 'vilesql upgrade' to install the update")
		return nil
	}

	// Confirm upgrade
	if !force && !confirmUpgrade(latestVersion) {
		fmt.Println("Upgrade cancelled.")
		return nil
	}

	// Create backup if requested
	if backupData {
		fmt.Println("📦 Creating backup...")
		if err := createUpgradeBackup(); err != nil {
			fmt.Printf("Warning: Could not create backup: %v\n", err)
		}
	}

	// Download and install
	fmt.Println("⬇️  Downloading latest version...")
	if err := downloadAndInstall(latestRelease); err != nil {
		return fmt.Errorf("upgrade failed: %w", err)
	}

	fmt.Printf("✅ Successfully upgraded to version %s!\n", latestVersion)
	fmt.Println("Please restart vilesql to use the new version.")

	return nil
}

// migrateCommand creates the migrate subcommand
func migrateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Run database and data migrations",
		Long:  "Manually run migrations for data directory structure updates",
		RunE:  runMigrate,
	}

	cmd.Flags().Bool("dry-run", false, "Show what migrations would run without executing")
	cmd.Flags().Bool("force", false, "Force re-run all migrations")

	return cmd
}

func runMigrate(cmd *cobra.Command, args []string) error {
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	dataDir := database.GetDataDir()
	
	fmt.Println("VileSQL Migration Manager")
	fmt.Println("========================")
	fmt.Printf("Data directory: %s\n", dataDir)

	if dryRun {
		fmt.Println("DRY RUN - No changes will be made")
	}

	return runMigrations(dataDir)
}

// Check for updates from GitHub releases
func checkForUpdates() (bool, string) {
	latestRelease, err := getLatestRelease(false)
	if err != nil {
		return false, ""
	}

	latestVersion := strings.TrimPrefix(latestRelease.TagName, "v")
	currentVersion := strings.TrimPrefix(version, "v")

	return currentVersion != latestVersion, latestVersion
}

// Get latest release from GitHub API
func getLatestRelease(includePreRelease bool) (*GitHubRelease, error) {
	url := "https://api.github.com/repos/imrany/vilesql/releases"
	if !includePreRelease {
		url = "https://api.github.com/repos/imrany/vilesql/releases/latest"
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if includePreRelease {
		var releases []GitHubRelease
		if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
			return nil, err
		}
		if len(releases) == 0 {
			return nil, fmt.Errorf("no releases found")
		}
		return &releases[0], nil
	} else {
		var release GitHubRelease
		if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
			return nil, err
		}
		return &release, nil
	}
}

// Download and install the new version
func downloadAndInstall(release *GitHubRelease) error {
	// Find the appropriate asset for current platform
	assetName := fmt.Sprintf("vilesql_%s_%s_", 
		strings.TrimPrefix(release.TagName, "v"),
		runtime.GOOS)
	
	if runtime.GOARCH == "amd64" {
		assetName += "x86_64"
	} else {
		assetName += runtime.GOARCH
	}

	if runtime.GOOS == "windows" {
		assetName += ".zip"
	} else {
		assetName += ".tar.gz"
	}

	var downloadURL string
	for _, asset := range release.Assets {
		if strings.Contains(asset.Name, assetName) {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		return fmt.Errorf("no compatible binary found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// Download the file
	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	// Create temporary file
	tmpFile, err := os.CreateTemp("", "vilesql-upgrade-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write downloaded content
	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		return fmt.Errorf("failed to write download: %w", err)
	}
	tmpFile.Close()

	// Extract and install
	return extractAndInstall(tmpFile.Name(), release.TagName)
}

// Extract downloaded archive and replace binary
func extractAndInstall(archivePath, version string) error {
	// Get current binary path
	currentBinary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current binary path: %w", err)
	}

	// Create backup of current binary
	backupPath := currentBinary + ".backup"
	if err := copyFile(currentBinary, backupPath); err != nil {
		return fmt.Errorf("failed to backup current binary: %w", err)
	}

	// Extract new binary (simplified - you might want to use proper archive extraction)
	// This is a placeholder - implement proper tar.gz/zip extraction based on your needs
	fmt.Printf("Extracting %s...\n", archivePath)
	
	// For now, assume the downloaded file is the binary itself
	// In reality, you'd extract from tar.gz/zip
	if err := copyFile(archivePath, currentBinary); err != nil {
		// Restore backup on failure
		copyFile(backupPath, currentBinary)
		return fmt.Errorf("failed to install new binary: %w", err)
	}

	// Make executable
	if err := os.Chmod(currentBinary, 0755); err != nil {
		return fmt.Errorf("failed to set executable permissions: %w", err)
	}

	// Clean up backup
	os.Remove(backupPath)

	return nil
}

// Migration system
func runMigrations(dataDir string) error {
	currentVersion := getCurrentDataVersion(dataDir)
	targetVersion := version

	if verboseMode {
		fmt.Printf("Data version: %s → %s\n", currentVersion, targetVersion)
	}

	// Define migrations (version → migration function)
	migrations := map[string]func(string) error{
		"1.0.0": migrate_1_0_0,
		"1.1.0": migrate_1_1_0,
		// Add more migrations as needed
	}

	// Run necessary migrations
	for migrationVersion, migrationFunc := range migrations {
		if shouldRunMigration(currentVersion, migrationVersion, targetVersion) {
			if verboseMode {
				fmt.Printf("Running migration: %s\n", migrationVersion)
			}
			if err := migrationFunc(dataDir); err != nil {
				return fmt.Errorf("migration %s failed: %w", migrationVersion, err)
			}
		}
	}

	// Update version file
	return writeVersionFile(dataDir, targetVersion)
}

// Example migration functions
func migrate_1_0_0(dataDir string) error {
	// Create initial directory structure
	dirs := []string{"databases", "backups", "logs"}
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(dataDir, dir), 0755); err != nil {
			return err
		}
	}
	return nil
}

func migrate_1_1_0(dataDir string) error {
	// Example: Create new config directory
	configDir := filepath.Join(dataDir, "config")
	return os.MkdirAll(configDir, 0755)
}

// Helper functions
func getCurrentDataVersion(dataDir string) string {
	versionFile := filepath.Join(dataDir, ".version")
	data, err := os.ReadFile(versionFile)
	if err != nil {
		return "0.0.0" // Default for new installations
	}
	return strings.TrimSpace(string(data))
}

func writeVersionFile(dataDir, version string) error {
	versionFile := filepath.Join(dataDir, ".version")
	return os.WriteFile(versionFile, []byte(version), 0644)
}

func shouldRunMigration(current, migration, target string) bool {
	// Simple version comparison - you might want to use a proper semver library
	return current < migration && migration <= target
}

func confirmUpgrade(version string) bool {
	fmt.Printf("Upgrade to version %s? (y/N): ", version)
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

func createUpgradeBackup() error {
	timestamp := time.Now().Format("20060102-150405")
	backupFile := fmt.Sprintf("vilesql-upgrade-backup-%s.tar.gz", timestamp)
	
	dataDirs := []string{database.GetDataDir()}
	return createBackupArchive(dataDirs, backupFile)
}

func createBackupArchive(dirs []string, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	for _, dir := range dirs {
		if exists(dir) {
			if err := addToTar(tarWriter, dir, filepath.Base(dir)); err != nil {
				return err
			}
		}
	}

	fmt.Printf("Backup created: %s\n", filename)
	return nil
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

// ... (keep all the existing uninstall functions unchanged)

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

	binaryPath := os.Args[0]
	if path, err := execLookPath("vilesql"); err == nil {
		binaryPath = path
	}

	dataDirs := []string{database.GetDataDir()}
	if runtime.GOOS == "linux" {
		dataDirs = append(dataDirs, "/var/lib/vilesql", "/etc/vilesql", "/usr/share/vilesql")
	}

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

func execLookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

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

func createBackup(dirs []string) error {
	timestamp := time.Now().Format("20060102-150405")
	backupFile := fmt.Sprintf("vilesql-backup-%s.tar.gz", timestamp)
	return createBackupArchive(dirs, backupFile)
}

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