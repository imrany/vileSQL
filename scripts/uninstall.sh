#!/bin/bash

# scripts/uninstall.sh - Smart uninstaller for VileSQL
set -e

echo "VileSQL Uninstaller"
echo "==================="

# Detect installation method
detect_installation() {
    local method="unknown"
    local binary_path=""
    local system_install=false
    
    if command -v vilesql >/dev/null 2>&1; then
        binary_path=$(which vilesql)
        
        # Check installation location to determine method
        case "$binary_path" in
            /usr/bin/vilesql|/usr/local/bin/vilesql|/opt/*/bin/vilesql)
                system_install=true
                ;;
        esac
        
        # Check package managers
        if command -v dpkg >/dev/null 2>&1 && dpkg -l vilesql >/dev/null 2>&1; then
            method="deb"
        elif command -v rpm >/dev/null 2>&1 && rpm -q vilesql >/dev/null 2>&1; then
            method="rpm"
        elif command -v brew >/dev/null 2>&1 && brew list vilesql >/dev/null 2>&1; then
            method="homebrew"
        elif [ -n "$binary_path" ]; then
            method="manual"
        fi
    fi
    
    echo "$method|$binary_path|$system_install"
}

DETECTION=$(detect_installation)
INSTALL_METHOD=$(echo "$DETECTION" | cut -d'|' -f1)
BINARY_PATH=$(echo "$DETECTION" | cut -d'|' -f2)
SYSTEM_INSTALL=$(echo "$DETECTION" | cut -d'|' -f3)

if [ "$INSTALL_METHOD" = "unknown" ]; then
    echo "VileSQL not found or not installed."
    exit 0
fi

echo "Installation method: $INSTALL_METHOD"
echo "Binary location: $BINARY_PATH"
echo "System installation: $SYSTEM_INSTALL"

# Check if service is running
check_service() {
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet vilesql 2>/dev/null; then
            echo "⚠️  VileSQL service is currently running"
            read -p "Stop service before uninstalling? (Y/n): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Nn]$ ]]; then
                echo "Stopping vilesql service..."
                sudo systemctl stop vilesql
                sudo systemctl disable vilesql 2>/dev/null || true
            fi
        fi
    fi
}

# Check for running processes
check_processes() {
    if pgrep -f vilesql >/dev/null 2>&1; then
        echo "⚠️  VileSQL processes are still running"
        echo "Running processes:"
        pgrep -f vilesql | xargs ps -p
        read -p "Kill all vilesql processes? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "Killing vilesql processes..."
            pkill -f vilesql || true
            sleep 2
        fi
    fi
}

# Remove based on installation method
remove_installation() {
    case $INSTALL_METHOD in
        "deb")
            echo "Removing via apt..."
            if [ "$EUID" -ne 0 ]; then
                sudo apt remove -y vilesql
            else
                apt remove -y vilesql
            fi
            ;;
        "rpm")
            echo "Removing via rpm/yum/dnf..."
            if command -v dnf >/dev/null 2>&1; then
                if [ "$EUID" -ne 0 ]; then
                    sudo dnf remove -y vilesql
                else
                    dnf remove -y vilesql
                fi
            elif command -v yum >/dev/null 2>&1; then
                if [ "$EUID" -ne 0 ]; then
                    sudo yum remove -y vilesql
                else
                    yum remove -y vilesql
                fi
            else
                if [ "$EUID" -ne 0 ]; then
                    sudo rpm -e vilesql
                else
                    rpm -e vilesql
                fi
            fi
            ;;
        "homebrew")
            echo "Removing via Homebrew..."
            brew uninstall vilesql
            ;;
        "manual")
            echo "Removing manually installed binary..."
            if [ "$SYSTEM_INSTALL" = "true" ]; then
                if [ "$EUID" -ne 0 ]; then
                    sudo rm -f "$BINARY_PATH"
                else
                    rm -f "$BINARY_PATH"
                fi
            else
                rm -f "$BINARY_PATH"
            fi
            
            # Remove system files if system installation
            if [ "$SYSTEM_INSTALL" = "true" ] && [ "$EUID" -eq 0 ]; then
                echo "Removing system files..."
                rm -f /etc/systemd/system/vilesql.service
                rm -f /etc/logrotate.d/vilesql
                systemctl daemon-reload 2>/dev/null || true
                
                # Remove user (only if no files owned)
                if getent passwd vilesql >/dev/null 2>&1; then
                    if [ -z "$(find / -user vilesql -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null)" ]; then
                        echo "Removing vilesql user..."
                        userdel vilesql 2>/dev/null || true
                    else
                        echo "vilesql user still owns files, not removing"
                    fi
                fi
            fi
            ;;
        *)
            echo "Could not detect installation method."
            echo "Please remove vilesql manually."
            return 1
            ;;
    esac
}

# Detect system type for data directories
detect_system() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

SYSTEM=$(detect_system)

# Main uninstallation process
echo ""
check_service
check_processes

echo ""
echo "Removing VileSQL installation..."
remove_installation

# Handle data directories
echo ""
echo "Data directory cleanup:"

# Define possible data locations
DATA_DIRS=()
case $SYSTEM in
    "linux")
        DATA_DIRS+=("/var/lib/vilesql")
        DATA_DIRS+=("/etc/vilesql")
        DATA_DIRS+=("$HOME/.vilesql")
        DATA_DIRS+=("$HOME/.config/vilesql")
        ;;
    "macos")
        DATA_DIRS+=("$HOME/.vilesql")
        DATA_DIRS+=("$HOME/.config/vilesql")
        DATA_DIRS+=("$HOME/Library/Application Support/vilesql")
        ;;
esac

# Check which directories exist
EXISTING_DIRS=()
for dir in "${DATA_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        EXISTING_DIRS+=("$dir")
    fi
done

if [ ${#EXISTING_DIRS[@]} -gt 0 ]; then
    echo "Found data directories:"
    for dir in "${EXISTING_DIRS[@]}"; do
        echo "  - $dir"
    done
    echo ""
    read -p "Remove all VileSQL data directories? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Removing data directories..."
        for dir in "${EXISTING_DIRS[@]}"; do
            echo "  Removing: $dir"
            if [[ "$dir" == "/var/lib/vilesql" ]] || [[ "$dir" == "/etc/vilesql" ]]; then
                # System directories need root
                if [ "$EUID" -eq 0 ]; then
                    rm -rf "$dir"
                else
                    sudo rm -rf "$dir"
                fi
            else
                rm -rf "$dir"
            fi
        done
        echo "✅ Data directories removed."
    else
        echo "📁 Data directories preserved:"
        for dir in "${EXISTING_DIRS[@]}"; do
            echo "  - $dir"
        done
    fi
else
    echo "No data directories found."
fi

# Remove log files
LOG_FILES=(/var/log/vilesql*.log)
if [ -e "${LOG_FILES[0]}" ]; then
    echo ""
    read -p "Remove log files? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ "$EUID" -eq 0 ]; then
            rm -f /var/log/vilesql*.log
        else
            sudo rm -f /var/log/vilesql*.log
        fi
        echo "Log files removed."
    fi
fi

# Final verification
echo ""
if command -v vilesql >/dev/null 2>&1; then
    echo "⚠️  Warning: vilesql command still found in PATH"
    echo "Location: $(which vilesql)"
    echo "You may need to restart your shell or manually remove it."
else
    echo "✅ VileSQL uninstall complete!"
fi

echo ""
echo "Uninstallation finished."