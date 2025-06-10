#!/bin/bash
set -e

echo "VileSQL Uninstaller"
echo "==================="

# Detect installation method
INSTALL_METHOD="unknown"
BINARY_PATH=""

if command -v vilesql >/dev/null 2>&1; then
    BINARY_PATH=$(which vilesql)
    
    # Check if installed via package manager
    if dpkg -l vilesql >/dev/null 2>&1; then
        INSTALL_METHOD="deb"
    elif rpm -q vilesql >/dev/null 2>&1; then
        INSTALL_METHOD="rpm"
    elif brew list vilesql >/dev/null 2>&1; then
        INSTALL_METHOD="homebrew"
    else
        INSTALL_METHOD="manual"
    fi
fi

echo "Installation method: $INSTALL_METHOD"
echo "Binary location: $BINARY_PATH"

# Uninstall based on method
case $INSTALL_METHOD in
    "deb")
        echo "Removing via apt..."
        sudo apt remove vilesql
        ;;
    "rpm")
        echo "Removing via rpm..."
        sudo rpm -e vilesql
        ;;
    "homebrew")
        echo "Removing via homebrew..."
        brew uninstall vilesql
        ;;
    "manual")
        echo "Removing manually installed binary..."
        sudo rm -f "$BINARY_PATH"
        ;;
    *)
        echo "Could not detect installation method."
        echo "Please remove vilesql manually."
        ;;
esac

# Ask about data removal
echo ""
read -p "Remove all vilesql data directories? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Removing data directories..."
    rm -rf ~/.vilesql
    rm -rf ~/Library/Application\ Support/vilesql  # macOS
    sudo rm -rf /var/lib/vilesql                   # Linux system
    sudo rm -rf /etc/vilesql                       # Linux config
    echo "Data directories removed."
else
    echo "Data directories preserved."
fi

echo "VileSQL uninstall complete!"