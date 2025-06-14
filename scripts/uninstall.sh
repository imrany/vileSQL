#!/bin/bash

# Smart Uninstaller for VileSQL
set -e

echo "🚀 VileSQL Uninstaller"
echo "==================="

USER="vilesql"
GROUP="vilesql"
SERVICE_PATH="/etc/systemd/system/vilesql.service"
DATA_DIR="/var/lib/vilesql"
CONFIG_FILE="$DATA_DIR/.env"
LOG_DIR="/var/log/vilesql"
LOG_FILE="/var/log/vilesql.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log "🛠️ Detecting installation method..."
INSTALL_METHOD="unknown"
if command -v dpkg &>/dev/null && dpkg -l vilesql &>/dev/null; then
    INSTALL_METHOD="deb"
elif command -v rpm &>/dev/null && rpm -q vilesql &>/dev/null; then
    INSTALL_METHOD="rpm"
elif command -v brew &>/dev/null && brew list vilesql &>/dev/null; then
    INSTALL_METHOD="homebrew"
elif command -v vilesql &>/dev/null; then
    INSTALL_METHOD="manual"
fi

log "Detected installation method: $INSTALL_METHOD"

# Stop service if running
if systemctl is-active --quiet vilesql; then
    log "🔴 Stopping VileSQL service..."
    systemctl stop vilesql
fi

if systemctl is-enabled --quiet vilesql; then
    log "⚙️ Disabling VileSQL service..."
    systemctl disable vilesql
fi

log "🗑️ Removing systemd service file..."
rm -f "$SERVICE_PATH"
systemctl daemon-reload || true

# Remove installation method-specific files
log "🧹 Removing VileSQL installation..."
case $INSTALL_METHOD in
    "deb") sudo apt remove -y vilesql ;;
    "rpm") sudo dnf remove -y vilesql || sudo yum remove -y vilesql || sudo rpm -e vilesql ;;
    "homebrew") brew uninstall vilesql ;;
    "manual") sudo rm -f "$(which vilesql)" ;;
    *) log "⚠️ Unknown installation method! Please remove manually."; exit 1 ;;
esac

# Remove VileSQL user/group if no files are owned
if id "$USER" &>/dev/null; then
    if [[ -z "$(find / -user $USER -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null)" ]]; then
        log "👤 Removing VileSQL user..."
        userdel -r "$USER" || true
    else
        log "🛑 VileSQL user owns files, not removing."
    fi
fi

# Offer to remove data directories
echo "📂 Data directories found:"
echo "  - $DATA_DIR"
echo "  - $CONFIG_FILE"
echo "  - $LOG_DIR"
echo "  - $LOG_FILE"
read -p "Remove all data directories? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log "🗑️ Removing data directories..."
    sudo rm -rf "$DATA_DIR" "$CONFIG_FILE" "$LOG_DIR" "$LOG_FILE"
    log "✅ Data directories removed."
else
    log "📂 Data directories preserved."
fi

log "✅ VileSQL uninstallation completed successfully!"

echo ""
echo "🚀 VileSQL has been successfully removed."
echo "⚠️ If any commands still exist, restart your shell or manually clean up PATH."
echo ""
