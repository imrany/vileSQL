#!/bin/bash

# VileSQL Post-Removal Script
set -e

SYSTEMD_SERVICE="/etc/systemd/system/vilesql.service"
DATA_DIR="/var/lib/vilesql"
USER="vilesql"
GROUP="vilesql"
LOG_DIR="/var/log/vilesql"
LOG_FILE="$LOG_DIR/vilesql.log"
RUNTIME_LOG_FILE="/var/log/vilesql.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log "🚀 Starting VileSQL post-removal script"

# Stop and disable the service if running
if systemctl is-active --quiet vilesql; then
    log "🔴 Stopping VileSQL service..."
    systemctl stop vilesql
fi

if systemctl is-enabled --quiet vilesql; then
    log "⚙️ Disabling VileSQL service..."
    systemctl disable vilesql
fi

# Remove systemd service file
if [[ -f "$SYSTEMD_SERVICE" ]]; then
    log "🗑️ Removing systemd service file..."
    rm -f "$SYSTEMD_SERVICE"
    systemctl daemon-reload
fi

# Remove vilesql user if it exists
if id "$USER" &>/dev/null; then
    log "👤 Removing VileSQL system user..."
    userdel -r "$USER"
fi

log "✅ Post-removal script completed"

echo ""
echo "🚀 VileSQL has been removed!"
echo "📌 Note: Data directories were preserved."
echo "To **completely remove** all data, run:"
echo "  sudo rm -rf $DATA_DIR $LOG_DIR $RUNTIME_LOG_FILE"
echo ""
