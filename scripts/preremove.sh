#!/bin/bash
# VileSQL Pre-Removal Script

set -e

USER="vilesql"
GROUP="vilesql"
SYSTEMD_SERVICE="/etc/systemd/system/vilesql.service"
DATA_DIR="/var/lib/vilesql"
CONFIG_DIR="$DATA_DIR"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log "🚀 Starting VileSQL pre-removal script"

# Ensure running as root
if [[ "$EUID" -ne 0 ]]; then
    echo "❌ This script must be run as root!"
    exit 1
fi

# Stop service if running
if systemctl is-active --quiet vilesql; then
    log "🔴 Stopping VileSQL service..."
    systemctl stop vilesql
fi

# Disable service
if systemctl is-enabled --quiet vilesql; then
    log "⚙️ Disabling VileSQL service..."
    systemctl disable vilesql
fi

# Remove vilesql user if it exists
if id "$USER" &>/dev/null; then
    log "👤 Removing VileSQL system user..."
    userdel -r "$USER"
fi

log "✅ Pre-removal script completed!"

echo ""
echo "🚀 VileSQL service has been disabled and stopped!"
echo "📌 Note: Data directories were **preserved**."
echo "To **completely remove** all data, run:"
echo "  sudo rm -rf $DATA_DIR $CONFIG_DIR"
echo ""
