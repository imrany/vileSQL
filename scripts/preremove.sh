#!/bin/bash
# VileSQL Pre-Removal Script

set -e

USER="vilesql"
GROUP="vilesql"
SYSTEMD_SERVICE="/etc/systemd/system/vilesql.service"
DATA_DIR="/var/lib/vilesql"
CONFIG_FILE="$DATA_DIR/.env"
LOG_DIR="/var/log/vilesql"
LOG_FILE="$LOG_DIR/vilesql.log"
RUNTIME_LOG_FILE="/var/log/vilesql.log"

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

# Kill all running VileSQL processes
log "🛑 Stopping all active VileSQL instances..."
pkill -u "$USER" || log "⚠️ No active processes found for $USER"

# Ensure processes are fully terminated
sleep 2
if pgrep -u "$USER" > /dev/null; then
    log "❌ Failed to terminate all VileSQL processes! Retrying..."
    pkill -9 -u "$USER"
fi

# Remove vilesql user if it exists
if id "$USER" &>/dev/null; then
    log "👤 Removing VileSQL system user..."
    userdel -r "$USER" || log "⚠️ User removal failed—check active processes!"
fi

log "✅ Pre-removal script completed!"

echo ""
echo "🚀 VileSQL service has been disabled and stopped!"
echo "📌 Note: Data directories were **preserved**."
echo "To **completely remove** all data, run:"
echo "  sudo rm -rf $DATA_DIR $CONFIG_FILE $LOG_DIR $RUNTIME_LOG_FILE"
echo ""
