#!/bin/bash
# VileSQL Post-Installation Script

set -e

DATA_DIR="/var/lib/vilesql"
CONFIG_DIR="/etc/vilesql"
LOG_DIR="/var/log/vilesql"
LOG_FILE="$LOG_DIR/vilesql.log"
BIN_PATH="/usr/bin/vilesql"
SERVICE_PATH="/etc/systemd/system/vilesql.service"
USER="vilesql"
GROUP="vilesql"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log "🚀 Starting VileSQL post-installation script"

# Ensure running as root
if [[ "$EUID" -ne 0 ]]; then
    echo "❌ This script must be run as root!"
    exit 1
fi

# Create vilesql system user and group (if not exists)
if ! id "$USER" &>/dev/null; then
    log "📌 Creating system user: $USER"
    useradd -r -s /bin/false -d "$DATA_DIR" "$USER"
fi

# Create necessary directories with correct ownership
for dir in "$DATA_DIR" "$CONFIG_DIR" "$LOG_DIR"; do
    if [[ ! -d "$dir" ]]; then
        log "📁 Creating directory: $dir"
        mkdir -p "$dir"
    fi
    chown "$USER:$GROUP" "$dir"
done

# Ensure log file exists
if [[ ! -f "$LOG_FILE" ]]; then
    log "📝 Creating log file: $LOG_FILE"
    touch "$LOG_FILE"
    chown "$USER:$GROUP" "$LOG_FILE"
    chmod 644 "$LOG_FILE"
fi

# Set secure permissions
chmod 755 "$DATA_DIR"
chmod 700 "$CONFIG_DIR" # Restrict config access
chmod 755 "$LOG_DIR" # Ensure log directory is accessible
chmod 644 "$LOG_FILE" # Ensure log file is readable

# Ensure binary exists
if [[ ! -x "$BIN_PATH" ]]; then
    log "❌ VileSQL binary not found at $BIN_PATH"
    exit 1
fi

# Install systemd service file (if missing)
if [[ ! -f "$SERVICE_PATH" ]]; then
    log "⚙️ Installing systemd service file"
    cp scripts/vilesql.service "$SERVICE_PATH"
    chmod 644 "$SERVICE_PATH"
    systemctl daemon-reload
fi

# Enable service
log "🔄 Enabling VileSQL service..."
systemctl enable vilesql.service || log "⚠️ Warning: Failed to enable service."

# Prompt user to start service immediately
read -p "▶️ Start VileSQL now? (y/n): " choice
if [[ "$choice" == "y" ]]; then
    systemctl start vilesql
    log "✅ VileSQL service started!"
else
    log "⚠️ You can start it manually using: sudo systemctl start vilesql"
fi

log "✅ VileSQL installation completed successfully!"

echo ""
echo "📁 Data directory: $DATA_DIR"
echo "⚙️ Configuration: $CONFIG_DIR/.env"
echo "📄 Log file: $LOG_FILE"
echo ""
echo "🚀 Next steps:"
echo "   1️⃣ Edit config: sudo nano $CONFIG_DIR/.env"
echo "   2️⃣ Check status: sudo systemctl status vilesql"
echo "   3️⃣ View logs: sudo tail -f $LOG_FILE"
echo "   4️⃣ Run manually: vilesql --help"
echo ""
