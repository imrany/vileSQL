#!/bin/bash

# VileSQL Post-Installation Script
set -e

DATA_DIR="/var/lib/vilesql"
CONFIG_DIR="/etc/vilesql"
LOG_DIR="/var/log/vilesql"
LOG_FILE="/var/log/vilesql-install.log"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log "Starting VileSQL post-installation script"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Create directories
for dir in "$DATA_DIR" "$CONFIG_DIR" "$LOG_DIR"; do
    if [ ! -d "$dir" ]; then
        log "Creating directory: $dir"
        mkdir -p "$dir"
    fi
done

# Set permissions (readable/writable by all users)
chmod 755 "$DATA_DIR"
chmod 755 "$CONFIG_DIR"
chmod 755 "$LOG_DIR"

# Create default config if it doesn't exist
if [ ! -f "$CONFIG_DIR/.env" ] && [ -f "$CONFIG_DIR/.env.example" ]; then
    log "Creating default configuration"
    cp "$CONFIG_DIR/.env.example" "$CONFIG_DIR/.env"
    chmod 644 "$CONFIG_DIR/.env"
fi

# Enable and start systemd service (if systemd is available)
if command -v systemctl >/dev/null 2>&1; then
    log "Enabling systemd service"
    systemctl daemon-reload
    systemctl enable vilesql.service || log "Failed to enable service"
    
    # Don't auto-start the service - let user do it manually
    log "Service enabled. Start with: systemctl start vilesql"
else
    log "Systemd not available, skipping service setup"
fi

log "Post-installation script completed successfully"

echo ""
echo "✅ VileSQL has been successfully installed!"
echo ""
echo "📁 Data directory: $DATA_DIR"
echo "⚙️  Configuration: $CONFIG_DIR/.env"
echo "📝 Logs: $LOG_DIR"
echo ""
echo "🚀 Next steps:"
echo "   1. Edit configuration: sudo nano $CONFIG_DIR/.env"
echo "   2. Start the service: sudo systemctl start vilesql"
echo "   3. Check status: sudo systemctl status vilesql"
echo "   4. Or run directly: vilesql --help"
echo ""