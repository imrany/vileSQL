#!/bin/bash

# scripts/postinstall.sh - Post-installation script
set -e

VILESQL_USER="vilesql"
VILESQL_GROUP="vilesql"
DATA_DIR="/var/lib/vilesql"
CONFIG_DIR="/etc/vilesql"
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

# Create log file
touch "$LOG_FILE"
chmod 644 "$LOG_FILE"

# Create vilesql user and group
if ! getent group "$VILESQL_GROUP" > /dev/null 2>&1; then
    log "Creating group: $VILESQL_GROUP"
    groupadd -r "$VILESQL_GROUP"
fi

if ! getent passwd "$VILESQL_USER" > /dev/null 2>&1; then
    log "Creating user: $VILESQL_USER"
    useradd -r -g "$VILESQL_GROUP" -d "$DATA_DIR" -s /bin/false "$VILESQL_USER"
fi

# Create directories
for dir in "$DATA_DIR" "$CONFIG_DIR"; do
    if [ ! -d "$dir" ]; then
        log "Creating directory: $dir"
        mkdir -p "$dir"
    fi
done

# Set ownership and permissions
chown -R "$VILESQL_USER:$VILESQL_GROUP" "$DATA_DIR"
chown -R "$VILESQL_USER:$VILESQL_GROUP" "$CONFIG_DIR"
chmod 755 "$DATA_DIR"
chmod 755 "$CONFIG_DIR"

# Initialize data directory
log "Initializing data directory"
su - "$VILESQL_USER" -s /bin/bash -c "vilesql migrate" || {
    log "Initial migration failed, but continuing"
}

log "Post-installation script completed successfully"

echo "VileSQL has been successfully installed!"
echo "Data directory: $DATA_DIR"
echo "Configuration: $CONFIG_DIR"
echo "Run 'vilesql --help' to see available commands"