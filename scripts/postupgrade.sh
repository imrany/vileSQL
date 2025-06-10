#!/bin/bash
# scripts/postupgrade.sh - Post-upgrade script for package managers

set -e

VILESQL_USER="vilesql"
VILESQL_GROUP="vilesql"
DATA_DIR="/var/lib/vilesql"
CONFIG_DIR="/etc/vilesql"
LOG_FILE="/var/log/vilesql-upgrade.log"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log "Starting VileSQL post-upgrade script"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Create log file if it doesn't exist
touch "$LOG_FILE"
chmod 644 "$LOG_FILE"

# Create vilesql user and group if they don't exist
if ! getent group "$VILESQL_GROUP" > /dev/null 2>&1; then
    log "Creating group: $VILESQL_GROUP"
    groupadd -r "$VILESQL_GROUP"
fi

if ! getent passwd "$VILESQL_USER" > /dev/null 2>&1; then
    log "Creating user: $VILESQL_USER"
    useradd -r -g "$VILESQL_GROUP" -d "$DATA_DIR" -s /bin/false "$VILESQL_USER"
fi

# Create directories if they don't exist
for dir in "$DATA_DIR" "$CONFIG_DIR"; do
    if [ ! -d "$dir" ]; then
        log "Creating directory: $dir"
        mkdir -p "$dir"
    fi
done

# Set proper ownership and permissions
chown -R "$VILESQL_USER:$VILESQL_GROUP" "$DATA_DIR"
chown -R "$VILESQL_USER:$VILESQL_GROUP" "$CONFIG_DIR"
chmod 755 "$DATA_DIR"
chmod 755 "$CONFIG_DIR"

# Run migrations if vilesql is installed
if command -v vilesql > /dev/null 2>&1; then
    log "Running data migrations"
    # Run as vilesql user
    su - "$VILESQL_USER" -s /bin/bash -c "vilesql migrate" || {
        log "Migration failed, but continuing with upgrade"
    }
else
    log "vilesql command not found, skipping migrations"
fi

# Restart service if it exists and is running
if systemctl is-active --quiet vilesql; then
    log "Restarting vilesql service"
    systemctl restart vilesql
elif systemctl is-enabled --quiet vilesql; then
    log "Starting vilesql service"
    systemctl start vilesql
fi

# Create systemd service file if it doesn't exist
SYSTEMD_SERVICE="/etc/systemd/system/vilesql.service"
if [ ! -f "$SYSTEMD_SERVICE" ]; then
    log "Creating systemd service file"
    cat > "$SYSTEMD_SERVICE" << 'EOF'
[Unit]
Description=VileSQL Database Management Service
After=network.target

[Service]
Type=simple
User=vilesql
Group=vilesql
WorkingDirectory=/var/lib/vilesql
ExecStart=/usr/bin/vilesql --host=127.0.0.1 --port=5000
Restart=always
RestartSec=10
Environment=VILESQL_DATA_DIR=/var/lib/vilesql

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/vilesql

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable vilesql
fi

# Set up log rotation
LOGROTATE_CONFIG="/etc/logrotate.d/vilesql"
if [ ! -f "$LOGROTATE_CONFIG" ]; then
    log "Setting up log rotation"
    cat > "$LOGROTATE_CONFIG" << 'EOF'
/var/log/vilesql*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 vilesql vilesql
    postrotate
        systemctl reload vilesql > /dev/null 2>&1 || true
    endscript
}
EOF
fi

log "Post-upgrade script completed successfully"

echo "VileSQL has been successfully upgraded!"
echo "You can start using it with: systemctl start vilesql"
echo "Or check the status with: systemctl status vilesql"
echo "Logs are available at: $LOG_FILE"
