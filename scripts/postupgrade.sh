#!/bin/bash
# scripts/postupgrade.sh - Post-upgrade script for package managers

set -e

DATA_DIR="/var/lib/vilesql"
CONFIG_DIR="/etc/vilesql"

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


# Create directories if they don't exist
for dir in "$DATA_DIR" "$CONFIG_DIR"; do
    if [ ! -d "$dir" ]; then
        log "Creating directory: $dir"
        mkdir -p "$dir"
    fi
done

# Set proper ownership and permissions
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
Documentation=https://github.com/imrany/vilesql
After=network.target network-online.target
Wants=network-online.target
RequiresMountsFor=/var/lib/vilesql

[Service]
Type=simple
WorkingDirectory=/var/lib/vilesql
ExecStart=/usr/bin/vilesql --host=0.0.0.0 --port=5000 --config=/etc/vilesql/.env
ExecReload=/bin/kill -USR2 $MAINPID
Restart=always
RestartSec=5
TimeoutStartSec=30
TimeoutStopSec=30
KillMode=mixed
KillSignal=SIGTERM

# Environment
Environment=VILESQL_DATA_DIR=/var/lib/vilesql
Environment=VILESQL_CONFIG_DIR=/etc/vilesql

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RemoveIPC=yes
SystemCallArchitectures=native

# File system permissions
ReadWritePaths=/var/lib/vilesql
ReadOnlyPaths=/etc/vilesql

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096
LimitMEMLOCK=51200

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vilesql

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable vilesql
fi


log "Post-upgrade script completed successfully"

echo "VileSQL has been successfully upgraded!"
echo "You can start using it with: systemctl start vilesql"
echo "Or check the status with: systemctl status vilesql"
