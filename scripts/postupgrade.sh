#!/bin/bash
# VileSQL Post-Upgrade Script for Package Managers

set -e

DATA_DIR="/var/lib/vilesql"
CONFIG_FILE="$DATA_DIR/.env"
SYSTEMD_SERVICE="/etc/systemd/system/vilesql.service"
USER="vilesql"
GROUP="vilesql"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log "🚀 Starting VileSQL post-upgrade script"

# Ensure running as root
if [[ "$EUID" -ne 0 ]]; then
    echo "❌ This script must be run as root!"
    exit 1
fi

# Create directories if missing
for dir in "$DATA_DIR"; do
    if [[ ! -d "$dir" ]]; then
        log "📁 Creating directory: $dir"
        mkdir -p "$dir"
    fi
    chown "$USER:$GROUP" "$dir"
done

# Set secure permissions
chmod 755 "$DATA_DIR"
chmod 755 "$CONFIG_FILE"

# Run database migrations if vilesql is installed
if command -v vilesql &>/dev/null; then
    log "⚙️ Running database migrations..."
    sudo -u "$USER" vilesql migrate || {
        log "⚠️ Migration failed, continuing upgrade..."
    }
else
    log "🔍 vilesql command not found, skipping migrations."
fi

# Restart service if active
if systemctl is-active --quiet vilesql; then
    log "🔄 Restarting VileSQL service..."
    systemctl restart vilesql
elif systemctl is-enabled --quiet vilesql; then
    log "⚙️ Starting VileSQL service..."
    systemctl start vilesql
fi

# Ensure systemd service file exists
if [[ ! -f "$SYSTEMD_SERVICE" ]]; then
    log "⚙️ Creating missing systemd service file..."
    cat > "$SYSTEMD_SERVICE" << 'EOF'
[Unit]
Description=VileSQL Database Management Service
Documentation=https://github.com/imrany/vilesql
After=network.target network-online.target
Wants=network-online.target
RequiresMountsFor=/var/lib/vilesql

[Service]
Type=simple
User=vilesql
Group=vilesql
WorkingDirectory=/var/lib/vilesql

# Load environment variables before executing VileSQL
EnvironmentFile=/var/lib/vilesql/.env
ExecStart=/bin/bash -c 'source /var/lib/vilesql/.env && exec /usr/bin/vilesql --host=$HOST --port=5000'
ExecReload=/bin/kill -USR2 $MAINPID

Restart=always
RestartSec=5
TimeoutStartSec=30
TimeoutStopSec=30
KillMode=process

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictRealtime=yes
SystemCallArchitectures=native

# Allow VileSQL write access to its working directory
ReadWritePaths=/var/lib/vilesql

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096
LimitMEMLOCK=64M

# Logging (redirect to file)
StandardOutput=append:/var/log/vilesql.log
StandardError=append:/var/log/vilesql.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable vilesql
fi

log "✅ Post-upgrade script completed successfully!"

echo ""
echo "🚀 VileSQL has been successfully upgraded!"
echo "📁 Data directory: $DATA_DIR"
echo "⚙️ Configuration file: $CONFIG_FILE"
echo ""
echo "🔄 To start the service: sudo systemctl start vilesql"
echo "📌 To check status: sudo systemctl status vilesql"
echo ""
