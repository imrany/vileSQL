#!/bin/bash
# VileSQL Post-Upgrade Script for Package Managers

set -e

DATA_DIR="/var/lib/vilesql"
CONFIG_DIR="$DATA_DIR"
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
for dir in "$DATA_DIR" "$CONFIG_DIR"; do
    if [[ ! -d "$dir" ]]; then
        log "📁 Creating directory: $dir"
        mkdir -p "$dir"
    fi
    chown "$USER:$GROUP" "$dir"
done

# Set secure permissions
chmod 755 "$DATA_DIR"
chmod 700 "$CONFIG_DIR"

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
ExecStart=/usr/bin/vilesql --host=0.0.0.0 --port=5000
ExecReload=/bin/kill -USR2 $MAINPID
Restart=always
RestartSec=5
TimeoutStartSec=30
TimeoutStopSec=30
KillMode=mixed
KillSignal=SIGTERM

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
LimitMEMLOCK=64M

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

log "✅ Post-upgrade script completed successfully!"

echo ""
echo "🚀 VileSQL has been successfully upgraded!"
echo "📁 Data directory: $DATA_DIR"
echo "⚙️ Configuration file: $CONFIG_DIR/.env"
echo ""
echo "🔄 To start the service: sudo systemctl start vilesql"
echo "📌 To check status: sudo systemctl status vilesql"
echo ""
