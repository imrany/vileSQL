#!/bin/bash

# scripts/postremove.sh - Post-removal script
set -e

SYSTEMD_SERVICE="/etc/systemd/system/vilesql.service"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log "Starting VileSQL post-removal script"

# Remove systemd service file
if [ -f "$SYSTEMD_SERVICE" ]; then
    log "Removing systemd service file"
    rm -f "$SYSTEMD_SERVICE"
    systemctl daemon-reload
fi

log "Post-removal script completed"

echo "VileSQL has been removed."
echo "Note: Data directories were preserved."
echo "To completely remove all data, run: rm -rf /var/lib/vilesql /etc/vilesql"