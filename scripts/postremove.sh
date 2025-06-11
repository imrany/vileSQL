#!/bin/bash

# scripts/postremove.sh - Post-removal script
set -e

VILESQL_USER="vilesql"
VILESQL_GROUP="vilesql"
SYSTEMD_SERVICE="/etc/systemd/system/vilesql.service"
LOGROTATE_CONFIG="/etc/logrotate.d/vilesql"

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

# Remove log rotation config
if [ -f "$LOGROTATE_CONFIG" ]; then
    log "Removing log rotation configuration"
    rm -f "$LOGROTATE_CONFIG"
fi

# Remove user and group (only if no files are owned by them)
if getent passwd "$VILESQL_USER" > /dev/null 2>&1; then
    if [ -z "$(find / -user "$VILESQL_USER" -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null)" ]; then
        log "Removing user: $VILESQL_USER"
        userdel "$VILESQL_USER" 2>/dev/null || true
    else
        log "User $VILESQL_USER still owns files, not removing"
    fi
fi

if getent group "$VILESQL_GROUP" > /dev/null 2>&1; then
    log "Removing group: $VILESQL_GROUP"
    groupdel "$VILESQL_GROUP" 2>/dev/null || true
fi

log "Post-removal script completed"

echo "VileSQL has been removed."
echo "Note: Data directories were preserved."
echo "To completely remove all data, run: rm -rf /var/lib/vilesql /etc/vilesql"