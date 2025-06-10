#!/bin/bash

# scripts/preremove.sh - Pre-removal script
set -e

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log "Starting VileSQL pre-removal script"

# Stop service if running
if systemctl is-active --quiet vilesql; then
    log "Stopping vilesql service"
    systemctl stop vilesql
fi

# Disable service
if systemctl is-enabled --quiet vilesql; then
    log "Disabling vilesql service"
    systemctl disable vilesql
fi

log "Pre-removal script completed"
