#!/bin/bash

# Create system-wide data directory
mkdir -p /var/lib/vilesql
chmod 755 /var/lib/vilesql

# Create symlink for easy access
ln -sf /var/lib/vilesql /usr/share/vilesql/data

echo "VileSQL data directory created at /var/lib/vilesql"