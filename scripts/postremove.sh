#!/bin/bash

# Post-removal script
echo "VileSQL has been removed."
echo ""
echo "Data directories preserved:"
echo "  - /var/lib/vilesql (system data)"
echo "  - ~/.vilesql (user data)"
echo ""
echo "To completely remove all data:"
echo "  sudo rm -rf /var/lib/vilesql /etc/vilesql"
echo "  rm -rf ~/.vilesql"