#!/bin/bash
# Helper script to run the user key migration

echo "=========================================="
echo "User Key Migration Helper"
echo "=========================================="
echo ""

# Check if dry-run flag is provided
if [ "$1" == "--dry-run" ]; then
    echo "Running in DRY RUN mode (no changes will be made)"
    echo ""
    python migrations/002_migrate_existing_users_keys.py --dry-run
else
    echo "⚠️  WARNING: This will modify your database!"
    echo ""
    echo "A backup will be created automatically, but please ensure you have"
    echo "additional backups before proceeding."
    echo ""
    read -p "Do you want to continue? (yes/no): " confirm
    
    if [ "$confirm" == "yes" ]; then
        echo ""
        echo "Starting migration..."
        python migrations/002_migrate_existing_users_keys.py
    else
        echo "Migration cancelled."
        exit 0
    fi
fi
