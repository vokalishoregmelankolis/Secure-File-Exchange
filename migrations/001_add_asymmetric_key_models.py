"""
Database migration script for asymmetric key exchange feature.

This migration adds:
1. UserRole enum and related columns to users table
2. AccessRequest table for tracking access requests
3. CryptoLog table for logging cryptographic operations

Run this script to upgrade the database schema.
"""

from app import create_app, db
from app.models import User, AccessRequest, CryptoLog, UserRole
import sys


def upgrade():
    """Apply the migration"""
    app = create_app()
    
    with app.app_context():
        print("Starting database migration...")
        
        try:
            # Create all new tables
            print("Creating new tables (access_requests, crypto_logs)...")
            db.create_all()
            
            # Note: SQLite doesn't support ALTER TABLE ADD COLUMN for existing tables easily
            # The new columns (role, public_key, public_key_fingerprint, key_generated_at)
            # will be added when db.create_all() is called if the table doesn't exist.
            # For existing databases, you may need to:
            # 1. Export data
            # 2. Drop and recreate the users table
            # 3. Re-import data
            # Or use a proper migration tool like Alembic
            
            print("Migration completed successfully!")
            print("\nNOTE: If you have an existing users table, you may need to manually add columns:")
            print("  - role (VARCHAR with default 'organization')")
            print("  - public_key (BLOB)")
            print("  - public_key_fingerprint (VARCHAR(64))")
            print("  - key_generated_at (DATETIME)")
            
        except Exception as e:
            print(f"Migration failed: {e}")
            sys.exit(1)


def downgrade():
    """Rollback the migration"""
    app = create_app()
    
    with app.app_context():
        print("Rolling back database migration...")
        
        try:
            # Drop new tables
            print("Dropping tables (access_requests, crypto_logs)...")
            db.session.execute(db.text("DROP TABLE IF EXISTS access_requests"))
            db.session.execute(db.text("DROP TABLE IF EXISTS crypto_logs"))
            db.session.commit()
            
            print("Rollback completed successfully!")
            print("\nNOTE: User table columns (role, public_key, etc.) were not removed.")
            print("You may need to manually remove them if needed.")
            
        except Exception as e:
            print(f"Rollback failed: {e}")
            db.session.rollback()
            sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'downgrade':
        downgrade()
    else:
        upgrade()
