"""
SQLite-compatible database migration script.

This script handles the migration for existing databases by:
1. Creating new tables (access_requests, crypto_logs)
2. Adding new columns to users table using SQLite's limited ALTER TABLE support
"""

import sqlite3
import os
import sys
from datetime import datetime


def get_db_path():
    """Get the database path"""
    # Try to find the database in the instance folder
    db_path = os.path.join('instance', 'secure_file_exchange.db')
    if os.path.exists(db_path):
        return db_path
    
    # Alternative path
    db_path = 'secure_file_exchange.db'
    if os.path.exists(db_path):
        return db_path
    
    print("Database not found. Please specify the path.")
    sys.exit(1)


def backup_database(db_path):
    """Create a backup of the database"""
    backup_path = f"{db_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    try:
        import shutil
        shutil.copy2(db_path, backup_path)
        print(f"Database backed up to: {backup_path}")
        return backup_path
    except Exception as e:
        print(f"Failed to create backup: {e}")
        sys.exit(1)


def migrate_users_table(conn):
    """Add new columns to users table"""
    cursor = conn.cursor()
    
    # Check if columns already exist
    cursor.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in cursor.fetchall()]
    
    # Add role column
    if 'role' not in columns:
        print("Adding 'role' column to users table...")
        cursor.execute("ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'organization'")
    
    # Add public_key column
    if 'public_key' not in columns:
        print("Adding 'public_key' column to users table...")
        cursor.execute("ALTER TABLE users ADD COLUMN public_key BLOB")
    
    # Add public_key_fingerprint column
    if 'public_key_fingerprint' not in columns:
        print("Adding 'public_key_fingerprint' column to users table...")
        cursor.execute("ALTER TABLE users ADD COLUMN public_key_fingerprint VARCHAR(64)")
    
    # Add key_generated_at column
    if 'key_generated_at' not in columns:
        print("Adding 'key_generated_at' column to users table...")
        cursor.execute("ALTER TABLE users ADD COLUMN key_generated_at DATETIME")
    
    conn.commit()


def create_access_requests_table(conn):
    """Create access_requests table"""
    cursor = conn.cursor()
    
    # Check if table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='access_requests'")
    if cursor.fetchone():
        print("access_requests table already exists, skipping...")
        return
    
    print("Creating access_requests table...")
    cursor.execute("""
        CREATE TABLE access_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            consultant_id INTEGER NOT NULL,
            organization_id INTEGER NOT NULL,
            file_id INTEGER NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'pending',
            wrapped_symmetric_key BLOB,
            requested_at DATETIME NOT NULL,
            processed_at DATETIME,
            FOREIGN KEY (consultant_id) REFERENCES users(id),
            FOREIGN KEY (organization_id) REFERENCES users(id),
            FOREIGN KEY (file_id) REFERENCES encrypted_files(id),
            UNIQUE(consultant_id, file_id)
        )
    """)
    conn.commit()


def create_crypto_logs_table(conn):
    """Create crypto_logs table"""
    cursor = conn.cursor()
    
    # Check if table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='crypto_logs'")
    if cursor.fetchone():
        print("crypto_logs table already exists, skipping...")
        return
    
    print("Creating crypto_logs table...")
    cursor.execute("""
        CREATE TABLE crypto_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            operation VARCHAR(50) NOT NULL,
            details TEXT,
            success BOOLEAN DEFAULT 1,
            error_message TEXT,
            timestamp DATETIME NOT NULL,
            ip_address VARCHAR(45),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.commit()


def upgrade():
    """Run the migration"""
    print("=" * 60)
    print("Database Migration: Asymmetric Key Exchange Feature")
    print("=" * 60)
    
    db_path = get_db_path()
    print(f"\nDatabase: {db_path}")
    
    # Create backup
    backup_path = backup_database(db_path)
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        
        # Run migrations
        migrate_users_table(conn)
        create_access_requests_table(conn)
        create_crypto_logs_table(conn)
        
        # Close connection
        conn.close()
        
        print("\n" + "=" * 60)
        print("Migration completed successfully!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\nMigration failed: {e}")
        print(f"Database backup is available at: {backup_path}")
        sys.exit(1)


def downgrade():
    """Rollback the migration"""
    print("=" * 60)
    print("Database Rollback: Asymmetric Key Exchange Feature")
    print("=" * 60)
    
    db_path = get_db_path()
    print(f"\nDatabase: {db_path}")
    
    # Create backup
    backup_path = backup_database(db_path)
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Drop new tables
        print("Dropping access_requests table...")
        cursor.execute("DROP TABLE IF EXISTS access_requests")
        
        print("Dropping crypto_logs table...")
        cursor.execute("DROP TABLE IF EXISTS crypto_logs")
        
        conn.commit()
        conn.close()
        
        print("\n" + "=" * 60)
        print("Rollback completed successfully!")
        print("=" * 60)
        print("\nNOTE: User table columns were not removed (SQLite limitation).")
        print("Columns: role, public_key, public_key_fingerprint, key_generated_at")
        
    except Exception as e:
        print(f"\nRollback failed: {e}")
        print(f"Database backup is available at: {backup_path}")
        sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'downgrade':
        downgrade()
    else:
        upgrade()
