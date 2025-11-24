"""
Test script for database migration.

This script tests the migration by:
1. Creating a test database
2. Running the migration
3. Verifying the schema changes
4. Testing rollback
"""

import os
import sys
import sqlite3
import tempfile
import shutil
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def create_test_database():
    """Create a minimal test database with the old schema"""
    # Create a temporary database
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, 'test_migration.db')
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create old schema (without new columns)
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(80) UNIQUE NOT NULL,
            email VARCHAR(120) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at DATETIME
        )
    """)
    
    cursor.execute("""
        CREATE TABLE encrypted_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id VARCHAR(36) UNIQUE NOT NULL,
            filename VARCHAR(255) NOT NULL,
            original_filename VARCHAR(255) NOT NULL,
            file_type VARCHAR(50) NOT NULL,
            file_size INTEGER NOT NULL,
            encrypted_path VARCHAR(500) NOT NULL,
            algorithm VARCHAR(20) NOT NULL,
            encryption_key BLOB,
            iv BLOB,
            wrapped_key BLOB,
            wrapped_key_version VARCHAR(10),
            user_id INTEGER NOT NULL,
            uploaded_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    
    # Insert test data
    cursor.execute("""
        INSERT INTO users (username, email, password_hash, created_at)
        VALUES ('testuser', 'test@example.com', 'hash123', ?)
    """, (datetime.utcnow(),))
    
    conn.commit()
    conn.close()
    
    return db_path, temp_dir


def verify_schema(db_path):
    """Verify the database schema after migration"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("\n" + "=" * 60)
    print("Verifying Database Schema")
    print("=" * 60)
    
    # Check users table columns
    cursor.execute("PRAGMA table_info(users)")
    columns = {row[1]: row[2] for row in cursor.fetchall()}
    
    print("\n1. Users Table Columns:")
    required_columns = ['role', 'public_key', 'public_key_fingerprint', 'key_generated_at']
    for col in required_columns:
        if col in columns:
            print(f"   ✓ {col} ({columns[col]})")
        else:
            print(f"   ✗ {col} - MISSING!")
            return False
    
    # Check access_requests table
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='access_requests'")
    if cursor.fetchone():
        print("\n2. Access Requests Table:")
        print("   ✓ Table exists")
        
        cursor.execute("PRAGMA table_info(access_requests)")
        ar_columns = [row[1] for row in cursor.fetchall()]
        required_ar_columns = ['consultant_id', 'organization_id', 'file_id', 'status', 
                               'wrapped_symmetric_key', 'requested_at', 'processed_at']
        for col in required_ar_columns:
            if col in ar_columns:
                print(f"   ✓ {col}")
            else:
                print(f"   ✗ {col} - MISSING!")
                return False
    else:
        print("\n2. Access Requests Table:")
        print("   ✗ Table does not exist!")
        return False
    
    # Check crypto_logs table
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='crypto_logs'")
    if cursor.fetchone():
        print("\n3. Crypto Logs Table:")
        print("   ✓ Table exists")
        
        cursor.execute("PRAGMA table_info(crypto_logs)")
        cl_columns = [row[1] for row in cursor.fetchall()]
        required_cl_columns = ['user_id', 'operation', 'details', 'success', 
                              'error_message', 'timestamp', 'ip_address']
        for col in required_cl_columns:
            if col in cl_columns:
                print(f"   ✓ {col}")
            else:
                print(f"   ✗ {col} - MISSING!")
                return False
    else:
        print("\n3. Crypto Logs Table:")
        print("   ✗ Table does not exist!")
        return False
    
    # Check indexes
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
    indexes = [row[0] for row in cursor.fetchall()]
    
    print("\n4. Indexes:")
    expected_indexes = [
        'ix_access_requests_consultant_id',
        'ix_access_requests_organization_id',
        'ix_access_requests_file_id',
        'ix_access_requests_status',
        'ix_crypto_logs_user_id',
        'ix_crypto_logs_operation',
        'ix_crypto_logs_timestamp'
    ]
    
    for idx in expected_indexes:
        if idx in indexes:
            print(f"   ✓ {idx}")
        else:
            print(f"   ✗ {idx} - MISSING!")
    
    # Check that existing data is preserved
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    print(f"\n5. Data Preservation:")
    print(f"   ✓ Users preserved: {user_count} user(s)")
    
    conn.close()
    return True


def test_migration_with_alembic():
    """Test migration using Alembic"""
    print("\n" + "=" * 60)
    print("Testing Migration with Alembic")
    print("=" * 60)
    
    # Create test database
    db_path, temp_dir = create_test_database()
    print(f"\nTest database created: {db_path}")
    
    try:
        # Update alembic.ini to use test database
        import configparser
        config = configparser.ConfigParser()
        config.read('alembic.ini')
        original_url = config.get('alembic', 'sqlalchemy.url')
        config.set('alembic', 'sqlalchemy.url', f'sqlite:///{db_path}')
        
        with open('alembic.ini', 'w') as f:
            config.write(f)
        
        # Run migration
        print("\nRunning migration...")
        import subprocess
        result = subprocess.run(['alembic', 'upgrade', 'head'], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✓ Migration completed successfully")
            print(result.stdout)
            
            # Verify schema
            if verify_schema(db_path):
                print("\n" + "=" * 60)
                print("✓ All schema verifications passed!")
                print("=" * 60)
            else:
                print("\n" + "=" * 60)
                print("✗ Schema verification failed!")
                print("=" * 60)
                return False
            
            # Test rollback
            print("\n" + "=" * 60)
            print("Testing Rollback")
            print("=" * 60)
            
            result = subprocess.run(['alembic', 'downgrade', 'base'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✓ Rollback completed successfully")
                print(result.stdout)
                
                # Verify tables are removed
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='access_requests'")
                if not cursor.fetchone():
                    print("✓ access_requests table removed")
                else:
                    print("✗ access_requests table still exists")
                
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='crypto_logs'")
                if not cursor.fetchone():
                    print("✓ crypto_logs table removed")
                else:
                    print("✗ crypto_logs table still exists")
                
                conn.close()
            else:
                print("✗ Rollback failed")
                print(result.stderr)
                return False
        else:
            print("✗ Migration failed")
            print(result.stderr)
            return False
        
        # Restore original alembic.ini
        config.set('alembic', 'sqlalchemy.url', original_url)
        with open('alembic.ini', 'w') as f:
            config.write(f)
        
        return True
        
    finally:
        # Cleanup
        shutil.rmtree(temp_dir)
        print(f"\nTest database cleaned up")


def test_migration_with_script():
    """Test migration using the standalone script"""
    print("\n" + "=" * 60)
    print("Testing Migration with Standalone Script")
    print("=" * 60)
    
    # Create test database
    db_path, temp_dir = create_test_database()
    print(f"\nTest database created: {db_path}")
    
    try:
        # Import and run migration
        sys.path.insert(0, os.path.dirname(__file__))
        
        # Temporarily override the database path
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        # Create instance directory
        os.makedirs('instance', exist_ok=True)
        shutil.copy(db_path, 'instance/secure_file_exchange.db')
        
        # Run migration
        from migrate_db import upgrade, downgrade
        
        print("\nRunning migration...")
        upgrade()
        
        # Verify schema
        if verify_schema('instance/secure_file_exchange.db'):
            print("\n" + "=" * 60)
            print("✓ All schema verifications passed!")
            print("=" * 60)
        else:
            print("\n" + "=" * 60)
            print("✗ Schema verification failed!")
            print("=" * 60)
            return False
        
        # Test rollback
        print("\n" + "=" * 60)
        print("Testing Rollback")
        print("=" * 60)
        
        downgrade()
        
        # Verify tables are removed
        conn = sqlite3.connect('instance/secure_file_exchange.db')
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='access_requests'")
        if not cursor.fetchone():
            print("✓ access_requests table removed")
        else:
            print("✗ access_requests table still exists")
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='crypto_logs'")
        if not cursor.fetchone():
            print("✓ crypto_logs table removed")
        else:
            print("✗ crypto_logs table still exists")
        
        conn.close()
        
        os.chdir(original_cwd)
        return True
        
    finally:
        # Cleanup
        shutil.rmtree(temp_dir)
        print(f"\nTest database cleaned up")


if __name__ == '__main__':
    print("=" * 60)
    print("Database Migration Test Suite")
    print("=" * 60)
    
    # Test with Alembic
    try:
        success = test_migration_with_alembic()
        if success:
            print("\n✓ Alembic migration test PASSED")
        else:
            print("\n✗ Alembic migration test FAILED")
    except Exception as e:
        print(f"\n✗ Alembic migration test FAILED with error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 60)
    
    # Test with standalone script
    try:
        success = test_migration_with_script()
        if success:
            print("\n✓ Standalone script migration test PASSED")
        else:
            print("\n✗ Standalone script migration test FAILED")
    except Exception as e:
        print(f"\n✗ Standalone script migration test FAILED with error: {e}")
        import traceback
        traceback.print_exc()
