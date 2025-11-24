"""
Test the rollback functionality.
"""
import sys
import os

# Import and run the downgrade
from migrate_db import downgrade, get_db_path

# Override get_db_path to use test database
def test_get_db_path():
    return '../instance/test_migration.db'

# Monkey patch
import migrate_db
migrate_db.get_db_path = test_get_db_path

print("Running rollback on test database...")
downgrade()

print("\nVerifying rollback...")
import sqlite3
conn = sqlite3.connect('../instance/test_migration.db')
cursor = conn.cursor()

cursor.execute('PRAGMA table_info(users)')
columns = [row[1] for row in cursor.fetchall()]
print(f"Users columns after rollback: {columns}")

cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [row[0] for row in cursor.fetchall()]
print(f"Tables after rollback: {tables}")

# Check that new tables are gone
if 'access_requests' not in tables:
    print("✓ access_requests table removed")
else:
    print("✗ access_requests table still exists")

if 'crypto_logs' not in tables:
    print("✓ crypto_logs table removed")
else:
    print("✗ crypto_logs table still exists")

# Check that data is preserved
cursor.execute("SELECT username FROM users")
users = [row[0] for row in cursor.fetchall()]
print(f"Preserved users: {users}")

conn.close()
