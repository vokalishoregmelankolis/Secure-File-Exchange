"""
Test the standalone migration script on the test database.
"""
import sys
import os

# Set the database path to the test database
os.environ['TEST_DB_PATH'] = '../instance/test_migration.db'

# Import and run the migration
from migrate_db import upgrade, get_db_path

# Override get_db_path to use test database
original_get_db_path = get_db_path

def test_get_db_path():
    return '../instance/test_migration.db'

# Monkey patch
import migrate_db
migrate_db.get_db_path = test_get_db_path

print("Running migration on test database...")
upgrade()

print("\nVerifying migration...")
import sqlite3
conn = sqlite3.connect('../instance/test_migration.db')
cursor = conn.cursor()

cursor.execute('PRAGMA table_info(users)')
columns = [row[1] for row in cursor.fetchall()]
print(f"Users columns: {columns}")

cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [row[0] for row in cursor.fetchall()]
print(f"Tables: {tables}")

conn.close()
