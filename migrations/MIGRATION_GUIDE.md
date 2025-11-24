# Database Migration Guide

## Overview

This guide explains how to migrate the Secure File Exchange database to support the asymmetric key exchange feature. The migration adds support for user roles (Organization/Consultant), access request tracking, and cryptographic operation logging.

## What's Changed

### 1. Users Table Extensions
- **role**: VARCHAR(20) - User role (organization or consultant)
- **public_key**: BLOB - RSA public key in PEM format
- **public_key_fingerprint**: VARCHAR(64) - SHA-256 fingerprint of public key
- **key_generated_at**: DATETIME - Timestamp of key generation

### 2. New Tables

#### access_requests
Tracks data access requests from consultants to organizations.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| consultant_id | INTEGER | Foreign key to users (consultant) |
| organization_id | INTEGER | Foreign key to users (organization) |
| file_id | INTEGER | Foreign key to encrypted_files |
| status | VARCHAR(20) | Request status (pending, approved, denied, revoked) |
| wrapped_symmetric_key | BLOB | RSA-wrapped symmetric key (after approval) |
| requested_at | DATETIME | Request submission timestamp |
| processed_at | DATETIME | Request processing timestamp |

**Constraints:**
- UNIQUE(consultant_id, file_id) - Prevents duplicate requests
- CASCADE DELETE on all foreign keys

#### crypto_logs
Logs all cryptographic operations for audit purposes.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| user_id | INTEGER | Foreign key to users |
| operation | VARCHAR(50) | Operation type (keypair_generated, key_wrapped, etc.) |
| details | TEXT | Additional operation details |
| success | BOOLEAN | Operation success status |
| error_message | TEXT | Error message if operation failed |
| timestamp | DATETIME | Operation timestamp |
| ip_address | VARCHAR(45) | User IP address |

## Migration Methods

### Method 1: Using Alembic (Recommended)

Alembic provides version control for database schemas with proper upgrade/downgrade support.

#### Prerequisites

```bash
# Install dependencies
pip install -r requirements.txt
```

#### Running the Migration

```bash
# Navigate to the project directory
cd Secure-File-Exchange-main

# Run the migration
alembic upgrade head
```

#### Verifying the Migration

```bash
# Check current migration version
alembic current

# View migration history
alembic history
```

#### Rolling Back

```bash
# Rollback to previous version
alembic downgrade -1

# Rollback to base (removes all migrations)
alembic downgrade base
```

### Method 2: Using Legacy Migration Script

For systems without Alembic, use the standalone migration script.

```bash
# Navigate to migrations directory
cd Secure-File-Exchange-main/migrations

# Run upgrade
python migrate_db.py

# Run downgrade (rollback)
python migrate_db.py downgrade
```

## Pre-Migration Checklist

- [ ] **Backup your database** - The migration will create an automatic backup, but create your own as well
- [ ] **Stop the application** - Ensure no active connections to the database
- [ ] **Check disk space** - Ensure sufficient space for backup and migration
- [ ] **Review the changes** - Understand what will be modified
- [ ] **Test on development** - Run migration on a copy of production data first

## Post-Migration Steps

### 1. Verify Database Schema

```python
# Run this in Python shell
from app import create_app, db
from app.models import User, AccessRequest, CryptoLog

app = create_app()
with app.app_context():
    # Check if tables exist
    print("Users table columns:", User.__table__.columns.keys())
    print("AccessRequest table exists:", db.engine.has_table('access_requests'))
    print("CryptoLog table exists:", db.engine.has_table('crypto_logs'))
```

### 2. Generate Keys for Existing Users

If you have existing users, they need RSA key pairs generated:

```bash
# Run the data migration script (to be created separately)
python migrations/migrate_existing_users.py
```

### 3. Update Application Configuration

Ensure your `.env` file includes MongoDB configuration:

```bash
# MongoDB for private key storage
MONGODB_URI=mongodb://username:password@localhost:27017/keystore
MONGODB_DB_NAME=secure_file_exchange_keys
```

### 4. Test the Application

```bash
# Run tests
pytest tests/

# Start the application
python run.py
```

## Troubleshooting

### Migration Fails with "Table already exists"

This means the migration was partially applied. Options:

1. **Check migration status:**
   ```bash
   alembic current
   ```

2. **Manually mark as complete:**
   ```bash
   alembic stamp head
   ```

3. **Rollback and retry:**
   ```bash
   alembic downgrade base
   alembic upgrade head
   ```

### SQLite "Cannot add NOT NULL column" Error

SQLite has limited ALTER TABLE support. The migration uses batch mode to handle this, but if you encounter issues:

1. Use the provided migration script which handles SQLite limitations
2. Ensure you're using SQLAlchemy 1.4+ which supports batch operations

### Rollback Doesn't Remove Columns

SQLite doesn't support DROP COLUMN in all versions. After rollback:

1. The tables (access_requests, crypto_logs) will be removed
2. User table columns may remain but will be unused
3. For complete cleanup, you may need to recreate the database

## Migration Testing

### Test on Development Database

```bash
# Create a copy of your database
cp instance/secure_file_exchange.db instance/secure_file_exchange_test.db

# Update alembic.ini to point to test database
# sqlalchemy.url = sqlite:///instance/secure_file_exchange_test.db

# Run migration
alembic upgrade head

# Test the application
python run.py

# If successful, run on production
```

### Automated Testing

```bash
# Run migration tests
pytest tests/test_migrations.py -v
```

## Rollback Procedure

If you need to rollback after deployment:

```bash
# 1. Stop the application
# 2. Restore database backup
cp instance/secure_file_exchange.db.backup instance/secure_file_exchange.db

# OR use Alembic downgrade
alembic downgrade -1

# 3. Restart application with previous version
```

## Migration Timeline

Estimated time for migration:

- **Small database** (< 1000 users): 1-2 seconds
- **Medium database** (1000-10000 users): 5-10 seconds
- **Large database** (> 10000 users): 30-60 seconds

The migration is fast because it only adds columns and creates empty tables.

## Support

If you encounter issues:

1. Check the backup file location (printed during migration)
2. Review migration logs
3. Consult the error messages in the output
4. Restore from backup if needed

## Requirements Validation

This migration satisfies the following requirements:

- **Requirement 1.1**: User role selection (Organization/Consultant)
- **Requirement 2.4**: Access request tracking with all required fields
- **Requirement 11.1**: Cryptographic operation logging infrastructure

## Additional Resources

- [Alembic Documentation](https://alembic.sqlalchemy.org/)
- [Flask-Migrate Documentation](https://flask-migrate.readthedocs.io/)
- [SQLite ALTER TABLE Limitations](https://www.sqlite.org/lang_altertable.html)
