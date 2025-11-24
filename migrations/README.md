# Database Migrations

This directory contains database migration scripts for the Secure File Exchange System.

## Quick Start

### Using Alembic (Recommended)

```bash
# Install dependencies
pip install -r requirements.txt

# Run migration
cd Secure-File-Exchange-main
alembic upgrade head

# Check status
alembic current

# Rollback
alembic downgrade -1
```

### Using Standalone Script

```bash
# Run migration
cd Secure-File-Exchange-main/migrations
python migrate_db.py

# Rollback
python migrate_db.py downgrade
```

## Files

- **`alembic/`** - Alembic migration framework files
  - `env.py` - Alembic environment configuration
  - `versions/001_add_asymmetric_key_exchange.py` - Migration for asymmetric key exchange feature
  
- **`migrate_db.py`** - Standalone migration script (SQLite-compatible)
  
- **`001_add_asymmetric_key_models.py`** - Legacy migration script (Flask-based)

- **`002_migrate_existing_users_keys.py`** - Data migration script for generating RSA keys for existing users
  
- **`test_migration.py`** - Automated migration testing script

- **`test_migration_script.py`** - Test suite for the data migration script
  
- **`MIGRATION_GUIDE.md`** - Comprehensive migration documentation

- **`DATA_MIGRATION_GUIDE.md`** - Guide for migrating existing users to RSA keys

- **`run_migration.sh`** / **`run_migration.bat`** - Helper scripts for running data migration

## Testing Migrations

```bash
# Run migration tests
cd Secure-File-Exchange-main/migrations
python test_migration.py
```

## Migration Details

### Version 001: Asymmetric Key Exchange (Schema Migration)

**What it does:**
- Adds role, public_key, public_key_fingerprint, and key_generated_at columns to users table
- Creates access_requests table for tracking consultant access requests
- Creates crypto_logs table for logging cryptographic operations
- Creates indexes for performance optimization

**Requirements satisfied:**
- Requirement 1.1: User role selection
- Requirement 2.4: Access request tracking
- Requirement 11.1: Cryptographic operation logging

**Rollback:**
- Removes access_requests and crypto_logs tables
- Removes new columns from users table (SQLite limitations may apply)

### Version 002: User Key Generation (Data Migration)

**What it does:**
- Generates RSA-2048 key pairs for existing users without keys
- Encrypts private keys with password-derived encryption (AES-256-GCM)
- Stores public keys in SQLite database
- Stores encrypted private keys in MongoDB
- Logs all key generation operations
- Creates automatic database backup before migration

**Requirements satisfied:**
- Requirement 4.1: RSA key pair generation with minimum 2048-bit key size
- Requirement 4.2: Public key storage in production database
- Requirement 4.3: Private key encryption with password
- Requirement 4.4: Private key storage in separate NoSQL database

**Usage:**
```bash
# Dry run (recommended first)
python migrations/002_migrate_existing_users_keys.py --dry-run

# Run migration
python migrations/002_migrate_existing_users_keys.py

# Or use helper scripts
./migrations/run_migration.sh --dry-run  # Linux/Mac
migrations\run_migration.bat --dry-run   # Windows
```

**Important:**
- Prompts for password to encrypt private keys
- Creates automatic backup before making changes
- Requires MongoDB to be running and accessible
- See [DATA_MIGRATION_GUIDE.md](DATA_MIGRATION_GUIDE.md) for detailed instructions

## Important Notes

### SQLite Limitations

SQLite has limited ALTER TABLE support. The migration uses batch mode to work around these limitations. If you encounter issues:

1. Use the standalone `migrate_db.py` script which handles SQLite-specific constraints
2. Ensure you're using SQLAlchemy 1.4+ with batch operation support
3. Always backup your database before migration

### Backup

Both migration methods automatically create backups:
- Alembic: Manual backup recommended before running
- Standalone script: Automatic backup with timestamp

### Production Deployment

1. **Test first**: Run migration on a copy of production data
2. **Backup**: Create manual backup before migration
3. **Downtime**: Plan for brief downtime during migration
4. **Verify**: Check application functionality after migration
5. **Monitor**: Watch logs for any issues

## Troubleshooting

### MongoDB SSL/TLS Connection Error

If you see SSL handshake errors when connecting to MongoDB Atlas:

**Quick Fix:**
```bash
# Run the automatic fix script
python migrations/apply_mongodb_fix.py

# Or manually update SSL libraries
pip install --upgrade certifi pymongo cryptography
pip install certifi-win32
```

**Test Connection:**
```bash
python migrations/test_mongo_fix.py
```

**Detailed Help:**
See [FIX_MONGODB_SSL.md](FIX_MONGODB_SSL.md) for comprehensive troubleshooting.

### "Table already exists" error

The migration was partially applied. Check status and manually mark as complete:

```bash
alembic current
alembic stamp head
```

### "Cannot add NOT NULL column" error

SQLite limitation. The migration handles this with default values. If issues persist, use the standalone script.

### Rollback doesn't remove columns

SQLite doesn't support DROP COLUMN in all versions. Tables will be removed, but columns may remain unused.

## Support

For detailed documentation, see [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md)
