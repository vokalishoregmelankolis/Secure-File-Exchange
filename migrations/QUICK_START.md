# Quick Start - User Key Migration

## TL;DR

```bash
# 1. Test first (no changes)
python migrations/002_migrate_existing_users_keys.py --dry-run

# 2. Run migration
python migrations/002_migrate_existing_users_keys.py

# 3. Enter password when prompted (min 8 chars)

# 4. Verify
sqlite3 instance/secure_file_exchange.db "SELECT COUNT(*) FROM users WHERE public_key IS NOT NULL;"
```

## What It Does

- ✅ Generates RSA-2048 keys for users without keys
- ✅ Encrypts private keys with your password
- ✅ Stores public keys in SQLite
- ✅ Stores private keys in MongoDB
- ✅ Creates automatic backup
- ✅ Logs everything

## Requirements

- MongoDB running
- Python dependencies installed
- Environment variables set (`MONGODB_URI`, `MONGODB_DB_NAME`)

## Quick Commands

```bash
# Dry run
python migrations/002_migrate_existing_users_keys.py --dry-run

# Run migration
python migrations/002_migrate_existing_users_keys.py

# Test components
python migrations/test_migration_script.py

# Check users without keys
python -c "from app import create_app, db; from app.models import User; app = create_app(); app.app_context().push(); print(f'Users without keys: {User.query.filter((User.public_key == None) | (User.public_key_fingerprint == None)).count()}')"
```

## Verification

```bash
# SQLite
sqlite3 instance/secure_file_exchange.db
SELECT id, username, CASE WHEN public_key IS NOT NULL THEN 'Yes' ELSE 'No' END FROM users;

# MongoDB
mongo
use secure_file_exchange_keys
db.private_keys.count()
```

## Rollback

```bash
# Restore backup
cp instance/secure_file_exchange.db.backup_YYYYMMDD_HHMMSS instance/secure_file_exchange.db
```

## Help

- Full guide: `migrations/DATA_MIGRATION_GUIDE.md`
- Checklist: `migrations/MIGRATION_CHECKLIST.md`
- Summary: `migrations/TASK_21_IMPLEMENTATION_SUMMARY.md`
