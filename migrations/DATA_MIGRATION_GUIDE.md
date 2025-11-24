# Data Migration Guide - RSA Key Generation for Existing Users

## Overview

This guide explains how to migrate existing users to the new asymmetric key exchange system by generating RSA key pairs for users who don't have them yet.

## Prerequisites

1. **Backup**: The script automatically creates a backup, but ensure you have additional backups
2. **MongoDB**: MongoDB must be running and accessible
3. **Environment Variables**: Ensure `MONGODB_URI` and `MONGODB_DB_NAME` are configured
4. **Python Environment**: All dependencies must be installed (`pymongo`, `pycryptodome`)

## Migration Script

The migration script is located at: `migrations/002_migrate_existing_users_keys.py`

### Features

- ✅ Automatic database backup before migration
- ✅ Generates RSA-2048 key pairs for users without keys
- ✅ Encrypts private keys with password-derived encryption
- ✅ Stores public keys in SQLite database
- ✅ Stores encrypted private keys in MongoDB
- ✅ Logs all key generation operations
- ✅ Graceful error handling with rollback
- ✅ Dry-run mode for testing

## Usage

### 1. Dry Run (Recommended First)

Test the migration without making any changes:

```bash
cd Secure-File-Exchange-main
python migrations/002_migrate_existing_users_keys.py --dry-run
```

This will:
- Show which users would be migrated
- Verify MongoDB connectivity
- Display what would happen without making changes

### 2. Run Migration

Execute the actual migration:

```bash
cd Secure-File-Exchange-main
python migrations/002_migrate_existing_users_keys.py
```

### 3. Follow Prompts

The script will:
1. Create a database backup
2. Connect to MongoDB
3. Identify users without RSA keys
4. Prompt for a password to encrypt private keys
5. Generate keys for each user
6. Display a summary of results

### Password Requirements

- Minimum 8 characters
- Will be used to encrypt all private keys in this migration batch
- Users can change their password later through the application
- **Important**: Remember this password or document it securely

## What the Script Does

### Step 1: Database Backup
```
Creates: <database>.backup_YYYYMMDD_HHMMSS
Location: Same directory as the database file
```

### Step 2: MongoDB Connection
- Connects to MongoDB using environment variables
- Verifies connection is working
- Prepares key store for private key storage

### Step 3: User Identification
- Queries all users without `public_key` or `public_key_fingerprint`
- Displays list of users to be migrated

### Step 4: Password Setup
- Prompts for password (hidden input)
- Requires confirmation
- Validates minimum length

### Step 5: Key Generation
For each user:
1. Generate RSA-2048 key pair
2. Generate public key fingerprint (SHA-256)
3. Encrypt private key with AES-256-GCM using password-derived key
4. Store public key in SQLite `users` table
5. Store encrypted private key in MongoDB `private_keys` collection
6. Create log entry in `crypto_logs` table

## Database Changes

### SQLite (users table)
```sql
UPDATE users SET
  public_key = <RSA public key PEM>,
  public_key_fingerprint = <SHA-256 fingerprint>,
  key_generated_at = <current timestamp>
WHERE id = <user_id>;
```

### MongoDB (private_keys collection)
```javascript
{
  user_id: <user_id>,
  encrypted_private_key: <AES-256-GCM encrypted RSA private key>,
  salt: <PBKDF2 salt>,
  nonce: <AES-GCM nonce>,
  algorithm: "RSA-2048",
  created_at: <timestamp>,
  last_accessed: <timestamp>,
  access_count: 0,
  migration_batch: <timestamp>,
  migration_script: "002_migrate_existing_users_keys.py"
}
```

### SQLite (crypto_logs table)
```sql
INSERT INTO crypto_logs (
  user_id,
  operation,
  details,
  success,
  timestamp,
  ip_address
) VALUES (
  <user_id>,
  'keypair_generated',
  'RSA-2048 key pair generated during migration for user <username>',
  1,
  <timestamp>,
  '127.0.0.1'
);
```

## Verification

After migration, verify the results:

### 1. Check SQLite Database
```bash
sqlite3 instance/secure_file_exchange.db
```

```sql
-- Check users have keys
SELECT id, username, role, 
       CASE WHEN public_key IS NOT NULL THEN 'Yes' ELSE 'No' END as has_public_key,
       public_key_fingerprint,
       key_generated_at
FROM users;

-- Check crypto logs
SELECT user_id, operation, success, timestamp
FROM crypto_logs
WHERE operation = 'keypair_generated'
ORDER BY timestamp DESC;
```

### 2. Check MongoDB
```bash
mongo
```

```javascript
use secure_file_exchange_keys

// Count private keys
db.private_keys.count()

// View private keys (metadata only)
db.private_keys.find({}, {
  user_id: 1,
  algorithm: 1,
  created_at: 1,
  migration_batch: 1
})
```

### 3. Test User Login
1. Log in as a migrated user
2. Navigate to profile page
3. Verify public key fingerprint is displayed
4. Test key operations (if applicable)

## Troubleshooting

### MongoDB Connection Failed
```
Error: Failed to connect to MongoDB
```

**Solution**:
- Verify MongoDB is running: `systemctl status mongod` (Linux) or `brew services list` (macOS)
- Check `MONGODB_URI` environment variable
- Test connection: `mongo <MONGODB_URI>`

### Password Too Short
```
Error: Password must be at least 8 characters
```

**Solution**: Use a password with at least 8 characters

### Duplicate Key Error
```
Error: Private key already exists for user_id
```

**Solution**: User already has a key in MongoDB. This is safe to ignore.

### Migration Interrupted
If migration is interrupted (Ctrl+C):
- Database backup is preserved
- Partial migrations are rolled back per user
- Safe to re-run the script

## Rollback

If you need to rollback the migration:

### 1. Restore Database Backup
```bash
cd Secure-File-Exchange-main/instance
cp secure_file_exchange.db.backup_YYYYMMDD_HHMMSS secure_file_exchange.db
```

### 2. Clean MongoDB (Optional)
```javascript
use secure_file_exchange_keys
db.private_keys.deleteMany({
  migration_script: "002_migrate_existing_users_keys.py"
})
```

### 3. Remove Crypto Logs (Optional)
```sql
DELETE FROM crypto_logs
WHERE operation = 'keypair_generated'
  AND details LIKE '%during migration%';
```

## Security Considerations

1. **Password Storage**: The migration password is NOT stored anywhere. Users will need to use this password to decrypt their private keys.

2. **Backup Security**: Database backups contain public keys but NOT private keys (those are in MongoDB).

3. **MongoDB Security**: Ensure MongoDB is properly secured with authentication and network restrictions.

4. **Password Strength**: Use a strong password for the migration. Consider using a password manager.

5. **Audit Trail**: All key generation operations are logged in `crypto_logs` table.

## Post-Migration

After successful migration:

1. ✅ Verify all users can log in
2. ✅ Test key operations (encryption, decryption)
3. ✅ Monitor crypto logs for any errors
4. ✅ Keep backup for at least 7 days
5. ✅ Document the migration password securely
6. ✅ Consider implementing password change functionality for users

## Support

If you encounter issues:
1. Check the migration summary output
2. Review crypto logs in the database
3. Check MongoDB logs
4. Verify environment variables
5. Ensure all dependencies are installed

## Requirements Satisfied

This migration script satisfies the following requirements:
- **4.1**: Generates RSA key pairs with minimum 2048-bit key size
- **4.2**: Stores public keys in production database (SQLite)
- **4.3**: Encrypts private keys using password-derived encryption
- **4.4**: Stores private keys in separate NoSQL database (MongoDB)
