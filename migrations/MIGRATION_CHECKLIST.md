# Migration Checklist

Use this checklist when performing the data migration for existing users.

## Pre-Migration

- [ ] **Backup Database**: Ensure you have a manual backup in addition to the automatic one
- [ ] **MongoDB Running**: Verify MongoDB is running and accessible
  ```bash
  # Test MongoDB connection
  mongo <MONGODB_URI>
  ```
- [ ] **Environment Variables**: Verify configuration
  ```bash
  echo $MONGODB_URI
  echo $MONGODB_DB_NAME
  ```
- [ ] **Dependencies Installed**: Ensure all required packages are installed
  ```bash
  pip install -r requirements.txt
  ```
- [ ] **Dry Run**: Test the migration without making changes
  ```bash
  python migrations/002_migrate_existing_users_keys.py --dry-run
  ```

## Migration

- [ ] **Review Dry Run Output**: Verify the list of users to be migrated
- [ ] **Prepare Password**: Choose a strong password (minimum 8 characters)
- [ ] **Run Migration**: Execute the migration script
  ```bash
  python migrations/002_migrate_existing_users_keys.py
  ```
- [ ] **Monitor Progress**: Watch for any errors during execution
- [ ] **Review Summary**: Check the migration summary for success/failure counts

## Post-Migration Verification

### Database Verification

- [ ] **Check SQLite**: Verify public keys are stored
  ```sql
  SELECT id, username, 
         CASE WHEN public_key IS NOT NULL THEN 'Yes' ELSE 'No' END as has_key,
         key_generated_at
  FROM users;
  ```

- [ ] **Check MongoDB**: Verify private keys are stored
  ```javascript
  use secure_file_exchange_keys
  db.private_keys.count()
  db.private_keys.find({}, {user_id: 1, algorithm: 1, created_at: 1})
  ```

- [ ] **Check Crypto Logs**: Verify operations are logged
  ```sql
  SELECT user_id, operation, success, timestamp
  FROM crypto_logs
  WHERE operation = 'keypair_generated'
  ORDER BY timestamp DESC;
  ```

### Functional Testing

- [ ] **User Login**: Test logging in as a migrated user
- [ ] **View Profile**: Verify public key fingerprint is displayed
- [ ] **Key Operations**: Test encryption/decryption if applicable
- [ ] **Access Requests**: Test consultant access request workflow (if applicable)

### Security Verification

- [ ] **Password Security**: Verify password is not stored anywhere
- [ ] **Private Key Encryption**: Verify private keys are encrypted in MongoDB
- [ ] **Public Key Visibility**: Verify public keys are accessible in SQLite
- [ ] **Audit Trail**: Verify all operations are logged

## Rollback (If Needed)

- [ ] **Restore Database**: Copy backup to original location
  ```bash
  cp secure_file_exchange.db.backup_YYYYMMDD_HHMMSS secure_file_exchange.db
  ```

- [ ] **Clean MongoDB** (Optional): Remove migrated keys
  ```javascript
  use secure_file_exchange_keys
  db.private_keys.deleteMany({
    migration_script: "002_migrate_existing_users_keys.py"
  })
  ```

- [ ] **Remove Logs** (Optional): Clean up crypto logs
  ```sql
  DELETE FROM crypto_logs
  WHERE operation = 'keypair_generated'
    AND details LIKE '%during migration%';
  ```

## Post-Migration Cleanup

- [ ] **Keep Backup**: Retain backup for at least 7 days
- [ ] **Document Password**: Store migration password securely (if needed for recovery)
- [ ] **Update Documentation**: Note migration date and any issues encountered
- [ ] **Monitor Logs**: Watch for any errors in the following days
- [ ] **User Communication**: Inform users about the new key-based system (if applicable)

## Troubleshooting

### Common Issues

**MongoDB Connection Failed**
- Check MongoDB is running
- Verify MONGODB_URI is correct
- Test connection manually

**Password Too Short**
- Use minimum 8 characters
- Consider using a password manager

**Duplicate Key Error**
- User already has a key in MongoDB
- Safe to ignore or skip that user

**Migration Interrupted**
- Partial migrations are rolled back per user
- Safe to re-run the script
- Already migrated users will be skipped

## Notes

- Migration is idempotent - safe to run multiple times
- Users without keys will be migrated
- Users with existing keys will be skipped
- All operations are logged for audit purposes
- Automatic backup is created before any changes

## Sign-Off

- [ ] Migration completed successfully
- [ ] All verifications passed
- [ ] Backup retained
- [ ] Documentation updated

**Migration Date**: _______________

**Performed By**: _______________

**Notes**: _______________________________________________
