# Key Management Best Practices

This guide covers best practices for managing cryptographic keys in the Secure File Exchange System, including key generation, storage, rotation, backup, and recovery procedures.

## Table of Contents
- [Overview](#overview)
- [Key Hierarchy](#key-hierarchy)
- [Key Generation](#key-generation)
- [Key Storage](#key-storage)
- [Key Rotation](#key-rotation)
- [Key Backup and Recovery](#key-backup-and-recovery)
- [Key Revocation](#key-revocation)
- [Monitoring and Auditing](#monitoring-and-auditing)
- [Incident Response](#incident-response)
- [Compliance Considerations](#compliance-considerations)

## Overview

The Secure File Exchange System uses a multi-layered key management architecture:

1. **Master KEK** (Key Encryption Key): Wraps symmetric file encryption keys
2. **Symmetric DEKs** (Data Encryption Keys): Encrypt file data
3. **RSA Key Pairs**: Enable secure key exchange between users
4. **Password-Derived Keys**: Protect RSA private keys

Proper key management is critical for maintaining the security and availability of encrypted data.

## Key Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│                     Master KEK                               │
│              (from MASTER_KEY env var)                       │
│         Used to wrap all symmetric DEKs                      │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ├─────────────────────────────────────────┐
                     │                                         │
          ┌──────────▼──────────┐                  ┌──────────▼──────────┐
          │  Symmetric DEK #1   │                  │  Symmetric DEK #2   │
          │   (File Specific)   │                  │   (File Specific)   │
          │  Encrypts file data │                  │  Encrypts file data │
          └──────────┬──────────┘                  └──────────┬──────────┘
                     │                                         │
                     │                                         │
          ┌──────────▼──────────┐                  ┌──────────▼──────────┐
          │   Encrypted File    │                  │   Encrypted File    │
          └─────────────────────┘                  └─────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│              User Password (Consultant)                      │
│         Used to derive private key encryption key            │
└────────────────────┬────────────────────────────────────────┘
                     │
                     │ PBKDF2 (100,000 iterations)
                     │
          ┌──────────▼──────────┐
          │  Password-Derived   │
          │   Encryption Key    │
          │  (AES-256-GCM key)  │
          └──────────┬──────────┘
                     │
                     │ Encrypts
                     │
          ┌──────────▼──────────┐
          │   RSA Private Key   │
          │    (Encrypted)      │
          └──────────┬──────────┘
                     │
                     │ Stored in MongoDB
                     │
          ┌──────────▼──────────┐
          │   MongoDB KeyStore  │
          └─────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│              RSA Public Key                                  │
│         Stored in SQLite, used by organizations              │
│         to wrap DEKs for consultants                         │
└─────────────────────────────────────────────────────────────┘
```

## Key Generation

### Master KEK Generation

The Master KEK should be a strong, random value:

```bash
# Generate a strong 32-byte (256-bit) key
python3 -c "import secrets; print(secrets.token_hex(32))"

# Or use OpenSSL
openssl rand -hex 32

# Set as environment variable
export MASTER_KEY="<generated-key>"
```

**Best Practices**:
- Generate using cryptographically secure random number generator
- Minimum 256 bits (32 bytes)
- Store securely (see Key Storage section)
- Never commit to version control
- Rotate periodically (see Key Rotation section)

### RSA Key Pair Generation

RSA key pairs are automatically generated during user registration:

```python
# Automatic generation (handled by system)
from app.asymmetric_crypto import AsymmetricCrypto

public_key, private_key = AsymmetricCrypto.generate_rsa_keypair(key_size=2048)
```

**Best Practices**:
- Minimum 2048-bit keys (current standard)
- Consider 4096-bit keys for high-security environments
- Generate on secure, trusted systems
- Ensure sufficient entropy (check `/dev/random` on Linux)
- Never reuse key pairs across systems

### Symmetric DEK Generation

DEKs are automatically generated for each file upload:

```python
# Automatic generation (handled by system)
import secrets

# AES-256 key (32 bytes)
dek = secrets.token_bytes(32)

# DES key (8 bytes)
dek = secrets.token_bytes(8)

# RC4 key (16 bytes)
dek = secrets.token_bytes(16)
```

**Best Practices**:
- Use `secrets` module (cryptographically secure)
- Generate unique key for each file
- Never reuse DEKs across files
- Immediately wrap with KEK after generation

## Key Storage

### Master KEK Storage

**Development**:
```bash
# .env file (never commit!)
MASTER_KEY=your-master-kek-here
```

**Production Options**:

1. **Environment Variables** (Basic):
   ```bash
   # Set in system environment
   export MASTER_KEY="<key>"
   
   # Or in systemd service file
   Environment="MASTER_KEY=<key>"
   ```

2. **Secrets Management Service** (Recommended):
   ```python
   # AWS Secrets Manager
   import boto3
   
   client = boto3.client('secretsmanager')
   response = client.get_secret_value(SecretId='sfe/master-kek')
   master_key = response['SecretString']
   ```

3. **Hardware Security Module (HSM)** (Enterprise):
   - Store KEK in HSM
   - Perform wrap/unwrap operations in HSM
   - Never expose KEK outside HSM

**Best Practices**:
- Never store in source code or version control
- Restrict access to authorized personnel only
- Use secrets management service in production
- Enable audit logging for key access
- Encrypt backups containing keys

### RSA Private Key Storage

Private keys are stored in MongoDB with encryption:

**Storage Format**:
```javascript
{
  "user_id": 123,
  "encrypted_private_key": Binary,  // AES-256-GCM encrypted
  "salt": Binary,                   // PBKDF2 salt (unique per user)
  "nonce": Binary,                  // AES-GCM nonce (unique per encryption)
  "algorithm": "RSA-2048",
  "created_at": ISODate,
  "last_accessed": ISODate,
  "access_count": 42
}
```

**Best Practices**:
- Enable MongoDB authentication
- Use TLS/SSL for MongoDB connections
- Enable MongoDB encryption at rest
- Restrict network access to MongoDB
- Regular backups (encrypted)
- Monitor access patterns

### RSA Public Key Storage

Public keys are stored in SQLite:

```sql
-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    public_key BLOB,                    -- PEM format
    public_key_fingerprint VARCHAR(64), -- SHA-256 hash
    key_generated_at DATETIME,
    ...
);
```

**Best Practices**:
- Public keys don't need encryption (public by design)
- Store fingerprint for verification
- Include generation timestamp
- Validate format before storage

### Wrapped DEK Storage

Wrapped DEKs are stored in SQLite:

```sql
-- EncryptedFiles table
CREATE TABLE encrypted_files (
    id INTEGER PRIMARY KEY,
    wrapped_key BLOB,              -- KEK-wrapped DEK
    wrapped_key_version VARCHAR(10), -- Wrapping format version
    encryption_key BLOB,           -- Legacy (nullable)
    ...
);
```

**Best Practices**:
- Always wrap DEKs before storage
- Never store plaintext DEKs
- Include version information
- Maintain backward compatibility

## Key Rotation

### Master KEK Rotation

Rotating the Master KEK requires re-wrapping all DEKs:

```python
# Example rotation script
from app import create_app, db
from app.models import EncryptedFile
from app.crypto_utils import get_kms_provider

app = create_app()

with app.app_context():
    # Get old and new KMS providers
    old_kms = get_kms_provider()  # Uses current MASTER_KEY
    
    # Set new MASTER_KEY in environment
    import os
    os.environ['MASTER_KEY'] = 'new-master-key-here'
    new_kms = get_kms_provider()  # Uses new MASTER_KEY
    
    # Re-wrap all DEKs
    files = EncryptedFile.query.all()
    for file in files:
        if file.wrapped_key:
            # Unwrap with old KEK
            dek = old_kms.unwrap_key(file.wrapped_key)
            
            # Wrap with new KEK
            new_wrapped = new_kms.wrap_key(dek)
            
            # Update database
            file.wrapped_key = new_wrapped
            file.wrapped_key_version = 'V1'  # Update version if needed
    
    db.session.commit()
    print(f"Rotated KEK for {len(files)} files")
```

**Rotation Schedule**:
- **Regular Rotation**: Every 12-24 months
- **Incident Response**: Immediately if compromised
- **Personnel Changes**: When key custodians leave
- **Compliance**: As required by regulations

**Best Practices**:
- Test rotation procedure in development first
- Backup database before rotation
- Perform during maintenance window
- Verify all files accessible after rotation
- Keep old KEK for recovery period
- Document rotation in audit log

### RSA Key Pair Rotation

Users can regenerate their RSA key pairs:

```python
# Example key regeneration (to be implemented)
@main.route('/regenerate-keys', methods=['POST'])
@login_required
def regenerate_keys():
    # Generate new key pair
    public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
    
    # Encrypt new private key
    encrypted_key, salt, nonce = AsymmetricCrypto.encrypt_private_key(
        private_key, 
        current_user.password
    )
    
    # Store new keys
    current_user.public_key = public_key
    current_user.public_key_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(public_key)
    current_user.key_generated_at = datetime.utcnow()
    
    key_store.store_private_key(
        current_user.id,
        encrypted_key,
        salt,
        nonce,
        {'algorithm': 'RSA-2048'}
    )
    
    # For consultants: re-wrap all approved DEKs with new public key
    if current_user.role == UserRole.CONSULTANT:
        # This would require organizations to re-approve or automatic re-wrapping
        pass
    
    db.session.commit()
    flash('Keys regenerated successfully', 'success')
    return redirect(url_for('main.profile'))
```

**When to Rotate**:
- **Suspected Compromise**: Immediately
- **Password Change**: Recommended
- **Regular Schedule**: Every 2-3 years
- **Compliance**: As required

**Considerations**:
- Consultants with approved access will need new approvals
- Organizations are not affected (they don't use their private keys)
- Coordinate with organizations before rotation

## Key Backup and Recovery

### Master KEK Backup

**Backup Procedure**:

1. **Secure Storage**:
   ```bash
   # Encrypt the KEK before backup
   echo -n "$MASTER_KEY" | openssl enc -aes-256-cbc -salt -pbkdf2 -out master_kek.enc
   
   # Store encrypted file in secure location
   # - Hardware security module
   # - Encrypted USB drive in safe
   # - Secrets management service
   ```

2. **Split Key Storage** (Shamir's Secret Sharing):
   ```python
   # Example using secretsharing library
   from secretsharing import PlaintextToHexSecretSharer
   
   # Split KEK into 5 shares, require 3 to reconstruct
   shares = PlaintextToHexSecretSharer.split_secret(master_key, 3, 5)
   
   # Distribute shares to different custodians
   # Store in separate secure locations
   ```

3. **Escrow Service**:
   - Use professional key escrow service
   - Requires multiple approvals for recovery
   - Maintains audit trail

**Recovery Procedure**:

1. Retrieve encrypted KEK from secure storage
2. Decrypt using backup password or reconstruct from shares
3. Set as `MASTER_KEY` environment variable
4. Restart application
5. Verify file decryption works
6. Document recovery in audit log

### MongoDB Backup

**Backup Private Keys**:

```bash
# Full database backup
mongodump --uri="mongodb://user:pass@localhost:27017/secure_file_exchange_keys" \
          --out=/backup/mongodb/$(date +%Y%m%d)

# Encrypt backup
tar czf - /backup/mongodb/$(date +%Y%m%d) | \
    openssl enc -aes-256-cbc -salt -pbkdf2 -out mongodb_backup_$(date +%Y%m%d).tar.gz.enc

# Store encrypted backup securely
```

**Restore Procedure**:

```bash
# Decrypt backup
openssl enc -d -aes-256-cbc -pbkdf2 -in mongodb_backup_20231215.tar.gz.enc | \
    tar xzf -

# Restore to MongoDB
mongorestore --uri="mongodb://user:pass@localhost:27017/secure_file_exchange_keys" \
             /backup/mongodb/20231215
```

**Best Practices**:
- Automate daily backups
- Encrypt all backups
- Store backups off-site
- Test restore procedure regularly
- Retain backups for compliance period
- Document backup/restore procedures

### SQLite Backup

**Backup Procedure**:

```bash
# Stop application
systemctl stop secure-file-exchange

# Backup database
cp instance/secure_file_exchange.db instance/secure_file_exchange.db.backup_$(date +%Y%m%d)

# Encrypt backup
openssl enc -aes-256-cbc -salt -pbkdf2 \
    -in instance/secure_file_exchange.db.backup_$(date +%Y%m%d) \
    -out secure_file_exchange.db.backup_$(date +%Y%m%d).enc

# Start application
systemctl start secure-file-exchange
```

**Restore Procedure**:

```bash
# Stop application
systemctl stop secure-file-exchange

# Decrypt and restore
openssl enc -d -aes-256-cbc -pbkdf2 \
    -in secure_file_exchange.db.backup_20231215.enc \
    -out instance/secure_file_exchange.db

# Start application
systemctl start secure-file-exchange
```

## Key Revocation

### Revoking User Access

When a consultant's access is revoked:

```python
# Handled by application
@main.route('/revoke-access/<request_id>', methods=['POST'])
@login_required
@organization_required
def revoke_access(request_id):
    request = AccessRequest.query.get_or_404(request_id)
    
    # Update status
    request.status = 'revoked'
    request.processed_at = datetime.utcnow()
    
    # Delete wrapped key
    request.wrapped_symmetric_key = None
    
    # Invalidate session keys
    # (handled by checking status on each access)
    
    db.session.commit()
    log_crypto_operation('access_revoked', ...)
```

**Best Practices**:
- Revoke immediately upon termination or suspicion
- Clear all session keys
- Log revocation for audit
- Notify affected parties
- Review all access grants periodically

### Revoking Compromised Keys

If a user's private key is compromised:

1. **Immediate Actions**:
   - Disable user account
   - Revoke all active access requests
   - Delete private key from MongoDB
   - Invalidate all sessions

2. **Investigation**:
   - Review audit logs for unauthorized access
   - Identify potentially accessed files
   - Notify affected organizations

3. **Recovery**:
   - User must re-register or regenerate keys
   - Re-request access to needed files
   - Organizations must re-approve requests

## Monitoring and Auditing

### Crypto Operation Logging

All cryptographic operations are logged:

```python
# Example log entry
{
    'user_id': 123,
    'operation': 'key_unwrapped',
    'details': 'Consultant unwrapped DEK for file_id=456',
    'success': True,
    'timestamp': '2023-12-15T10:30:00Z',
    'ip_address': '192.168.1.100'
}
```

**Logged Operations**:
- `keypair_generated`: RSA key pair creation
- `key_wrapped`: DEK wrapped with RSA public key
- `key_unwrapped`: DEK unwrapped with RSA private key
- `private_key_decrypted`: Private key decrypted with password
- `access_granted`: Access request approved
- `access_revoked`: Access revoked

### Monitoring Alerts

Set up alerts for:
- Multiple failed password attempts
- Unusual access patterns
- Key generation failures
- MongoDB connection failures
- Unauthorized access attempts
- Large number of downloads

### Audit Reports

Generate regular audit reports:

```python
# Example audit report query
from app.models import CryptoLog
from datetime import datetime, timedelta

# Last 30 days
start_date = datetime.utcnow() - timedelta(days=30)
logs = CryptoLog.query.filter(CryptoLog.timestamp >= start_date).all()

# Group by operation
operations = {}
for log in logs:
    operations[log.operation] = operations.get(log.operation, 0) + 1

# Failed operations
failed = CryptoLog.query.filter(
    CryptoLog.timestamp >= start_date,
    CryptoLog.success == False
).all()

# Generate report
print(f"Audit Report: {start_date} to {datetime.utcnow()}")
print(f"Total operations: {len(logs)}")
print(f"Failed operations: {len(failed)}")
for op, count in operations.items():
    print(f"  {op}: {count}")
```

## Incident Response

### Suspected Key Compromise

**Response Procedure**:

1. **Immediate Actions** (within 1 hour):
   - Disable affected user accounts
   - Revoke all active access grants
   - Isolate affected systems
   - Preserve logs and evidence

2. **Investigation** (within 24 hours):
   - Review audit logs
   - Identify scope of compromise
   - Determine attack vector
   - Assess data exposure

3. **Containment** (within 48 hours):
   - Rotate compromised keys
   - Patch vulnerabilities
   - Update security controls
   - Monitor for further activity

4. **Recovery** (within 1 week):
   - Restore from clean backups if needed
   - Re-issue keys to affected users
   - Re-establish access controls
   - Verify system integrity

5. **Post-Incident** (within 2 weeks):
   - Document incident
   - Update procedures
   - Train personnel
   - Notify affected parties (if required)

### Data Breach Response

If encrypted files are exposed:

1. **Assess Risk**:
   - Are KEKs compromised? (High risk)
   - Are wrapped DEKs exposed? (Medium risk - requires KEK)
   - Are encrypted files exposed? (Low risk - requires DEK)

2. **Mitigation**:
   - Rotate KEK if compromised
   - Re-wrap all DEKs
   - Notify affected organizations
   - Enhance security controls

3. **Compliance**:
   - Notify authorities if required (GDPR, HIPAA, etc.)
   - Document breach and response
   - Implement corrective actions

## Compliance Considerations

### Regulatory Requirements

Different regulations have different key management requirements:

**GDPR** (General Data Protection Regulation):
- Encryption of personal data
- Key management procedures documented
- Ability to delete keys (right to erasure)
- Breach notification within 72 hours

**HIPAA** (Health Insurance Portability and Accountability Act):
- Encryption of ePHI (electronic Protected Health Information)
- Key management procedures
- Access controls and audit logs
- Disaster recovery plan

**PCI DSS** (Payment Card Industry Data Security Standard):
- Strong cryptography (AES-256, RSA-2048+)
- Key rotation procedures
- Separation of duties
- Secure key storage

**SOC 2** (Service Organization Control 2):
- Documented key management procedures
- Access controls
- Monitoring and logging
- Incident response plan

### Documentation Requirements

Maintain documentation for:
- Key generation procedures
- Key storage locations and methods
- Key rotation schedule and procedures
- Backup and recovery procedures
- Access control policies
- Incident response plan
- Audit log retention policy
- Training materials

### Retention Policies

Define retention periods for:
- **Active Keys**: While in use
- **Archived Keys**: Compliance period (typically 7 years)
- **Audit Logs**: Compliance period (typically 7 years)
- **Backups**: Compliance period
- **Incident Reports**: Indefinitely

## Best Practices Summary

### Do's

✅ Use strong, random keys (256-bit minimum for symmetric, 2048-bit minimum for RSA)
✅ Wrap all DEKs before storage
✅ Encrypt private keys with password-derived keys
✅ Store private keys separately from application data
✅ Enable MongoDB authentication and encryption
✅ Rotate keys regularly
✅ Backup keys securely and test recovery
✅ Log all cryptographic operations
✅ Monitor for suspicious activity
✅ Document all procedures
✅ Train personnel on key management
✅ Use secrets management service in production
✅ Enable audit logging
✅ Implement least privilege access
✅ Test incident response procedures

### Don'ts

❌ Never store plaintext keys in database
❌ Never commit keys to version control
❌ Never reuse keys across files or users
❌ Never log plaintext keys or passwords
❌ Never share private keys
❌ Never use weak encryption (ECB, DES without wrapping, MD5, SHA-1)
❌ Never skip backups
❌ Never ignore failed operations
❌ Never grant unnecessary access
❌ Never skip key rotation
❌ Never use default or weak passwords
❌ Never expose keys in error messages
❌ Never store keys in application code
❌ Never skip security updates

## Additional Resources

- [NIST Special Publication 800-57: Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
- [AWS Key Management Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
- [MongoDB Security Checklist](https://docs.mongodb.com/manual/administration/security-checklist/)

## Support

For key management questions or incidents:
- Contact your security team immediately
- Review this guide and system documentation
- Escalate to system administrators if needed
- Document all actions taken

---

**Remember**: Proper key management is critical for system security. When in doubt, consult with security professionals and follow the principle of least privilege.
