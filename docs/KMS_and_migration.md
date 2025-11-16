# KMS Integration and Database Migration

This document provides example steps and code to integrate a real KMS (AWS KMS) and to migrate the database schema to use `wrapped_key` for storing KEK-wrapped DEKs instead of raw DEKs.

## Goals
- Replace raw DEK storage with KEK-wrapped DEKs stored in `wrapped_key` column.
- Provide an adapter for a real KMS (AWS KMS example) and a simple in-memory dummy adapter for development.
- Provide an Alembic migration example and recommended migration procedure.

---

## AWS KMS adapter (example)

A minimal adapter is provided in `app/kms_adapters.py` which implements:
- `AWSKMS.wrap(plaintext: bytes) -> bytes` — encrypts plaintext DEK with KMS.
- `AWSKMS.unwrap(wrapped: bytes) -> bytes` — decrypts a KMS CiphertextBlob.

Requirements:
- `boto3` installed and configured with AWS credentials and permissions to use KMS.

Usage:
```python
from app.kms_adapters import AWSKMS
from app.crypto_utils import set_kms_provider

kms = AWSKMS(key_id='alias/your-kms-key')
set_kms_provider('env')  # keep using EnvKMS by default
# To use AWS adapter directly in your code, set module-level provider:
# from app.crypto_utils import set_kms_provider
# set_kms_provider('aws')  # if you implement automatic registration
```

Note: `app/crypto_utils` provides a `KMSInterface` used by the internal wrap/unwrap functions. The provided `AWSKMS` matches that interface.

## Adding a `kek_id` column (recommended)
When integrating with KMS, add a `kek_id` column to `EncryptedFile` to track which KMS key encrypted each DEK.

Schema example:
```sql
ALTER TABLE encrypted_files ADD COLUMN kek_id VARCHAR(255);
```

Store `KeyId` or alias used by KMS when wrapping the DEK.

## Alembic migration example (outline)
If your project uses Alembic / Flask-Migrate, create a migration similar to the following revision.

```python
# alembic revision --autogenerate -m "Add wrapped_key to EncryptedFile"
from alembic import op
import sqlalchemy as sa

def upgrade():
    op.add_column('encrypted_files', sa.Column('wrapped_key', sa.LargeBinary(), nullable=True))
    op.add_column('encrypted_files', sa.Column('wrapped_key_version', sa.String(length=10), nullable=True))
    op.alter_column('encrypted_files', 'encryption_key', nullable=True)
    op.add_column('encrypted_files', sa.Column('kek_id', sa.String(length=255), nullable=True))

def downgrade():
    op.drop_column('encrypted_files', 'kek_id')
    op.drop_column('encrypted_files', 'wrapped_key_version')
    op.drop_column('encrypted_files', 'wrapped_key')
    op.alter_column('encrypted_files', 'encryption_key', nullable=False)
```

### Migration procedure when you have existing raw DEKs
1. Deploy migration that adds `wrapped_key` and leaves `encryption_key` intact (nullable).
2. Run a migration script that, for each `EncryptedFile` row that has `encryption_key`:
   - Wrap the raw DEK using your chosen KEK (via KMS or local KEK) and store result in `wrapped_key`.
   - Optionally set `kek_id` with the KMS Key ID used.
   - Do NOT delete `encryption_key` yet — keep until you're confident everything decrypts correctly.
3. Test decryption flows across the application reading from `wrapped_key` first.
4. Once validated, remove/zero-out plaintext `encryption_key` and, in a later migration, drop the column.

Sample migration script outline (Python):
```python
# run in app context
from app import create_app, db
from app.models import EncryptedFile
from app.kms_adapters import AWSKMS

app = create_app()
with app.app_context():
    kms = AWSKMS(key_id='alias/your-kms-key')
    files = EncryptedFile.query.filter(EncryptedFile.encryption_key != None).all()
    for f in files:
        raw = f.encryption_key
        wrapped = kms.wrap(raw)
        f.wrapped_key = wrapped
        f.wrapped_key_version = 'V1'
        # optionally save KMS key id
        f.kek_id = 'alias/your-kms-key'
        db.session.add(f)
    db.session.commit()
```

## Rotation & Re-wrapping
- If the KEK must be rotated, do not re-encrypt underlying ciphertext. Instead, re-wrap DEKs by unwrapping with the old KEK and wrapping with the new KEK, or use KMS Re-encrypt APIs where available.

## Security Notes
- Do not embed AWS credentials in code. Use IAM roles or environment credentials.
- Restrict KMS key usage to only necessary principals.
- Audit KMS operations and enforce least privilege.

---

If you want, I can:
- implement an automatic registration hook so `set_kms_provider('aws')` wires `AWSKMS` into the `app.crypto_utils` provider,
- add the Alembic migration file under `migrations/versions/` using a generated revision id,
- or add a CLI script to perform the wrap-migration safely (with dry-run mode).

Tell me which of those you want next.
