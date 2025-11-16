# Secure Financial Report Sharing System

[![Python](https://img.shields.io/badge/Python-3.13+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0.3-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-Educational-yellow.svg)](LICENSE)

A comprehensive secure web-based file exchange system supporting multiple encryption algorithms (AES-256, DES, RC4) for confidential financial report sharing. Built with Flask and featuring real-time performance analytics with a modern dark UI interface.

## Key Features

- **Multiple Encryption Algorithms**: AES-256, DES, RC4 with CBC mode support
- **Modern Dark UI**: Clean, responsive interface with Valorant-inspired dark theme  
- **Performance Analytics**: Real-time encryption/decryption metrics and algorithm comparison
- **Secure File Sharing**: User-based access control and granular permissions
- **Encrypted Database Storage**: All sensitive data encrypted at rest with secure key management
- **Responsive Design**: Mobile-friendly interface optimized for all devices
- **User Authentication**: Secure login system with password hashing and session management
- **Real-time Monitoring**: Live performance tracking and encryption statistics

## Prerequisites

- **Python 3.13+** (recommended) or 3.11+ minimum
- **Git** for repository management
- **Modern web browser** (Chrome 90+, Firefox 88+, Safari 14+, Edge 90+)
- **Virtual Environment** support (venv recommended)

## Project Structure
```
secure-financial-report-sharing-bakso-kamil/
├── app/                          # Flask application package
│   ├── __init__.py               # App factory and configuration
│   ├── routes.py                 # Web routes and endpoints
│   ├── models.py                 # Database models
│   ├── forms.py                  # WTForms for user input
│   ├── crypto_utils.py           # Encryption/decryption engine
│   └── utils.py                  # Helper utilities
├── static/                       # Static assets
├── templates/                    # Jinja2 HTML templates
├── encrypted_files/              # Encrypted file storage
├── scripts/                      # Utility scripts
├── run.py                        # Application entry point
└── requirements.txt              # Python dependencies
```

## Installation

1. **Clone the repository**:
```bash
git clone https://github.com/ericatriana/WEBPRO-MIDTERM.git
cd secure-financial-report-sharing-bakso-kamil
```

2. **Create virtual environment**:
```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# macOS/Linux
python3 -m venv .venv
source .venv/bin/activate
```

3. **Install dependencies** (Python 3.13 compatible):
```bash
pip install -r requirements.txt
```

**Note**: The requirements.txt has been updated with Python 3.13 compatible versions:
- Flask 3.0.3
- pandas 2.2.3 
- pycryptodome 3.20.0
- And other updated dependencies

4. **Run the application**:
```bash
python run.py
```

5. **Open in browser**:
```
http://localhost:8080
```

## Usage

### 1. User Registration
- Navigate to `/register`
- Create account with username, email, and password
- Passwords are securely hashed using scrypt

### 2. File Upload & Encryption
- Go to Dashboard → Upload File
- Select file (Excel, images, PDFs supported)
- Choose encryption algorithm (AES-256, DES, or RC4)
- File is encrypted and stored securely

### 3. File Sharing
- From file details page, click "Share File"
- Enter recipient username
- Recipient gains access to view and download

### 4. Performance Analytics
- Visit `/performance` page
- View encryption/decryption metrics
- Compare algorithm performance

## Encryption Details

### Supported Algorithms
- **AES-256**: Industry standard, maximum security (CBC mode)
- **DES**: Legacy support, faster for small files (CBC mode)
- **RC4**: Stream cipher, fast continuous data processing

### Security Features
- Non-ECB cipher modes (CBC for AES/DES)
- Secure random key generation
- Encrypted database storage
- Session-based authentication

## Recent Revisions — Key Management & Ciphertext Format

This project was updated to improve key handling, make key storage safer, and produce a self-describing ciphertext envelope. Summary of the three main changes requested and implemented:

1) Mengecek iki (parse key)
- Added `parse_key(...)` utility in `app/crypto_utils.py`.
- `parse_key` accepts raw bytes, base64 strings, hex strings, or a passphrase and will:
   - detect and decode hex and base64 encodings,
   - derive a key from a passphrase using PBKDF2 (PyCryptodome HMAC-SHA256) when an `expected_length` is provided.
- Use cases: normalize keys supplied by users or migration scripts before using them as DEKs or KEKs.

2) Revisi mekanisme penyimpanan key file (move to KMS / key wrapping)
- Instead of storing raw data-encryption-keys (DEKs) directly in the database, the app now stores KEK-wrapped DEKs in the `wrapped_key` column of `EncryptedFile` (see `app/models.py`). The legacy `encryption_key` column is retained for backward compatibility and is nullable.
- Implementation details:
   - A KMS interface abstraction (`KMSInterface`) was added to `app/crypto_utils.py` with two providers:
      - `EnvKMS` — default provider that derives a KEK from the `MASTER_KEY` environment variable and wraps DEKs using AES-GCM.
      - `StubKMS` — thin stub useful for tests.
   - Wrapping format (internal): versioned binary blob. The current version is `V1`. The blob encodes nonce and tag lengths so IV/tag sizes are parsed reliably.
   - Use `set_kms_provider('stub'|'env')` if tests or a different provider is required.
- Configuration: set a strong `MASTER_KEY` in environment for production. For local development tests, a deterministic fallback exists, but DO NOT use that in production.

3) Resulting ciphertext (envelope format)
- Encryption outputs are now packable into a JSON envelope using `pack_ciphertext(...)` and unpacked with `unpack_ciphertext(...)` in `app/crypto_utils.py`.
- Envelope fields (JSON, base64-encoded bytes):
   - `version` — envelope version ("1")
   - `algorithm` — string (e.g., "AES")
   - `iv` — base64 IV (nullable)
   - `wrapped_key` — base64 wrapped DEK blob (nullable)
   - `wrapped_key_version` — string or null
   - `ciphertext` — base64 ciphertext payload
- This makes ciphertext self-describing and portable. You can store the envelope as a single blob or file, or keep metadata columns and the ciphertext separately in the DB.

Developer / Migration notes
- The code keeps backward compatibility:
   - On decryption, the app prefers `wrapped_key` (new) and falls back to `encryption_key` (legacy) if needed.
   - `encryption_key` was made nullable to allow new uploads to omit storing raw keys.
- Recommended production steps:
   1. Integrate with a real KMS (AWS KMS, GCP KMS, Azure Key Vault) by implementing a new `KMSInterface` adapter that performs wrap/unwrap via the provider; update `set_kms_provider` and configuration to use it.
   2. Add a `kek_id` or `kms_key_id` column to `EncryptedFile` to track which KMS key/version encrypted each wrapped DEK (useful for rotation).
   3. Create a migration (Alembic / Flask-Migrate) to add `wrapped_key` and `wrapped_key_version` columns and to migrate existing `encryption_key` values by wrapping them with the KEK (or storing them in KMS) if you need to preserve access.
   4. Re-wrap keys during KEK rotation using the KMS re-encrypt API or a safe unwrap/rewrap process.

Quick examples
- Pack ciphertext (to store or export):
```python
from app.crypto_utils import pack_ciphertext
# encrypted_data, wrapped_key, iv obtained from CryptoEngine.encrypt_file
envelope_bytes = pack_ciphertext(encrypted_data, 'AES', iv, wrapped_key, 'V1')
```

- Unpack ciphertext and decrypt:
```python
from app.crypto_utils import unpack_ciphertext, CryptoEngine
ct, algo, iv, wrapped, wkver = unpack_ciphertext(envelope_bytes)
# CryptoEngine.decrypt_file handles unwrap internally
plaintext, exec_time = CryptoEngine.decrypt_file(ct, algo, wrapped, iv)
```

These revisions improve key confidentiality (no raw DEKs stored in DB), enable future KMS integration, and make ciphertext portable and self-describing.

## Environment Configuration
```bash
# Optional configuration
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///secure_file_exchange.db
UPLOAD_FOLDER=uploads
ENCRYPTED_FOLDER=encrypted_files
MAX_CONTENT_LENGTH=16777216  # 16MB
```

### Default Settings
- **Host**: 0.0.0.0 (all interfaces)
- **Port**: 8080
- **Debug**: True (development)
- **Database**: SQLite (instance/secure_file_exchange.db)

## Verification Tools

### Check Encryption Script
```bash
python scripts/check_encryption.py
```
- Lists all encrypted files in database
- Verifies encryption integrity
- Shows file statistics and metadata

### User Management Scripts
```bash
# View registered users
python view_users.py

# Reset user password
python reset_password.py
```

## Database Schema

### Users
- id, username, email, password_hash, created_at

### EncryptedFiles
- id, file_id, filename, original_filename, file_type, file_size
- encrypted_path, algorithm, encryption_key, iv, user_id, uploaded_at

### SharedFiles
- id, file_id, recipient_id, shared_at, can_download

### PerformanceMetrics
- id, file_id, algorithm, operation, data_type
- execution_time, input_size, output_size, timestamp

## Development Team

**Team Name**: Bakso Kamil

**Members**:
- 5025231128 | Nadief Aqila Rabbani
- 5025231186 | Agym Kamil Ramadhan
- 5025231212 | Muhammad Rizal Hafiyyan

## Security Notes

### Key Management
- Keys stored in database for development/testing
- Production deployment should use proper Key Management System (KMS)
- Consider implementing key derivation functions for enhanced security

### Best Practices
- Regular security audits
- Input validation and sanitization
- Secure session management
- HTTPS in production
- Regular dependency updates

## License

This project is developed for educational purposes as part of cryptography coursework.

## Support

For issues or questions:
1. Check existing GitHub issues
2. Create new issue with detailed description
3. Include error messages and steps to reproduce

---

**Note**: This application is designed for educational purposes. For production use, implement additional security measures including proper key management, HTTPS, and comprehensive security auditing.

## Troubleshooting

### Common Issues

1. **Python 3.13 Compatibility Issues**:
   - Make sure to use the updated `requirements.txt`
   - If you encounter build errors, try upgrading pip: `pip install --upgrade pip`

2. **Package Installation Errors**:
   ```bash
   # Clear pip cache and reinstall
   pip cache purge
   pip install -r requirements.txt --no-cache-dir
   ```

3. **Database error**:
   - Delete `instance/secure_file_exchange.db`
   - Restart the application (database will be recreated)

4. **File upload fails**:
   - Check file size (max 16MB)
   - Ensure `uploads/` and `encrypted_files/` directories exist
   - Check file permissions

5. **Permission denied on Windows**:
   - Run terminal as administrator
   - Check folder permissions

6. **Virtual Environment Issues**:
   ```bash
   # Recreate virtual environment
   deactivate
   rm -rf .venv  # or rmdir /s .venv on Windows
   python -m venv .venv
   source .venv/bin/activate  # or .venv\Scripts\activate on Windows
   pip install -r requirements.txt
   ```

## Stopping the Application

- Press `Ctrl+C` in the terminal to stop the Flask development server

## Resetting the Database

If you want to start fresh:
```bash
# Delete the database file
rm instance/secure_file_exchange.db  # Linux/Mac
del instance\secure_file_exchange.db  # Windows

# Restart the application
python run.py
```

## Development Notes

- The application runs in debug mode by default for development
- Database files are stored in the `instance/` folder (ignored by git)
- Uploaded files are stored in `uploads/` (ignored by git)
- Encrypted files are stored in `encrypted_files/` (ignored by git)
- Virtual environment `.venv/` is ignored by git