# Secure Financial Report Sharing System

[![Python](https://img.shields.io/badge/Python-3.13+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0.3-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-Educational-yellow.svg)](LICENSE)

A comprehensive secure web-based file exchange system supporting multiple encryption algorithms (AES-256, DES, RC4) for confidential financial report sharing. Built with Flask and featuring real-time performance analytics with a modern dark UI interface. Now includes **asymmetric key exchange** using RSA-2048 for secure key sharing between organizations and consultants.

## 🔐 Encryption Implementation

### Symmetric Encryption (File Data)
- **AES-256**: 256-bit key, CBC mode ✅ **Primary & Recommended**
- **DES**: 56-bit effective key, CBC mode
- **RC4**: 128-bit key, stream cipher

### Asymmetric Encryption (Key Exchange)
- **RSA-2048**: 2048-bit key pairs for secure key exchange
- Public keys stored in SQLite database
- Private keys encrypted with AES-GCM and stored in MongoDB

### Key Management Architecture
```
KEK (Key Encryption Key) → Wraps DEK
  └─> DEK (Data Encryption Key) → Encrypts File Data

RSA Public Key (Organization) → Wraps DEK for Consultant
  └─> Consultant's RSA Private Key → Unwraps DEK → Decrypts File
```

## 🔍 Viewing Keys in Database

### Quick Key Inspection
```bash
# View all keys and encryption information
python check_keys.py

# Verify encryption implementation and key sizes
python verify_encryption.py
```

📚 **Documentation:**
- [QUICK_KEY_CHECK.md](QUICK_KEY_CHECK.md) - Quick reference guide
- [docs/KEY_INSPECTION_GUIDE.md](docs/KEY_INSPECTION_GUIDE.md) - Detailed inspection guide

## Key Features

- **Multiple Encryption Algorithms**: AES-256, DES, RC4 with CBC mode support
- **Asymmetric Key Exchange**: RSA-2048 encryption for secure symmetric key sharing
- **Role-Based Access Control**: Separate workflows for Organizations and Consultants
- **Access Request System**: Formal request and approval workflow for file access
- **Secure Key Management**: Private keys encrypted and stored in MongoDB, public keys in SQLite
- **Modern Dark UI**: Clean, responsive interface with Valorant-inspired dark theme  
- **Performance Analytics**: Real-time encryption/decryption metrics and algorithm comparison
- **Secure File Sharing**: User-based access control and granular permissions
- **Encrypted Database Storage**: All sensitive data encrypted at rest with secure key management
- **Comprehensive Audit Logging**: All cryptographic operations logged for security audits
- **Responsive Design**: Mobile-friendly interface optimized for all devices
- **User Authentication**: Secure login system with password hashing and session management
- **Real-time Monitoring**: Live performance tracking and encryption statistics

## Prerequisites

- **Python 3.13+** (recommended) or 3.11+ minimum
- **MongoDB 4.4+** for private key storage
- **Git** for repository management
- **Modern web browser** (Chrome 90+, Firefox 88+, Safari 14+, Edge 90+)
- **Virtual Environment** support (venv recommended)

## Project Structure
```
secure-financial-report-sharing-bakso-kamil/
├── app/                          # Flask application package
│   ├── __init__.py               # App factory and configuration
│   ├── routes.py                 # Web routes and endpoints
│   ├── models.py                 # Database models (User, AccessRequest, CryptoLog)
│   ├── forms.py                  # WTForms for user input
│   ├── crypto_utils.py           # Symmetric encryption engine
│   ├── asymmetric_crypto.py      # RSA key generation and wrapping (NEW)
│   ├── key_store.py              # MongoDB interface for private keys (NEW)
│   ├── decorators.py             # Role-based access control decorators (NEW)
│   └── utils.py                  # Helper utilities
├── static/                       # Static assets
├── templates/                    # Jinja2 HTML templates
├── encrypted_files/              # Encrypted file storage
├── scripts/                      # Utility scripts
├── migrations/                   # Database migration scripts
├── docs/                         # Documentation (NEW)
│   ├── MONGODB_SETUP.md          # MongoDB installation and configuration
│   ├── ORGANIZATION_GUIDE.md     # User guide for organizations
│   ├── CONSULTANT_GUIDE.md       # User guide for consultants
│   └── KEY_MANAGEMENT.md         # Key management best practices
├── run.py                        # Application entry point
└── requirements.txt              # Python dependencies
```

## Quick Start Guide

### Installation & Setup

1. **Clone the repository**:
```bash
git clone https://github.com/vokalishoregmelankolis/Secure-File-Exchange.git
cd Secure-File-Exchange
```

2. **Create and activate virtual environment**:
```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# macOS/Linux
python3 -m venv .venv
source .venv/bin/activate
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Configure environment** (the `.env` file is already configured with defaults):
   - The project includes a `.env` file with MongoDB Atlas connection
   - For local development, you can use the existing configuration
   - For production, update the `.env` file with your own values:
     - `SECRET_KEY`: Your Flask secret key
     - `MONGODB_URI`: Your MongoDB connection string
     - `MONGODB_DB_NAME`: Your database name

5. **Run the application**:
```bash
python run.py
```

6. **Access the application**:
   - Open your browser and navigate to: `http://localhost:8080`
   - The application will automatically create the database on first run

### First Time Usage

1. **Register an account**:
   - Click "Register" on the homepage
   - Choose your role: **Organization** (to upload files) or **Consultant** (to request access)
   - Fill in username, email, and password
   - System automatically generates RSA-2048 key pair for you

2. **For Organizations** (File Uploaders):
   - Login with your credentials
   - Go to "Upload File" from the dashboard
   - Select a file and choose encryption algorithm (AES-256 recommended)
   - File is encrypted and stored securely
   - Manage access requests from consultants in "Access Requests"

3. **For Consultants** (File Requesters):
   - Login with your credentials
   - Browse available organizations and files
   - Submit access requests for files you need
   - Once approved, decrypt and download files from "My Approved Files"

### Running the Application

**Start the server**:
```bash
python run.py
```

The application will start on `http://localhost:8080` with the following features:
- User registration and authentication
- File upload with encryption (AES-256, DES, RC4)
- Access request workflow
- File decryption and download
- Performance analytics dashboard

**Stop the server**:
- Press `Ctrl+C` in the terminal

### MongoDB Setup (Optional)

The project is pre-configured with MongoDB Atlas (cloud). If you want to use a local MongoDB instance:

1. **Install MongoDB**:
```bash
# Ubuntu/Debian
sudo apt-get install mongodb

# macOS
brew install mongodb-community

# Windows
# Download from https://www.mongodb.com/try/download/community
```

2. **Update `.env` file**:
```bash
MONGODB_URI=mongodb://localhost:27017/keystore
MONGODB_DB_NAME=secure_file_exchange_keys
```

For detailed MongoDB setup, see [MongoDB Setup Guide](docs/MONGODB_SETUP.md)

## Usage

### Quick Start by Role

- **Organizations**: See [Organization User Guide](docs/ORGANIZATION_GUIDE.md)
- **Consultants**: See [Consultant User Guide](docs/CONSULTANT_GUIDE.md)

### 1. User Registration
- Navigate to `/register`
- Create account with username, email, and password
- **Select your role**: Organization or Consultant
- System automatically generates RSA-2048 key pair for you
- Passwords are securely hashed using scrypt
- Private key is encrypted with your password and stored in MongoDB

### 2. File Upload & Encryption (Organizations Only)
- Go to Dashboard → Upload File
- Select file (Excel, images, PDFs supported)
- Choose encryption algorithm (AES-256, DES, or RC4)
- File is encrypted with a symmetric key (DEK)
- DEK is wrapped with the master KEK and stored securely

### 3. Access Request Workflow (Consultants)
- Browse available organizations and their files
- Submit access request for specific files
- Wait for organization approval
- Once approved, decrypt the symmetric key with your password
- Download and view decrypted files

### 4. Access Request Management (Organizations)
- View pending access requests from consultants
- Review consultant information and requested files
- Approve or deny requests
- On approval, symmetric key is wrapped with consultant's RSA public key
- Revoke access at any time if needed

### 5. Key Decryption (Consultants)
- Navigate to approved files list
- Click "Decrypt Key" for a file
- Enter your password to decrypt your private key
- System unwraps the symmetric key using your RSA private key
- Symmetric key is temporarily stored in session for file access

### 6. Performance Analytics
- Visit `/performance` page
- View encryption/decryption metrics
- Compare algorithm performance

## Encryption Details

### Symmetric Encryption (File Data)
- **AES-256**: Industry standard, maximum security (CBC mode)
- **DES**: Legacy support, faster for small files (CBC mode)
- **RC4**: Stream cipher, fast continuous data processing

### Asymmetric Encryption (Key Exchange)
- **RSA-2048**: Minimum key size for secure key wrapping
- **RSA-OAEP**: Optimal Asymmetric Encryption Padding with SHA-256
- **Key Wrapping**: Symmetric keys encrypted with RSA public keys
- **Private Key Protection**: AES-256-GCM encryption with password-derived keys

### Security Features
- Non-ECB cipher modes (CBC for AES/DES)
- Secure random key generation (cryptographically secure RNG)
- Encrypted database storage (SQLite + MongoDB)
- Session-based authentication
- Role-based access control
- Password-derived key encryption (PBKDF2-HMAC-SHA256, 100,000 iterations)
- Comprehensive audit logging of all cryptographic operations
- Private key isolation (stored separately in MongoDB)
- No plaintext key exposure in database or logs

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

### Required Environment Variables
```bash
# Flask Configuration
SECRET_KEY=your-secret-key-here              # Flask session encryption
MASTER_KEY=your-master-kek-here              # KEK for wrapping symmetric keys

# MongoDB Configuration (NEW - Required)
MONGODB_URI=mongodb://username:password@localhost:27017/keystore
MONGODB_DB_NAME=secure_file_exchange_keys

# Database Configuration
DATABASE_URL=sqlite:///secure_file_exchange.db

# File Upload Configuration
UPLOAD_FOLDER=uploads
ENCRYPTED_FOLDER=encrypted_files
MAX_CONTENT_LENGTH=16777216  # 16MB
```

### Default Settings
- **Host**: 0.0.0.0 (all interfaces)
- **Port**: 8080
- **Debug**: True (development)
- **SQLite Database**: instance/secure_file_exchange.db (user data, files, requests)
- **MongoDB Database**: secure_file_exchange_keys (private keys only)

### Security Recommendations
- Use strong random values for `SECRET_KEY` and `MASTER_KEY` (32+ bytes)
- Enable MongoDB authentication in production
- Use TLS/SSL for MongoDB connections in production
- Never commit `.env` file to version control
- Rotate keys periodically (see [Key Management Guide](docs/KEY_MANAGEMENT.md))

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

### SQLite Database (Production Data)

#### Users
- id, username, email, password_hash, created_at
- **role** (NEW): organization or consultant
- **public_key** (NEW): RSA public key (PEM format)
- **public_key_fingerprint** (NEW): SHA-256 fingerprint
- **key_generated_at** (NEW): timestamp of key generation

#### EncryptedFiles
- id, file_id, filename, original_filename, file_type, file_size
- encrypted_path, algorithm, encryption_key (legacy), iv, user_id, uploaded_at
- **wrapped_key** (NEW): KEK-wrapped symmetric key
- **wrapped_key_version** (NEW): wrapping format version

#### AccessRequests (NEW)
- id, consultant_id, organization_id, file_id
- status (pending, approved, denied, revoked)
- **wrapped_symmetric_key**: RSA-wrapped DEK (after approval)
- requested_at, processed_at

#### CryptoLogs (NEW)
- id, user_id, operation, details, success, error_message
- timestamp, ip_address

#### SharedFiles
- id, file_id, recipient_id, shared_at, can_download

#### PerformanceMetrics
- id, file_id, algorithm, operation, data_type
- execution_time, input_size, output_size, timestamp

### MongoDB Database (Private Keys Only)

#### private_keys Collection
```javascript
{
  "_id": ObjectId,
  "user_id": Integer,                    // References SQLite User.id
  "encrypted_private_key": Binary,       // AES-256-GCM encrypted RSA private key
  "salt": Binary,                        // PBKDF2 salt
  "nonce": Binary,                       // AES-GCM nonce
  "algorithm": String,                   // "RSA-2048"
  "created_at": ISODate,
  "last_accessed": ISODate,
  "access_count": Integer
}
```

**Index**: `user_id` (unique)

## Development Team

**Team Name**: Bakso Kamil

**Members**:
- 5025231128 | Nadief Aqila Rabbani
- 5025231186 | Agym Kamil Ramadhan
- 5025231212 | Muhammad Rizal Hafiyyan

## Security Notes

### Key Management Architecture
- **Symmetric Keys (DEKs)**: Wrapped with KEK, stored in SQLite
- **Master KEK**: Derived from `MASTER_KEY` environment variable
- **RSA Public Keys**: Stored in SQLite (public by design)
- **RSA Private Keys**: Encrypted with password-derived keys, stored in MongoDB
- **Password Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Key Isolation**: Private keys physically separated from application data

For detailed key management practices, see [Key Management Guide](docs/KEY_MANAGEMENT.md)

### Cryptographic Standards
- **RSA**: Minimum 2048-bit keys with OAEP-SHA256 padding
- **AES**: 256-bit keys with GCM mode for authenticated encryption
- **Random Generation**: Cryptographically secure random number generators
- **No Weak Algorithms**: No ECB mode, MD5, or SHA-1

### Access Control
- **Role-Based**: Strict separation between organization and consultant capabilities
- **Request-Based**: File access only through approved access requests
- **Revocation**: Organizations can revoke access at any time
- **Audit Trail**: All cryptographic operations logged with timestamps

### Best Practices
- Regular security audits
- Input validation and sanitization
- Secure session management
- HTTPS in production (required)
- Regular dependency updates
- MongoDB authentication enabled
- Strong password policies
- Key rotation procedures (see documentation)
- Never log plaintext keys or passwords

## Documentation

Comprehensive documentation is available in the `docs/` directory:

### User Guides
- **[Organization User Guide](docs/ORGANIZATION_GUIDE.md)**: Complete guide for organizations uploading files and managing access requests
- **[Consultant User Guide](docs/CONSULTANT_GUIDE.md)**: Complete guide for consultants requesting and accessing encrypted files

### Setup and Configuration
- **[MongoDB Setup Guide](docs/MONGODB_SETUP.md)**: Installation, configuration, and troubleshooting for MongoDB
- **[Key Management Best Practices](docs/KEY_MANAGEMENT.md)**: Comprehensive guide to cryptographic key management

### Quick Links
- **New User?** Start with the user guide for your role (Organization or Consultant)
- **Setting up MongoDB?** See the [MongoDB Setup Guide](docs/MONGODB_SETUP.md)
- **Security Questions?** Review the [Key Management Guide](docs/KEY_MANAGEMENT.md)
- **Troubleshooting?** Check the troubleshooting sections in each guide

## Additional Resources

- [MongoDB Official Documentation](https://docs.mongodb.com/)
- [MongoDB Security Checklist](https://docs.mongodb.com/manual/administration/security-checklist/)
- [PyMongo Documentation](https://pymongo.readthedocs.io/)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

## License

This project is developed for educational purposes as part of cryptography coursework.

## Support

For issues or questions:
1. **Check Documentation**: Review the comprehensive guides in `docs/` directory
2. **Check Existing Issues**: Look for similar issues on GitHub
3. **Create New Issue**: Include detailed description, error messages, and steps to reproduce
4. **Contact Team**: Reach out to the development team for assistance

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