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

- **Python 3.11+** 
- **Git** for repository management
- **Modern web browser**

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

## Security Features

- **AES-256, DES, RC4** encryption algorithms
- **RSA-2048** asymmetric key exchange
- Role-based access control
- Encrypted database storage (SQLite + MongoDB)
- Session-based authentication
- Comprehensive audit logging

## Development Team

**Team Name**: Bakso Kamil

**Members**:
- 5025231128 | Nadief Aqila Rabbani
- 5025231186 | Agym Kamil Ramadhan
- 5025231212 | Muhammad Rizal Hafiyyan

## Documentation

For detailed guides, see the `docs/` directory:
- [Organization User Guide](docs/ORGANIZATION_GUIDE.md)
- [Consultant User Guide](docs/CONSULTANT_GUIDE.md)
- [MongoDB Setup Guide](docs/MONGODB_SETUP.md)

## License

This project is developed for educational purposes as part of cryptography coursework.

## Troubleshooting

**Database error**: Delete `instance/secure_file_exchange.db` and restart

**Package installation error**: 
```bash
pip install --upgrade pip
pip install -r requirements.txt --no-cache-dir
```

**Stop the server**: Press `Ctrl+C` in terminal