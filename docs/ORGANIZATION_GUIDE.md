# Organization User Guide

Welcome to the Secure File Exchange System! This guide is designed for **Organization** users who need to upload encrypted files and manage access requests from consultants.

## Table of Contents
- [Getting Started](#getting-started)
- [Your Role](#your-role)
- [Registration](#registration)
- [Uploading Files](#uploading-files)
- [Managing Access Requests](#managing-access-requests)
- [Revoking Access](#revoking-access)
- [Viewing Your Keys](#viewing-your-keys)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Getting Started

As an Organization user, you can:
- Upload and encrypt confidential financial reports
- View and manage access requests from consultants
- Approve or deny access to your encrypted files
- Revoke access at any time
- Monitor all access through audit logs

## Your Role

**Organizations** are the data owners in this system. You:
- Control who can access your encrypted files
- Securely share encryption keys with approved consultants
- Maintain full control over your data at all times

The system uses **asymmetric encryption** (RSA-2048) to securely share your file encryption keys with consultants without exposing the keys during transmission or storage.

## Registration

### Step 1: Create Your Account

1. Navigate to the registration page: `http://localhost:8080/register`
2. Fill in the registration form:
   - **Username**: Choose a unique username
   - **Email**: Your email address
   - **Password**: Strong password (8+ characters, mix of letters, numbers, symbols)
   - **Confirm Password**: Re-enter your password
   - **Role**: Select **"Organization"**

3. Click **"Register"**

### Step 2: Key Generation

When you register, the system automatically:
- Generates an RSA-2048 key pair for you
- Stores your public key in the database
- Encrypts your private key with your password
- Stores the encrypted private key securely in MongoDB

**Important**: Your password is used to encrypt your private key. If you forget your password, you cannot recover your private key!

### Step 3: Login

After registration, you'll be redirected to the login page. Enter your credentials to access the system.

## Uploading Files

### Step 1: Navigate to Upload Page

From your dashboard, click **"Upload File"** or navigate to `/upload`

### Step 2: Select File and Encryption Algorithm

1. **Choose File**: Click "Choose File" and select your financial report
   - Supported formats: Excel (.xlsx, .xls), PDF, images, text files
   - Maximum size: 16 MB

2. **Select Encryption Algorithm**:
   - **AES-256** (Recommended): Industry standard, maximum security
   - **DES**: Legacy support, faster for small files
   - **RC4**: Stream cipher, fast for continuous data

3. **Click "Upload and Encrypt"**

### Step 3: Encryption Process

The system will:
1. Generate a random symmetric key (DEK) for your file
2. Encrypt your file with the DEK using the selected algorithm
3. Wrap the DEK with the master KEK (Key Encryption Key)
4. Store the encrypted file and wrapped key securely
5. Log the encryption operation

### Step 4: View Your Files

After upload, you can:
- View file details from your dashboard
- See encryption algorithm used
- Check file size and upload date
- View who has requested or been granted access

## Managing Access Requests

### Viewing Pending Requests

1. Navigate to **"Access Requests"** from the main menu
2. You'll see a list of all pending requests for your files

Each request shows:
- **Consultant Name**: Who is requesting access
- **File Name**: Which file they want to access
- **Request Date**: When the request was submitted
- **Request Message**: Optional message from the consultant

### Approving Access Requests

When you approve a request, the system performs secure key exchange:

1. Click **"Approve"** next to the request
2. The system will:
   - Retrieve the wrapped symmetric key for the file
   - Unwrap it using the master KEK
   - Retrieve the consultant's RSA public key
   - Wrap the symmetric key with the consultant's public key (RSA-OAEP SHA-256)
   - Store the wrapped key in the access request record
   - Update the request status to "approved"
   - Log the key wrapping operation

3. The consultant can now decrypt the key using their private key

**Security Note**: At no point is the symmetric key exposed in plaintext. It goes directly from KEK-wrapped to RSA-wrapped.

### Denying Access Requests

If you don't want to grant access:

1. Click **"Deny"** next to the request
2. The request status will be updated to "denied"
3. The consultant will see the denial status
4. No encryption keys are shared

### Filtering Requests

You can filter requests by:
- **Status**: Pending, Approved, Denied, Revoked
- **File**: View requests for a specific file
- **Consultant**: View all requests from a specific consultant

## Revoking Access

You can revoke access at any time, even after approval:

### Step 1: View Approved Requests

1. Navigate to **"Access Requests"**
2. Filter by status: **"Approved"**

### Step 2: Revoke Access

1. Click **"Revoke"** next to the approved request
2. Confirm the revocation

The system will:
- Update the request status to "revoked"
- Delete the wrapped symmetric key from the database
- Invalidate any cached keys in the consultant's session
- Log the revocation operation

### Effect of Revocation

After revocation:
- The consultant can no longer download or decrypt the file
- Any attempt to access the file will be denied
- The consultant will see "Access Revoked" status
- You can re-approve the request later if needed

## Viewing Your Keys

### Public Key Information

1. Navigate to **"Profile"** or **"My Keys"**
2. You'll see:
   - **Public Key Fingerprint**: SHA-256 hash of your public key
   - **Key Generation Date**: When your keys were created
   - **Key Algorithm**: RSA-2048

### Key Security

- Your **public key** is stored in the database and shared with consultants
- Your **private key** is encrypted with your password and stored in MongoDB
- Your private key is never used by the organization workflow
- Only consultants need to decrypt their private keys to access files

## Best Practices

### Password Management

- **Use a strong password**: Mix of uppercase, lowercase, numbers, and symbols
- **Don't share your password**: Your password protects your private key
- **Don't reuse passwords**: Use a unique password for this system
- **Use a password manager**: Consider using a password manager for security

### Access Control

- **Review requests carefully**: Check consultant identity before approving
- **Approve only necessary access**: Grant access on a need-to-know basis
- **Revoke when no longer needed**: Remove access when the consultant's work is complete
- **Monitor access logs**: Regularly review who has accessed your files

### File Management

- **Use descriptive filenames**: Make it easy to identify files
- **Choose appropriate encryption**: AES-256 for maximum security
- **Regular backups**: Keep backups of important files
- **Clean up old files**: Delete files that are no longer needed

### Security

- **Log out when done**: Always log out after your session
- **Use HTTPS in production**: Ensure the site uses HTTPS
- **Report suspicious activity**: Contact administrators if you notice unusual access patterns
- **Keep software updated**: Ensure you're using the latest version

## Troubleshooting

### File Upload Fails

**Problem**: File upload returns an error

**Solutions**:
- Check file size (must be under 16 MB)
- Verify file format is supported
- Ensure you have sufficient disk space
- Check server logs for specific errors

### Cannot See Access Requests

**Problem**: Access requests page is empty

**Solutions**:
- Verify you're logged in as an Organization user
- Check if any consultants have submitted requests
- Refresh the page
- Check filters (ensure "All" or "Pending" is selected)

### Approval Fails

**Problem**: Clicking "Approve" returns an error

**Solutions**:
- Verify the consultant has a valid public key
- Check server logs for specific errors
- Ensure MongoDB is running and accessible
- Try refreshing the page and approving again

### Key Generation Failed During Registration

**Problem**: Registration fails with key generation error

**Solutions**:
- Ensure MongoDB is running and accessible
- Check MongoDB connection settings in `.env`
- Verify sufficient system entropy for key generation
- Try registering again

### Forgot Password

**Problem**: Cannot remember password

**Solutions**:
- **Important**: There is no password recovery mechanism
- Your private key is encrypted with your password
- If you forget your password, you cannot decrypt your private key
- However, as an Organization user, you don't need your private key for normal operations
- You can continue uploading files and managing access requests
- Contact an administrator if you need to reset your account

## Workflow Example

Here's a typical workflow for an Organization user:

### Scenario: Sharing a Financial Report with a Consultant

1. **Upload the Report**
   - Log in to the system
   - Navigate to Upload page
   - Select your financial report (e.g., `Q4_2023_Report.xlsx`)
   - Choose AES-256 encryption
   - Click "Upload and Encrypt"

2. **Receive Access Request**
   - Consultant "john_consultant" submits an access request
   - You receive a notification (or see it in Access Requests page)
   - Request shows: "John Consultant requests access to Q4_2023_Report.xlsx"

3. **Review and Approve**
   - Navigate to Access Requests page
   - Review John's request and credentials
   - Click "Approve"
   - System securely wraps the encryption key with John's public key

4. **Consultant Accesses File**
   - John decrypts the key using his password and private key
   - John downloads and views the decrypted report
   - All operations are logged in the audit trail

5. **Revoke Access When Complete**
   - After John completes his work, you revoke his access
   - Navigate to Access Requests → Approved
   - Click "Revoke" next to John's request
   - John can no longer access the file

## Security Reminders

- Your files are encrypted with strong symmetric encryption (AES-256, DES, or RC4)
- Encryption keys are never stored in plaintext
- Keys are securely wrapped before sharing with consultants
- You maintain full control over who can access your files
- All cryptographic operations are logged for audit purposes
- Private keys are isolated in a separate MongoDB database

## Getting Help

If you encounter issues:

1. **Check this guide**: Review the troubleshooting section
2. **Check server logs**: Look for error messages in application logs
3. **Contact support**: Reach out to your system administrator
4. **Review documentation**: See [Key Management Guide](KEY_MANAGEMENT.md) for advanced topics

## Additional Resources

- [Consultant User Guide](CONSULTANT_GUIDE.md) - Understand the consultant workflow
- [Key Management Guide](KEY_MANAGEMENT.md) - Advanced key management topics
- [MongoDB Setup Guide](MONGODB_SETUP.md) - Database configuration
- [Main README](../README.md) - System overview and installation

---

**Remember**: You are the data owner. You control access to your files at all times. The system is designed to give you maximum security and control while enabling secure collaboration with consultants.
