# Consultant User Guide

Welcome to the Secure File Exchange System! This guide is designed for **Consultant** users who need to request access to encrypted files from organizations and decrypt them for review.

## Table of Contents
- [Getting Started](#getting-started)
- [Your Role](#your-role)
- [Registration](#registration)
- [Requesting Access](#requesting-access)
- [Viewing Your Requests](#viewing-your-requests)
- [Decrypting Keys](#decrypting-keys)
- [Downloading Files](#downloading-files)
- [Viewing Approved Files](#viewing-approved-files)
- [Understanding Your Keys](#understanding-your-keys)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Getting Started

As a Consultant user, you can:
- Browse organizations and their encrypted files
- Submit access requests for files you need to review
- Decrypt encryption keys using your private key
- Download and view decrypted files
- Track the status of all your access requests

## Your Role

**Consultants** are authorized reviewers who need temporary access to encrypted organizational data. You:
- Request access to specific files from organizations
- Wait for approval from the data owner
- Decrypt encryption keys using your private key
- Access files only while you have active approval

The system uses **asymmetric encryption** (RSA-2048) to securely receive encryption keys from organizations without exposing the keys during transmission.

## Registration

### Step 1: Create Your Account

1. Navigate to the registration page: `http://localhost:8080/register`
2. Fill in the registration form:
   - **Username**: Choose a unique username
   - **Email**: Your email address
   - **Password**: Strong password (8+ characters, mix of letters, numbers, symbols)
   - **Confirm Password**: Re-enter your password
   - **Role**: Select **"Consultant"**

3. Click **"Register"**

### Step 2: Key Generation

When you register, the system automatically:
- Generates an RSA-2048 key pair for you
- Stores your public key in the database (organizations will use this to encrypt keys for you)
- Encrypts your private key with your password
- Stores the encrypted private key securely in MongoDB

**Critical**: Your password is used to encrypt your private key. You MUST remember this password to decrypt files!

### Step 3: Login

After registration, you'll be redirected to the login page. Enter your credentials to access the system.

## Requesting Access

### Step 1: Browse Organizations

1. From your dashboard, navigate to **"Organizations"** or **"Request Access"**
2. You'll see a list of all organizations in the system
3. Click on an organization to view their available files

### Step 2: Select a File

1. Browse the organization's encrypted files
2. Each file shows:
   - **Filename**: Name of the encrypted file
   - **File Type**: Format (Excel, PDF, etc.)
   - **File Size**: Size of the encrypted file
   - **Upload Date**: When the file was uploaded
   - **Encryption Algorithm**: AES-256, DES, or RC4

### Step 3: Submit Access Request

1. Click **"Request Access"** next to the file you need
2. Optionally, add a message explaining why you need access
3. Click **"Submit Request"**

The system will:
- Create an access request with status "pending"
- Notify the organization (if notifications are enabled)
- Record the request timestamp
- Prevent duplicate requests for the same file

### What Happens Next

- The organization will review your request
- They can approve or deny your request
- You'll see the status update in your requests list
- If approved, you can proceed to decrypt the key and access the file

## Viewing Your Requests

### Access Your Requests Page

Navigate to **"My Requests"** from the main menu

### Request Status

Each request shows:
- **File Name**: The file you requested
- **Organization**: Who owns the file
- **Status**: Current status of your request
  - **Pending**: Waiting for organization review
  - **Approved**: Access granted, you can now decrypt the key
  - **Denied**: Access denied by organization
  - **Revoked**: Previously approved but access has been revoked
- **Request Date**: When you submitted the request
- **Processed Date**: When the organization approved/denied (if applicable)

### Filtering Requests

You can filter your requests by:
- **Status**: View only pending, approved, denied, or revoked requests
- **Organization**: View requests to a specific organization
- **Date Range**: View requests from a specific time period

## Decrypting Keys

Once your request is approved, you need to decrypt the encryption key before you can access the file.

### Step 1: Navigate to Approved Files

1. Go to **"Approved Files"** from the main menu
2. You'll see all files you have approved access to

### Step 2: Decrypt the Key

1. Find the file you want to access
2. Click **"Decrypt Key"**
3. Enter your password (the one you used during registration)
4. Click **"Decrypt"**

### What Happens During Decryption

The system will:
1. Retrieve your encrypted private key from MongoDB
2. Derive a decryption key from your password using PBKDF2 (100,000 iterations)
3. Decrypt your private key using AES-256-GCM
4. Retrieve the RSA-wrapped symmetric key from the access request
5. Unwrap the symmetric key using your RSA private key (RSA-OAEP SHA-256)
6. Store the decrypted symmetric key temporarily in your session
7. Clear your private key from memory
8. Log the unwrapping operation

**Security Note**: Your private key is only in memory briefly and is never stored in plaintext. The symmetric key is stored in your session only for the duration of your login.

### Decryption Status

After successful decryption:
- The file will show **"Key Decrypted"** status
- You can now download and view the file
- The key remains in your session until you log out

## Downloading Files

### Step 1: Ensure Key is Decrypted

Before downloading, make sure you've decrypted the key (see previous section)

### Step 2: Download the File

1. From the **"Approved Files"** page, click **"Download"** next to the file
2. Or navigate to the file detail page and click **"Download"**

The system will:
1. Verify you have approved (non-revoked) access
2. Retrieve the symmetric key from your session
3. Decrypt the file using the symmetric key
4. Serve the decrypted file to your browser
5. Log the download operation

### Step 3: View the File

The decrypted file will download to your browser's default download location. You can now open and review it.

## Viewing Approved Files

### Approved Files List

Navigate to **"Approved Files"** to see all files you can access:

Each file shows:
- **File Name**: Name of the file
- **Organization**: Who owns the file
- **Approval Date**: When access was granted
- **Access Status**: Active or Revoked
- **Decryption Status**: Whether you've decrypted the key
- **Actions**: Decrypt Key, Download, View Details

### File Details Page

Click on a file name to view detailed information:
- File metadata (size, type, upload date)
- Encryption algorithm used
- Your access status
- Decrypted financial data (if available and key is decrypted)
- Download option

### Revoked Access

If an organization revokes your access:
- The file will show **"Access Revoked"** status
- You cannot decrypt the key or download the file
- Any previously decrypted keys in your session are invalidated
- You'll need to submit a new access request if you need access again

## Understanding Your Keys

### Your Key Pair

When you registered, the system generated:
- **Public Key**: Stored in the database, used by organizations to encrypt keys for you
- **Private Key**: Encrypted with your password, stored in MongoDB, used by you to decrypt keys

### Viewing Your Keys

1. Navigate to **"Profile"** or **"My Keys"**
2. You'll see:
   - **Public Key Fingerprint**: SHA-256 hash of your public key (unique identifier)
   - **Key Generation Date**: When your keys were created
   - **Key Algorithm**: RSA-2048

### Key Security

- Your public key is shared with organizations (this is safe and necessary)
- Your private key is encrypted and never leaves MongoDB in plaintext
- Your password is the only way to decrypt your private key
- Your private key is only in memory briefly during key decryption
- The system never logs or stores your plaintext private key

## Best Practices

### Password Management

- **Remember your password**: You cannot decrypt files without it
- **Use a strong password**: Mix of uppercase, lowercase, numbers, and symbols
- **Don't share your password**: Your password protects your private key
- **Use a password manager**: Consider using a password manager for security
- **No password recovery**: If you forget your password, you cannot recover your private key

### Access Requests

- **Be specific in request messages**: Explain why you need access
- **Request only what you need**: Don't request access to unnecessary files
- **Respect denials**: If access is denied, respect the organization's decision
- **Complete work promptly**: Access may be time-limited

### File Handling

- **Decrypt keys when needed**: Don't decrypt keys for files you're not actively using
- **Download files securely**: Ensure you're on a secure network
- **Handle files appropriately**: Follow your organization's data handling policies
- **Delete local copies**: Remove downloaded files when no longer needed
- **Log out when done**: Always log out to clear session keys

### Security

- **Use HTTPS**: Ensure the site uses HTTPS in production
- **Secure your device**: Use device encryption and screen locks
- **Report issues**: Contact administrators if you notice problems
- **Monitor your requests**: Regularly review your access request history

## Troubleshooting

### Cannot Submit Access Request

**Problem**: "Request Access" button doesn't work or returns an error

**Solutions**:
- Check if you already have a pending or approved request for this file
- Verify you're logged in as a Consultant user
- Refresh the page and try again
- Check server logs for specific errors

### Key Decryption Fails

**Problem**: Entering password returns "Incorrect password" or decryption error

**Solutions**:
- **Double-check your password**: Ensure caps lock is off, check for typos
- **Try again**: Re-enter your password carefully
- **Password is case-sensitive**: Ensure correct capitalization
- **If you forgot your password**: Unfortunately, there is no recovery mechanism
  - You'll need to contact an administrator to reset your account
  - You'll lose access to all previously approved files
  - You'll need to re-request access after account reset

### Download Fails

**Problem**: Cannot download file or download returns an error

**Solutions**:
- Ensure you've decrypted the key first
- Verify your access hasn't been revoked
- Check that you're still logged in (session may have expired)
- Try decrypting the key again
- Refresh the page and try downloading again

### Access Revoked

**Problem**: File shows "Access Revoked" status

**Solutions**:
- This means the organization has revoked your access
- You cannot access the file anymore
- Contact the organization if you believe this is an error
- Submit a new access request if you still need access

### Session Expired

**Problem**: "Session expired" or "Please log in again" message

**Solutions**:
- Your session has timed out
- Log in again
- You'll need to decrypt keys again after logging in
- Consider completing your work in one session

### MongoDB Connection Error

**Problem**: "Cannot connect to key store" or similar error

**Solutions**:
- This is a server-side issue
- Contact your system administrator
- MongoDB may be down or misconfigured
- Wait for the issue to be resolved before attempting key decryption

## Workflow Example

Here's a typical workflow for a Consultant user:

### Scenario: Reviewing a Financial Report

1. **Register and Login**
   - Register as a Consultant user
   - System generates your RSA key pair
   - Log in with your credentials

2. **Find the File**
   - Navigate to "Organizations"
   - Select "Acme Corporation"
   - Browse their files
   - Find "Q4_2023_Financial_Report.xlsx"

3. **Request Access**
   - Click "Request Access"
   - Add message: "Need to review Q4 financials for audit"
   - Submit request

4. **Wait for Approval**
   - Check "My Requests" page
   - Status shows "Pending"
   - Wait for organization to review

5. **Access Approved**
   - Receive notification (if enabled)
   - Status changes to "Approved"
   - Navigate to "Approved Files"

6. **Decrypt the Key**
   - Click "Decrypt Key" next to the file
   - Enter your password
   - System decrypts your private key and unwraps the symmetric key
   - Status shows "Key Decrypted"

7. **Download and Review**
   - Click "Download"
   - File is decrypted and downloaded
   - Open the file in Excel
   - Review the financial data

8. **Complete Your Work**
   - Finish your review
   - Delete the local copy of the file
   - Log out (clears session keys)

## Security Reminders

- Your private key is your most sensitive asset - protect your password
- Files are encrypted with strong symmetric encryption (AES-256, DES, or RC4)
- Keys are securely wrapped with your RSA public key before transmission
- Your private key is only in memory briefly during decryption
- All cryptographic operations are logged for audit purposes
- Organizations can revoke your access at any time
- Session keys are cleared when you log out

## Getting Help

If you encounter issues:

1. **Check this guide**: Review the troubleshooting section
2. **Check your password**: Most issues are due to incorrect passwords
3. **Contact the organization**: If you have questions about access requests
4. **Contact support**: Reach out to your system administrator for technical issues
5. **Review documentation**: See [Key Management Guide](KEY_MANAGEMENT.md) for advanced topics

## Additional Resources

- [Organization User Guide](ORGANIZATION_GUIDE.md) - Understand the organization workflow
- [Key Management Guide](KEY_MANAGEMENT.md) - Advanced key management topics
- [MongoDB Setup Guide](MONGODB_SETUP.md) - Database configuration (for administrators)
- [Main README](../README.md) - System overview and installation

---

**Remember**: Your password is critical. Without it, you cannot decrypt your private key or access any files. There is no password recovery mechanism. Choose a strong password and store it securely!
