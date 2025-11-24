# Fix MongoDB SSL Connection Issues

## Problem

You're seeing this error:
```
SSL handshake failed: [SSL: TLSV1_ALERT_INTERNAL_ERROR] tlsv1 alert internal error
```

This is a common issue on Windows when connecting to MongoDB Atlas with SSL/TLS.

## Quick Fixes (Try in Order)

### Fix 1: Update SSL/TLS Libraries (Recommended)

The issue is often caused by outdated SSL libraries. Update them:

```bash
# Update certifi (SSL certificates)
pip install --upgrade certifi

# Update pymongo
pip install --upgrade pymongo

# Update cryptography
pip install --upgrade cryptography

# Install additional SSL support
pip install certifi-win32
```

### Fix 2: Use Python's Certificate Store

```bash
# Install certifi-win32 to use Windows certificate store
pip install certifi-win32

# Or install python-certifi-win32
pip install python-certifi-win32
```

### Fix 3: Update Python SSL Module

If using Python 3.10 or older on Windows, you might need to update:

```bash
# Check Python version
python --version

# If < 3.11, consider upgrading Python or:
pip install --upgrade pip setuptools wheel
pip install --upgrade pyOpenSSL
```

### Fix 4: Modify Connection String (Development Only)

**⚠️ WARNING: Only for development/testing, NOT for production!**

Add `tlsAllowInvalidCertificates=true` to your connection string:

```bash
# In .env file or environment variable
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/?retryWrites=true&w=majority&tlsAllowInvalidCertificates=true
```

### Fix 5: Use Alternative DNS Resolution

MongoDB Atlas uses SRV records. Try the standard connection format:

```bash
# Instead of mongodb+srv://
# Use mongodb:// with explicit hosts

# Original (SRV):
mongodb+srv://user:pass@cluster.mongodb.net/

# Alternative (Standard):
mongodb://user:pass@cluster-shard-00-00.mongodb.net:27017,cluster-shard-00-01.mongodb.net:27017,cluster-shard-00-02.mongodb.net:27017/?ssl=true&replicaSet=atlas-xxxxx-shard-0&authSource=admin&retryWrites=true&w=majority
```

## Detailed Solutions

### Solution 1: Install/Update SSL Dependencies

```bash
# Complete SSL dependency update
pip uninstall pymongo certifi cryptography -y
pip install pymongo certifi cryptography --upgrade

# Windows-specific SSL support
pip install certifi-win32

# Verify installation
python -c "import ssl; print(ssl.OPENSSL_VERSION)"
python -c "import certifi; print(certifi.where())"
```

### Solution 2: Test Connection with Modified Settings

Create a test script to verify the fix:

```python
# test_mongodb_connection.py
from pymongo import MongoClient
import os

# Your connection string
uri = os.getenv('MONGODB_URI', 'mongodb+srv://...')

print(f"Testing connection to: {uri[:30]}...")

try:
    # Try with TLS options
    client = MongoClient(
        uri,
        tls=True,
        tlsAllowInvalidCertificates=False,  # Change to True for testing
        serverSelectionTimeoutMS=10000,
        connectTimeoutMS=10000
    )
    
    # Test connection
    client.admin.command('ping')
    print("✓ Connection successful!")
    
    # List databases
    dbs = client.list_database_names()
    print(f"✓ Available databases: {dbs}")
    
    client.close()
    
except Exception as e:
    print(f"❌ Connection failed: {e}")
    print("\nTrying with tlsAllowInvalidCertificates=True...")
    
    try:
        client = MongoClient(
            uri,
            tls=True,
            tlsAllowInvalidCertificates=True,  # Less secure, for testing only
            serverSelectionTimeoutMS=10000,
            connectTimeoutMS=10000
        )
        
        client.admin.command('ping')
        print("✓ Connection successful with relaxed TLS!")
        print("⚠️  Note: This is less secure. Update SSL certificates for production.")
        
        client.close()
        
    except Exception as e2:
        print(f"❌ Still failed: {e2}")
```

Run it:
```bash
python test_mongodb_connection.py
```

### Solution 3: Update key_store.py (Already Applied)

The `key_store.py` has been updated to include better SSL/TLS handling:

```python
# Now includes:
connection_options = {
    'tls': True,
    'tlsAllowInvalidCertificates': False,
    'retryWrites': True,
    'w': 'majority'
}
```

### Solution 4: Check Windows Firewall/Antivirus

Sometimes Windows Firewall or antivirus software blocks SSL connections:

1. **Temporarily disable antivirus** and test
2. **Add Python to firewall exceptions**:
   - Windows Security → Firewall & network protection
   - Allow an app through firewall
   - Add Python executable

### Solution 5: Use Local MongoDB (Development)

For development, use a local MongoDB instance instead of Atlas:

```bash
# Install MongoDB locally
# Download from: https://www.mongodb.com/try/download/community

# Or use Docker
docker run -d -p 27017:27017 --name mongodb mongo:latest

# Update .env
MONGODB_URI=mongodb://localhost:27017/
MONGODB_DB_NAME=secure_file_exchange_keys
```

## Verification Steps

After applying fixes, verify the connection:

```bash
# 1. Test with Python
python -c "from pymongo import MongoClient; client = MongoClient('YOUR_URI'); client.admin.command('ping'); print('Success!')"

# 2. Run the test script
python migrations/test_migration_script.py

# 3. Try the migration dry-run
python migrations/002_migrate_existing_users_keys.py --dry-run
```

## Environment-Specific Solutions

### Windows 10/11

```bash
# Update Windows SSL/TLS
# 1. Windows Update (install all updates)
# 2. Update Python SSL
pip install --upgrade pip
pip install --upgrade certifi cryptography pyOpenSSL

# 3. Install Windows certificate support
pip install certifi-win32
```

### Python Virtual Environment

```bash
# Recreate virtual environment with updated packages
deactivate
rm -rf .venv  # or: rmdir /s .venv on Windows
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -r requirements.txt
pip install --upgrade certifi cryptography pymongo
```

### MongoDB Atlas Specific

1. **Check IP Whitelist**: Ensure your IP is whitelisted in MongoDB Atlas
   - Atlas Dashboard → Network Access → Add IP Address

2. **Check Database User**: Verify credentials are correct
   - Atlas Dashboard → Database Access

3. **Check Connection String**: Use the correct format
   - Atlas Dashboard → Connect → Connect your application
   - Copy the connection string

## Production Recommendations

For production environments:

1. ✅ **Use valid SSL certificates** (don't disable certificate validation)
2. ✅ **Keep SSL libraries updated**
3. ✅ **Use connection pooling**
4. ✅ **Set appropriate timeouts**
5. ✅ **Monitor connection health**
6. ✅ **Use environment variables for credentials**

## Still Not Working?

If none of the above works, try:

### Option A: Use MongoDB Compass

Test connection with MongoDB Compass GUI:
1. Download: https://www.mongodb.com/try/download/compass
2. Connect using your URI
3. If Compass works, the issue is Python-specific

### Option B: Check Python SSL Support

```python
import ssl
import certifi

print(f"SSL Version: {ssl.OPENSSL_VERSION}")
print(f"Certifi Location: {certifi.where()}")
print(f"SSL Support: {ssl.HAS_TLSv1_3}")
```

### Option C: Use Alternative Driver

Try using `motor` (async driver) or `mongoengine`:

```bash
pip install motor
```

## Quick Test Script

Save this as `test_mongo_fix.py`:

```python
#!/usr/bin/env python
"""Quick MongoDB connection test with multiple strategies"""

import os
import sys
from pymongo import MongoClient

uri = os.getenv('MONGODB_URI', 'mongodb+srv://...')

strategies = [
    {
        'name': 'Default',
        'options': {}
    },
    {
        'name': 'With TLS',
        'options': {
            'tls': True,
            'tlsAllowInvalidCertificates': False
        }
    },
    {
        'name': 'With Relaxed TLS (Testing Only)',
        'options': {
            'tls': True,
            'tlsAllowInvalidCertificates': True
        }
    },
    {
        'name': 'With Extended Timeout',
        'options': {
            'tls': True,
            'serverSelectionTimeoutMS': 30000,
            'connectTimeoutMS': 30000
        }
    }
]

print("Testing MongoDB connection with different strategies...\n")

for strategy in strategies:
    print(f"Strategy: {strategy['name']}")
    try:
        client = MongoClient(uri, **strategy['options'])
        client.admin.command('ping')
        print(f"  ✓ SUCCESS!\n")
        client.close()
        sys.exit(0)
    except Exception as e:
        print(f"  ❌ Failed: {str(e)[:100]}...\n")

print("All strategies failed. Please check:")
print("1. MongoDB URI is correct")
print("2. IP is whitelisted in MongoDB Atlas")
print("3. SSL libraries are up to date (pip install --upgrade certifi pymongo)")
print("4. Windows firewall allows Python connections")
```

Run it:
```bash
python test_mongo_fix.py
```

## Summary

**Most Common Fix (90% of cases):**
```bash
pip install --upgrade certifi pymongo cryptography
pip install certifi-win32
```

**Quick Test:**
```bash
python -c "from pymongo import MongoClient; MongoClient('YOUR_URI', tls=True).admin.command('ping'); print('OK')"
```

**If Still Failing:**
- Use local MongoDB for development
- Contact MongoDB Atlas support
- Check Windows SSL/TLS settings
