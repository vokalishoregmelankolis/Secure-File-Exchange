# MongoDB Setup Guide

This guide covers the installation and configuration of MongoDB for the Secure File Exchange System's private key storage.

## Table of Contents
- [Why MongoDB?](#why-mongodb)
- [Installation](#installation)
- [Configuration](#configuration)
- [Security Setup](#security-setup)
- [Testing Connection](#testing-connection)
- [Troubleshooting](#troubleshooting)

## Why MongoDB?

The system uses MongoDB as a separate database for storing encrypted private keys, providing:

- **Physical Isolation**: Private keys are stored separately from application data
- **Enhanced Security**: Additional layer of protection for sensitive cryptographic material
- **Scalability**: MongoDB can be easily scaled for high-volume deployments
- **Flexibility**: Document-based storage ideal for key metadata

## Installation

### Ubuntu/Debian

```bash
# Import MongoDB public GPG key
wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo apt-key add -

# Add MongoDB repository
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list

# Update package database
sudo apt-get update

# Install MongoDB
sudo apt-get install -y mongodb-org

# Start MongoDB service
sudo systemctl start mongod

# Enable MongoDB to start on boot
sudo systemctl enable mongod

# Verify installation
sudo systemctl status mongod
```

### macOS

```bash
# Install using Homebrew
brew tap mongodb/brew
brew install mongodb-community@6.0

# Start MongoDB service
brew services start mongodb-community@6.0

# Verify installation
brew services list | grep mongodb
```

### Windows

1. Download MongoDB Community Server from: https://www.mongodb.com/try/download/community
2. Run the installer (`.msi` file)
3. Choose "Complete" installation
4. Install MongoDB as a Windows Service
5. Optionally install MongoDB Compass (GUI tool)

**Start MongoDB Service:**
```cmd
net start MongoDB
```

## Configuration

### 1. Create Database and User

Connect to MongoDB shell:
```bash
mongosh
# or on older versions:
mongo
```

Create the database and user:
```javascript
// Switch to the keystore database
use secure_file_exchange_keys

// Create application user with read/write permissions
db.createUser({
  user: "sfe_app",
  pwd: "CHANGE_THIS_PASSWORD",  // Use a strong password!
  roles: [
    {
      role: "readWrite",
      db: "secure_file_exchange_keys"
    }
  ]
})

// Verify user creation
db.getUsers()

// Exit
exit
```

### 2. Enable Authentication (Production)

Edit MongoDB configuration file:

**Linux**: `/etc/mongod.conf`
**macOS**: `/usr/local/etc/mongod.conf` or `/opt/homebrew/etc/mongod.conf`
**Windows**: `C:\Program Files\MongoDB\Server\6.0\bin\mongod.cfg`

Add or modify the security section:
```yaml
security:
  authorization: enabled
```

Restart MongoDB:
```bash
# Linux
sudo systemctl restart mongod

# macOS
brew services restart mongodb-community@6.0

# Windows
net stop MongoDB
net start MongoDB
```

### 3. Configure Application Environment Variables

Create or update your `.env` file:

```bash
# MongoDB Configuration
MONGODB_URI=mongodb://sfe_app:CHANGE_THIS_PASSWORD@localhost:27017/secure_file_exchange_keys
MONGODB_DB_NAME=secure_file_exchange_keys
```

**Connection String Format:**
```
mongodb://[username]:[password]@[host]:[port]/[database]?[options]
```

**Common Options:**
- `authSource=admin` - if user is in admin database
- `ssl=true` - enable SSL/TLS
- `replicaSet=rs0` - for replica sets

### 4. Create Indexes

The application will automatically create indexes, but you can create them manually:

```javascript
use secure_file_exchange_keys

// Create unique index on user_id
db.private_keys.createIndex({ "user_id": 1 }, { unique: true })

// Verify indexes
db.private_keys.getIndexes()
```

## Security Setup

### 1. Network Security

**Bind to localhost only** (for single-server deployments):

Edit `mongod.conf`:
```yaml
net:
  bindIp: 127.0.0.1
  port: 27017
```

**For remote access**, use firewall rules:
```bash
# Ubuntu/Debian - Allow only from application server
sudo ufw allow from <app-server-ip> to any port 27017
```

### 2. Enable TLS/SSL (Production)

Generate or obtain SSL certificates, then configure:

```yaml
net:
  ssl:
    mode: requireSSL
    PEMKeyFile: /path/to/mongodb.pem
    CAFile: /path/to/ca.pem
```

Update connection string:
```bash
MONGODB_URI=mongodb://sfe_app:password@localhost:27017/secure_file_exchange_keys?ssl=true&tlsCAFile=/path/to/ca.pem
```

### 3. Enable Encryption at Rest

MongoDB Enterprise supports encryption at rest. For Community Edition, use:
- Encrypted filesystem (LUKS on Linux, FileVault on macOS, BitLocker on Windows)
- Encrypted cloud storage volumes

### 4. Regular Backups

**Create backup:**
```bash
mongodump --uri="mongodb://sfe_app:password@localhost:27017/secure_file_exchange_keys" --out=/backup/mongodb/$(date +%Y%m%d)
```

**Restore backup:**
```bash
mongorestore --uri="mongodb://sfe_app:password@localhost:27017/secure_file_exchange_keys" /backup/mongodb/20231215
```

**Automated backup script** (Linux/macOS):
```bash
#!/bin/bash
# Save as /usr/local/bin/backup-mongodb.sh

BACKUP_DIR="/backup/mongodb"
DATE=$(date +%Y%m%d_%H%M%S)
MONGODB_URI="mongodb://sfe_app:password@localhost:27017/secure_file_exchange_keys"

mkdir -p $BACKUP_DIR
mongodump --uri="$MONGODB_URI" --out="$BACKUP_DIR/$DATE"

# Keep only last 7 days of backups
find $BACKUP_DIR -type d -mtime +7 -exec rm -rf {} +
```

Add to crontab:
```bash
# Run daily at 2 AM
0 2 * * * /usr/local/bin/backup-mongodb.sh
```

## Testing Connection

### Using Python

Create a test script `test_mongodb.py`:

```python
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure
import os

def test_mongodb_connection():
    """Test MongoDB connection and permissions"""
    
    # Get connection string from environment
    mongodb_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
    db_name = os.getenv('MONGODB_DB_NAME', 'secure_file_exchange_keys')
    
    try:
        # Connect to MongoDB
        client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=5000)
        
        # Test connection
        client.admin.command('ping')
        print("✓ MongoDB connection successful")
        
        # Get database
        db = client[db_name]
        
        # Test write permission
        test_doc = {"test": "data", "timestamp": "2024-01-01"}
        result = db.test_collection.insert_one(test_doc)
        print(f"✓ Write permission verified (inserted {result.inserted_id})")
        
        # Test read permission
        found = db.test_collection.find_one({"_id": result.inserted_id})
        print(f"✓ Read permission verified (found: {found})")
        
        # Clean up
        db.test_collection.delete_one({"_id": result.inserted_id})
        print("✓ Delete permission verified")
        
        # Test index creation
        db.private_keys.create_index("user_id", unique=True)
        print("✓ Index creation successful")
        
        print("\n✅ All MongoDB tests passed!")
        return True
        
    except ConnectionFailure as e:
        print(f"❌ Connection failed: {e}")
        return False
    except OperationFailure as e:
        print(f"❌ Operation failed (check permissions): {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False
    finally:
        if 'client' in locals():
            client.close()

if __name__ == "__main__":
    test_mongodb_connection()
```

Run the test:
```bash
python test_mongodb.py
```

### Using MongoDB Shell

```bash
# Connect with authentication
mongosh "mongodb://sfe_app:password@localhost:27017/secure_file_exchange_keys"

# Test operations
use secure_file_exchange_keys

// Insert test document
db.test.insertOne({test: "data"})

// Read test document
db.test.findOne({test: "data"})

// Delete test document
db.test.deleteOne({test: "data"})

// Check collections
show collections

// Exit
exit
```

## Troubleshooting

### Connection Refused

**Problem**: `pymongo.errors.ServerSelectionTimeoutError: localhost:27017: [Errno 111] Connection refused`

**Solutions**:
1. Check if MongoDB is running:
   ```bash
   # Linux
   sudo systemctl status mongod
   
   # macOS
   brew services list | grep mongodb
   
   # Windows
   sc query MongoDB
   ```

2. Start MongoDB if not running:
   ```bash
   # Linux
   sudo systemctl start mongod
   
   # macOS
   brew services start mongodb-community@6.0
   
   # Windows
   net start MongoDB
   ```

3. Check MongoDB logs:
   ```bash
   # Linux
   sudo tail -f /var/log/mongodb/mongod.log
   
   # macOS
   tail -f /usr/local/var/log/mongodb/mongo.log
   
   # Windows
   # Check: C:\Program Files\MongoDB\Server\6.0\log\mongod.log
   ```

### Authentication Failed

**Problem**: `pymongo.errors.OperationFailure: Authentication failed`

**Solutions**:
1. Verify username and password in connection string
2. Check if user exists:
   ```javascript
   use secure_file_exchange_keys
   db.getUsers()
   ```
3. Recreate user if needed (see Configuration section)
4. Verify authentication is enabled in `mongod.conf`

### Permission Denied

**Problem**: `pymongo.errors.OperationFailure: not authorized on secure_file_exchange_keys`

**Solutions**:
1. Verify user has correct roles:
   ```javascript
   use secure_file_exchange_keys
   db.getUser("sfe_app")
   ```
2. Grant additional permissions if needed:
   ```javascript
   use secure_file_exchange_keys
   db.grantRolesToUser("sfe_app", [{role: "readWrite", db: "secure_file_exchange_keys"}])
   ```

### Port Already in Use

**Problem**: MongoDB won't start because port 27017 is in use

**Solutions**:
1. Find process using the port:
   ```bash
   # Linux/macOS
   sudo lsof -i :27017
   
   # Windows
   netstat -ano | findstr :27017
   ```
2. Kill the process or change MongoDB port in `mongod.conf`:
   ```yaml
   net:
     port: 27018  # Use different port
   ```
3. Update connection string accordingly

### Disk Space Issues

**Problem**: MongoDB fails to start due to insufficient disk space

**Solutions**:
1. Check disk space:
   ```bash
   df -h
   ```
2. Clean up old backups or logs
3. Move MongoDB data directory to larger partition:
   ```yaml
   # In mongod.conf
   storage:
     dbPath: /path/to/larger/partition/mongodb
   ```

### Slow Performance

**Solutions**:
1. Ensure indexes are created:
   ```javascript
   db.private_keys.getIndexes()
   ```
2. Monitor MongoDB performance:
   ```javascript
   db.serverStatus()
   db.currentOp()
   ```
3. Enable profiling to identify slow queries:
   ```javascript
   db.setProfilingLevel(1, { slowms: 100 })
   db.system.profile.find().sort({ts: -1}).limit(5)
   ```

## Production Checklist

Before deploying to production, ensure:

- [ ] MongoDB authentication is enabled
- [ ] Strong passwords are used for all database users
- [ ] Network access is restricted (firewall rules)
- [ ] TLS/SSL is enabled for connections
- [ ] Encryption at rest is configured
- [ ] Regular backups are scheduled and tested
- [ ] Monitoring and alerting are set up
- [ ] Connection pooling is configured in application
- [ ] Indexes are created on all collections
- [ ] Log rotation is configured
- [ ] MongoDB version is up to date with security patches

## Additional Resources

- [MongoDB Official Documentation](https://docs.mongodb.com/)
- [MongoDB Security Checklist](https://docs.mongodb.com/manual/administration/security-checklist/)
- [PyMongo Documentation](https://pymongo.readthedocs.io/)
- [MongoDB University](https://university.mongodb.com/) - Free courses

## Support

For MongoDB-specific issues:
- MongoDB Community Forums: https://www.mongodb.com/community/forums/
- Stack Overflow: Tag questions with `mongodb` and `pymongo`

For application-specific issues:
- Check application logs
- Review [Key Management Guide](KEY_MANAGEMENT.md)
- Contact development team
