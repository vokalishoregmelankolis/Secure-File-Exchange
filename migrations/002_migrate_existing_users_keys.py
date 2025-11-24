"""
Data Migration Script for Existing Users - RSA Key Generation

This script generates RSA key pairs for existing users who don't have keys yet.
It prompts for a password to encrypt private keys and stores them securely.

Features:
- Creates database backup before migration
- Generates RSA keys for users without keys
- Encrypts private keys with user-provided password
- Stores public keys in SQLite
- Stores encrypted private keys in MongoDB
- Logs all key generation operations
- Handles errors gracefully with rollback capability

Requirements: 4.1, 4.2, 4.3, 4.4

Usage:
    python migrations/002_migrate_existing_users_keys.py
    python migrations/002_migrate_existing_users_keys.py --dry-run
"""

import sys
import os
import shutil
import getpass
from datetime import datetime
from pathlib import Path

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app, db
from app.models import User, CryptoLog, UserRole
from app.asymmetric_crypto import AsymmetricCrypto
from app.key_store import KeyStore
from pymongo.errors import ConnectionFailure


class MigrationError(Exception):
    """Custom exception for migration errors"""
    pass


class UserKeyMigration:
    """Handles the migration of RSA keys for existing users"""
    
    def __init__(self, app, dry_run=False):
        self.app = app
        self.dry_run = dry_run
        self.key_store = None
        self.backup_path = None
        self.migrated_users = []
        self.failed_users = []
        
    def create_backup(self):
        """Create a backup of the SQLite database"""
        print("\n" + "="*70)
        print("STEP 1: Creating Database Backup")
        print("="*70)
        
        try:
            # Get database path
            db_uri = self.app.config['SQLALCHEMY_DATABASE_URI']
            if not db_uri.startswith('sqlite:///'):
                raise MigrationError("This script only supports SQLite databases")
            
            db_path = db_uri.replace('sqlite:///', '')
            if not os.path.isabs(db_path):
                # Relative path - make it absolute relative to app root
                db_path = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    'instance',
                    db_path
                )
            
            if not os.path.exists(db_path):
                raise MigrationError(f"Database file not found: {db_path}")
            
            # Create backup with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.backup_path = f"{db_path}.backup_{timestamp}"
            
            if self.dry_run:
                print(f"[DRY RUN] Would create backup: {self.backup_path}")
            else:
                shutil.copy2(db_path, self.backup_path)
                print(f"✓ Backup created: {self.backup_path}")
                print(f"  Original size: {os.path.getsize(db_path):,} bytes")
                print(f"  Backup size: {os.path.getsize(self.backup_path):,} bytes")
            
            return True
            
        except Exception as e:
            raise MigrationError(f"Failed to create backup: {e}")
    
    def connect_mongodb(self):
        """Initialize MongoDB connection"""
        print("\n" + "="*70)
        print("STEP 2: Connecting to MongoDB")
        print("="*70)
        
        try:
            mongodb_uri = self.app.config.get('MONGODB_URI')
            mongodb_db = self.app.config.get('MONGODB_DB_NAME')
            
            print(f"MongoDB URI: {mongodb_uri}")
            print(f"Database: {mongodb_db}")
            
            if self.dry_run:
                print("[DRY RUN] Would connect to MongoDB")
                return True
            
            self.key_store = KeyStore(mongodb_uri, mongodb_db)
            print("✓ Successfully connected to MongoDB")
            return True
            
        except ConnectionFailure as e:
            raise MigrationError(f"Failed to connect to MongoDB: {e}")
        except Exception as e:
            raise MigrationError(f"Unexpected error connecting to MongoDB: {e}")
    
    def get_users_without_keys(self):
        """Find all users who don't have RSA keys"""
        print("\n" + "="*70)
        print("STEP 3: Identifying Users Without Keys")
        print("="*70)
        
        try:
            # Query users without public keys
            users = User.query.filter(
                (User.public_key == None) | (User.public_key_fingerprint == None)
            ).all()
            
            print(f"Found {len(users)} user(s) without RSA keys:")
            for user in users:
                role = user.role.value if user.role else 'unknown'
                print(f"  - ID: {user.id}, Username: {user.username}, Role: {role}")
            
            return users
            
        except Exception as e:
            raise MigrationError(f"Failed to query users: {e}")
    
    def prompt_for_password(self):
        """Prompt user for password to encrypt private keys"""
        print("\n" + "="*70)
        print("STEP 4: Password Setup")
        print("="*70)
        print("Enter a password to encrypt all private keys.")
        print("This password will be used for all users in this migration.")
        print("Users can change their password later through the application.")
        print()
        
        if self.dry_run:
            print("[DRY RUN] Would prompt for password")
            return "dry-run-password"
        
        while True:
            password = getpass.getpass("Enter password: ")
            if not password:
                print("❌ Password cannot be empty. Please try again.")
                continue
            
            if len(password) < 8:
                print("❌ Password must be at least 8 characters. Please try again.")
                continue
            
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("❌ Passwords do not match. Please try again.")
                continue
            
            return password
    
    def generate_keys_for_user(self, user, password):
        """Generate and store RSA keys for a single user"""
        try:
            print(f"\n  Processing user: {user.username} (ID: {user.id})")
            
            # Generate RSA key pair
            print("    - Generating RSA-2048 key pair...")
            public_key_pem, private_key_pem = AsymmetricCrypto.generate_rsa_keypair()
            
            # Generate public key fingerprint
            print("    - Generating public key fingerprint...")
            fingerprint = AsymmetricCrypto.get_public_key_fingerprint(public_key_pem)
            
            # Encrypt private key with password
            print("    - Encrypting private key...")
            encrypted_key, salt, nonce = AsymmetricCrypto.encrypt_private_key(
                private_key_pem, password
            )
            
            if self.dry_run:
                print("    [DRY RUN] Would store keys in databases")
                print(f"    [DRY RUN] Public key fingerprint: {fingerprint[:16]}...")
                return True
            
            # Store public key in SQLite
            print("    - Storing public key in SQLite...")
            user.public_key = public_key_pem
            user.public_key_fingerprint = fingerprint
            user.key_generated_at = datetime.utcnow()
            
            # Store encrypted private key in MongoDB
            print("    - Storing encrypted private key in MongoDB...")
            metadata = {
                'algorithm': 'RSA-2048',
                'migration_batch': datetime.utcnow().isoformat(),
                'migration_script': '002_migrate_existing_users_keys.py'
            }
            self.key_store.store_private_key(
                user.id,
                encrypted_key,
                salt,
                nonce,
                metadata
            )
            
            # Log the operation
            print("    - Logging key generation...")
            log_entry = CryptoLog(
                user_id=user.id,
                operation='keypair_generated',
                details=f'RSA-2048 key pair generated during migration for user {user.username}',
                success=True,
                ip_address='127.0.0.1'  # Migration script
            )
            db.session.add(log_entry)
            
            # Commit changes
            db.session.commit()
            
            print(f"    ✓ Successfully generated keys for {user.username}")
            print(f"      Fingerprint: {fingerprint[:32]}...")
            
            self.migrated_users.append(user.username)
            return True
            
        except Exception as e:
            print(f"    ❌ Failed to generate keys for {user.username}: {e}")
            db.session.rollback()
            self.failed_users.append((user.username, str(e)))
            return False
    
    def migrate_users(self, users, password):
        """Generate keys for all users"""
        print("\n" + "="*70)
        print("STEP 5: Generating Keys for Users")
        print("="*70)
        
        if not users:
            print("No users to migrate.")
            return True
        
        print(f"Generating RSA keys for {len(users)} user(s)...")
        
        for i, user in enumerate(users, 1):
            print(f"\n[{i}/{len(users)}]", end=" ")
            self.generate_keys_for_user(user, password)
        
        return True
    
    def print_summary(self):
        """Print migration summary"""
        print("\n" + "="*70)
        print("MIGRATION SUMMARY")
        print("="*70)
        
        if self.dry_run:
            print("\n[DRY RUN MODE] No changes were made to the database.")
        
        print(f"\n✓ Successfully migrated: {len(self.migrated_users)} user(s)")
        if self.migrated_users:
            for username in self.migrated_users:
                print(f"  - {username}")
        
        if self.failed_users:
            print(f"\n❌ Failed migrations: {len(self.failed_users)} user(s)")
            for username, error in self.failed_users:
                print(f"  - {username}: {error}")
        
        if self.backup_path and not self.dry_run:
            print(f"\n📁 Backup location: {self.backup_path}")
            print("   Keep this backup until you verify the migration was successful.")
        
        print("\n" + "="*70)
        
        if self.failed_users:
            print("\n⚠️  Some users failed to migrate. Please review the errors above.")
            return False
        
        if not self.dry_run and self.migrated_users:
            print("\n✓ Migration completed successfully!")
            print("\nNext steps:")
            print("1. Verify that users can log in and access their keys")
            print("2. Test key operations (encryption, decryption)")
            print("3. If everything works, you can delete the backup file")
        
        return True
    
    def cleanup(self):
        """Clean up resources"""
        if self.key_store:
            self.key_store.close()
    
    def run(self):
        """Execute the migration"""
        try:
            print("\n" + "="*70)
            print("RSA KEY MIGRATION FOR EXISTING USERS")
            print("="*70)
            
            if self.dry_run:
                print("\n⚠️  DRY RUN MODE - No changes will be made")
            
            # Step 1: Create backup
            self.create_backup()
            
            # Step 2: Connect to MongoDB
            self.connect_mongodb()
            
            # Step 3: Get users without keys
            users = self.get_users_without_keys()
            
            if not users:
                print("\n✓ All users already have RSA keys. No migration needed.")
                return True
            
            # Step 4: Get password
            password = self.prompt_for_password()
            
            # Step 5: Migrate users
            self.migrate_users(users, password)
            
            # Print summary
            success = self.print_summary()
            
            return success
            
        except MigrationError as e:
            print(f"\n❌ Migration Error: {e}")
            return False
        except KeyboardInterrupt:
            print("\n\n⚠️  Migration interrupted by user")
            return False
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            self.cleanup()


def main():
    """Main entry point"""
    # Check for dry-run flag
    dry_run = '--dry-run' in sys.argv
    
    # Create Flask app
    app = create_app()
    
    with app.app_context():
        # Run migration
        migration = UserKeyMigration(app, dry_run=dry_run)
        success = migration.run()
        
        # Exit with appropriate code
        sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
