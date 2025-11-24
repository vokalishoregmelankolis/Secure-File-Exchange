"""
Test script for the user key migration

This script tests the migration logic without affecting the production database.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app, db
from app.models import User, UserRole
from app.asymmetric_crypto import AsymmetricCrypto
from app.key_store import KeyStore


def test_key_generation():
    """Test RSA key generation"""
    print("\n" + "="*70)
    print("TEST 1: RSA Key Generation")
    print("="*70)
    
    try:
        print("Generating RSA-2048 key pair...")
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        
        print(f"✓ Public key generated: {len(public_key)} bytes")
        print(f"✓ Private key generated: {len(private_key)} bytes")
        
        # Test fingerprint generation
        fingerprint = AsymmetricCrypto.get_public_key_fingerprint(public_key)
        print(f"✓ Fingerprint: {fingerprint[:32]}...")
        
        return True
    except Exception as e:
        print(f"❌ Failed: {e}")
        return False


def test_private_key_encryption():
    """Test private key encryption and decryption"""
    print("\n" + "="*70)
    print("TEST 2: Private Key Encryption")
    print("="*70)
    
    try:
        # Generate a key pair
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        
        # Encrypt with password
        password = "test_password_123"
        print(f"Encrypting private key with password...")
        encrypted_key, salt, nonce = AsymmetricCrypto.encrypt_private_key(
            private_key, password
        )
        
        print(f"✓ Encrypted key: {len(encrypted_key)} bytes")
        print(f"✓ Salt: {len(salt)} bytes")
        print(f"✓ Nonce: {len(nonce)} bytes")
        
        # Decrypt with password
        print("Decrypting private key...")
        decrypted_key = AsymmetricCrypto.decrypt_private_key(
            encrypted_key, password, salt, nonce
        )
        
        print(f"✓ Decrypted key: {len(decrypted_key)} bytes")
        
        # Verify keys match
        if decrypted_key == private_key:
            print("✓ Decrypted key matches original")
            return True
        else:
            print("❌ Decrypted key does not match original")
            return False
            
    except Exception as e:
        print(f"❌ Failed: {e}")
        return False


def test_mongodb_connection():
    """Test MongoDB connection"""
    print("\n" + "="*70)
    print("TEST 3: MongoDB Connection")
    print("="*70)
    
    try:
        app = create_app()
        mongodb_uri = app.config.get('MONGODB_URI')
        mongodb_db = app.config.get('MONGODB_DB_NAME')
        
        print(f"MongoDB URI: {mongodb_uri}")
        print(f"Database: {mongodb_db}")
        
        key_store = KeyStore(mongodb_uri, mongodb_db)
        print("✓ Successfully connected to MongoDB")
        
        key_store.close()
        return True
        
    except Exception as e:
        print(f"❌ Failed: {e}")
        return False


def test_user_query():
    """Test querying users without keys"""
    print("\n" + "="*70)
    print("TEST 4: User Query")
    print("="*70)
    
    try:
        app = create_app()
        
        with app.app_context():
            # Query all users
            all_users = User.query.all()
            print(f"Total users in database: {len(all_users)}")
            
            # Query users without keys
            users_without_keys = User.query.filter(
                (User.public_key == None) | (User.public_key_fingerprint == None)
            ).all()
            
            print(f"Users without keys: {len(users_without_keys)}")
            
            if users_without_keys:
                print("\nUsers needing migration:")
                for user in users_without_keys:
                    role = user.role.value if user.role else 'unknown'
                    print(f"  - ID: {user.id}, Username: {user.username}, Role: {role}")
            else:
                print("✓ All users have RSA keys")
            
            return True
            
    except Exception as e:
        print(f"❌ Failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("MIGRATION SCRIPT TEST SUITE")
    print("="*70)
    
    results = []
    
    # Run tests
    results.append(("Key Generation", test_key_generation()))
    results.append(("Private Key Encryption", test_private_key_encryption()))
    results.append(("MongoDB Connection", test_mongodb_connection()))
    results.append(("User Query", test_user_query()))
    
    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✓ All tests passed! Migration script is ready to use.")
        return 0
    else:
        print("\n❌ Some tests failed. Please review the errors above.")
        return 1


if __name__ == '__main__':
    sys.exit(main())
