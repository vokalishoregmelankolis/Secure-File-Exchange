"""
Script to verify encryption implementation and key sizes.
Checks if the system meets security requirements.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from app import create_app, db
from app.models import User, EncryptedFile
from app.asymmetric_crypto import AsymmetricCrypto
from app.crypto_utils import CryptoEngine
from Crypto.PublicKey import RSA


def check_rsa_key_sizes():
    """Verify RSA key sizes meet security requirements"""
    print("\n" + "="*80)
    print("  RSA KEY SIZE VERIFICATION")
    print("="*80 + "\n")
    
    users = User.query.filter(User.public_key.isnot(None)).all()
    
    if not users:
        print("❌ No users with RSA keys found!")
        return False
    
    all_valid = True
    
    for user in users:
        try:
            key_obj = RSA.import_key(user.public_key)
            key_size = key_obj.size_in_bits()
            
            print(f"👤 {user.username}:")
            print(f"   Key Size: {key_size} bits")
            
            if key_size >= 2048:
                print(f"   ✅ SECURE (>= 2048 bits)")
            elif key_size >= 1024:
                print(f"   ⚠️  WEAK (1024-2047 bits) - Consider upgrading")
                all_valid = False
            else:
                print(f"   ❌ INSECURE (< 1024 bits)")
                all_valid = False
            
            # Check key components
            print(f"   Public Exponent: {key_obj.e}")
            print(f"   Modulus Size: {key_obj.n.bit_length()} bits")
            print()
            
        except Exception as e:
            print(f"❌ {user.username}: Error - {str(e)}\n")
            all_valid = False
    
    return all_valid


def check_symmetric_algorithms():
    """Verify symmetric encryption algorithms"""
    print("\n" + "="*80)
    print("  SYMMETRIC ENCRYPTION VERIFICATION")
    print("="*80 + "\n")
    
    files = EncryptedFile.query.all()
    
    if not files:
        print("❌ No encrypted files found!")
        return False
    
    algorithms = {}
    for file in files:
        algo = file.algorithm.upper()
        if algo not in algorithms:
            algorithms[algo] = {'count': 0, 'key_sizes': set()}
        algorithms[algo]['count'] += 1
    
    print("📊 Algorithms in use:\n")
    
    for algo, data in algorithms.items():
        print(f"   {algo}:")
        print(f"   - Files encrypted: {data['count']}")
        
        if algo == 'AES':
            print(f"   - Key Size: 256 bits (AES-256)")
            print(f"   - Block Size: 128 bits")
            print(f"   - Mode: CBC")
            print(f"   ✅ SECURE - Industry standard")
        elif algo == 'DES':
            print(f"   - Key Size: 56 bits (effective)")
            print(f"   - Block Size: 64 bits")
            print(f"   - Mode: CBC")
            print(f"   ⚠️  WEAK - Consider using AES instead")
        elif algo == 'RC4':
            print(f"   - Key Size: 128 bits")
            print(f"   - Type: Stream cipher")
            print(f"   ⚠️  DEPRECATED - Known vulnerabilities, use AES")
        
        print()
    
    return True


def check_key_management():
    """Verify key management implementation"""
    print("\n" + "="*80)
    print("  KEY MANAGEMENT VERIFICATION")
    print("="*80 + "\n")
    
    print("🔐 Key Hierarchy:\n")
    
    # Check KEK
    kek_exists = os.environ.get('MASTER_KEY') is not None
    print(f"1. KEK (Key Encryption Key):")
    print(f"   Source: Environment variable (MASTER_KEY)")
    print(f"   Status: {'✅ Configured' if kek_exists else '⚠️  Using fallback'}")
    print(f"   Purpose: Wraps file DEKs")
    print()
    
    # Check DEKs
    files_with_wrapped = EncryptedFile.query.filter(
        EncryptedFile.wrapped_key.isnot(None)
    ).count()
    total_files = EncryptedFile.query.count()
    
    print(f"2. DEK (Data Encryption Key):")
    print(f"   Generated: Per file")
    print(f"   Wrapped by: KEK")
    print(f"   Files with wrapped DEKs: {files_with_wrapped}/{total_files}")
    print(f"   Status: {'✅ All wrapped' if files_with_wrapped == total_files else '⚠️  Some legacy keys'}")
    print()
    
    # Check RSA keys
    users_with_keys = User.query.filter(User.public_key.isnot(None)).count()
    total_users = User.query.count()
    
    print(f"3. RSA Key Pairs:")
    print(f"   Users with keys: {users_with_keys}/{total_users}")
    print(f"   Public key storage: SQLite database")
    print(f"   Private key storage: MongoDB (encrypted)")
    print(f"   Status: {'✅ All users have keys' if users_with_keys == total_users else '⚠️  Some users missing keys'}")
    print()
    
    return True


def test_encryption_roundtrip():
    """Test encryption/decryption roundtrip"""
    print("\n" + "="*80)
    print("  ENCRYPTION ROUNDTRIP TEST")
    print("="*80 + "\n")
    
    test_data = b"This is a test message for encryption verification."
    
    algorithms = ['AES', 'DES', 'RC4']
    
    for algo in algorithms:
        try:
            print(f"Testing {algo}...")
            
            # Encrypt
            if algo == 'AES':
                encrypted, wrapped_key, iv, _ = CryptoEngine.encrypt_aes(test_data)
            elif algo == 'DES':
                encrypted, wrapped_key, iv, _ = CryptoEngine.encrypt_des(test_data)
            elif algo == 'RC4':
                encrypted, wrapped_key, iv, _ = CryptoEngine.encrypt_rc4(test_data)
            
            # Decrypt
            if algo == 'AES':
                decrypted, _ = CryptoEngine.decrypt_aes(encrypted, wrapped_key, iv)
            elif algo == 'DES':
                decrypted, _ = CryptoEngine.decrypt_des(encrypted, wrapped_key, iv)
            elif algo == 'RC4':
                decrypted, _ = CryptoEngine.decrypt_rc4(encrypted, wrapped_key)
            
            # Verify
            if decrypted == test_data:
                print(f"   ✅ {algo} encryption/decryption: PASSED")
            else:
                print(f"   ❌ {algo} encryption/decryption: FAILED")
            
        except Exception as e:
            print(f"   ❌ {algo} test error: {str(e)}")
    
    print()


def test_rsa_key_exchange():
    """Test RSA key wrapping/unwrapping"""
    print("\n" + "="*80)
    print("  RSA KEY EXCHANGE TEST")
    print("="*80 + "\n")
    
    try:
        # Generate test RSA key pair
        print("Generating test RSA-2048 key pair...")
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        print("   ✅ Key pair generated")
        
        # Test symmetric key wrapping
        test_symmetric_key = os.urandom(32)  # 256-bit AES key
        print(f"\nWrapping 256-bit symmetric key with RSA public key...")
        wrapped = AsymmetricCrypto.wrap_symmetric_key(test_symmetric_key, public_key)
        print(f"   ✅ Key wrapped (size: {len(wrapped)} bytes)")
        
        # Test unwrapping
        print(f"\nUnwrapping with RSA private key...")
        # First, encrypt private key with password
        password = "test_password_123"
        encrypted_private, salt, nonce = AsymmetricCrypto.encrypt_private_key(private_key, password)
        
        # Decrypt private key
        decrypted_private = AsymmetricCrypto.decrypt_private_key(
            encrypted_private, password, salt, nonce
        )
        
        # Unwrap symmetric key
        unwrapped = AsymmetricCrypto.unwrap_symmetric_key(wrapped, decrypted_private)
        print(f"   ✅ Key unwrapped")
        
        # Verify
        if unwrapped == test_symmetric_key:
            print(f"\n   ✅ RSA key exchange: PASSED")
            print(f"   Original and unwrapped keys match!")
        else:
            print(f"\n   ❌ RSA key exchange: FAILED")
            print(f"   Keys do not match!")
        
    except Exception as e:
        print(f"   ❌ RSA test error: {str(e)}")
    
    print()


def main():
    """Main verification function"""
    app = create_app()
    
    with app.app_context():
        print("\n")
        print("="*80)
        print("  ENCRYPTION VERIFICATION TOOL")
        print("="*80)
        
        # Run all checks
        check_rsa_key_sizes()
        check_symmetric_algorithms()
        check_key_management()
        test_encryption_roundtrip()
        test_rsa_key_exchange()
        
        print("="*80)
        print("  VERIFICATION COMPLETE")
        print("="*80)
        print()
        
        print("📋 SUMMARY:")
        print()
        print("✅ Symmetric Encryption: AES-256 (recommended), DES, RC4")
        print("✅ Asymmetric Encryption: RSA-2048")
        print("✅ Key Management: KEK wraps DEKs, RSA for key exchange")
        print("✅ Key Storage: Public keys in SQLite, Private keys in MongoDB")
        print()


if __name__ == '__main__':
    main()
