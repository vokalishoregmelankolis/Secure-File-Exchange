"""
Script to check and display encryption keys stored in the database.
Shows both SQLite (public keys) and MongoDB (private keys) storage.
"""

import os
import sys
from datetime import datetime

# Add app to path
sys.path.insert(0, os.path.dirname(__file__))

from app import create_app, db
from app.models import User, EncryptedFile, AccessRequest
from app.key_store import KeyStore
from app.asymmetric_crypto import AsymmetricCrypto
import base64


def print_separator(char='=', length=80):
    print(char * length)


def print_header(text):
    print_separator()
    print(f"  {text}")
    print_separator()


def display_user_keys():
    """Display all user RSA keys from SQLite database"""
    print_header("USER RSA KEYS (SQLite Database)")
    
    users = User.query.all()
    
    if not users:
        print("No users found in database.")
        return
    
    for user in users:
        print(f"\n👤 User: {user.username} (ID: {user.id})")
        print(f"   Email: {user.email}")
        print(f"   Role: {user.role.value if user.role else 'N/A'}")
        print(f"   Key Generated: {user.key_generated_at.strftime('%Y-%m-%d %H:%M:%S') if user.key_generated_at else 'N/A'}")
        
        if user.public_key:
            print(f"\n   📜 PUBLIC KEY (RSA):")
            print(f"   Length: {len(user.public_key)} bytes")
            print(f"   Fingerprint: {user.public_key_fingerprint or 'N/A'}")
            
            # Display first and last 100 chars of public key
            if len(user.public_key) > 200:
                print(f"   Preview: {user.public_key[:100]}...")
                print(f"            ...{user.public_key[-100:]}")
            else:
                print(f"   Full Key:\n{user.public_key}")
            
            # Verify key format
            try:
                from Crypto.PublicKey import RSA
                key_obj = RSA.import_key(user.public_key)
                print(f"   ✓ Key Format: Valid RSA")
                print(f"   ✓ Key Size: {key_obj.size_in_bits()} bits")
                print(f"   ✓ Has Private: {key_obj.has_private()}")
            except Exception as e:
                print(f"   ✗ Key Validation Error: {str(e)}")
        else:
            print("   ⚠️  No public key stored")
        
        print()


def display_private_keys():
    """Display encrypted private keys from MongoDB"""
    print_header("ENCRYPTED PRIVATE KEYS (MongoDB)")
    
    try:
        keystore = KeyStore()
        users = User.query.all()
        
        if not users:
            print("No users found in database.")
            keystore.close()
            return
        
        for user in users:
            print(f"\n👤 User: {user.username} (ID: {user.id})")
            
            try:
                # Retrieve encrypted private key from MongoDB
                key_doc = keystore.get_private_key(user.id)
                
                if key_doc:
                    print(f"   🔐 ENCRYPTED PRIVATE KEY:")
                    print(f"   Stored in MongoDB: ✓")
                    print(f"   Encrypted Key Length: {len(key_doc['encrypted_key'])} bytes")
                    print(f"   Salt Length: {len(key_doc['salt'])} bytes")
                    print(f"   Nonce Length: {len(key_doc['nonce'])} bytes")
                    print(f"   Created: {key_doc['created_at'].strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    if 'metadata' in key_doc:
                        print(f"   Metadata:")
                        for k, v in key_doc['metadata'].items():
                            print(f"     - {k}: {v}")
                    
                    # Show preview of encrypted data (base64)
                    enc_preview = base64.b64encode(key_doc['encrypted_key'][:50]).decode('utf-8')
                    print(f"   Encrypted Data Preview: {enc_preview}...")
                else:
                    print("   ⚠️  No private key found in MongoDB")
                    
            except Exception as e:
                print(f"   ✗ Error retrieving private key: {str(e)}")
            
            print()
        
        keystore.close()
        
    except Exception as e:
        print(f"✗ MongoDB Connection Error: {str(e)}")
        print("  Make sure MongoDB is running and configured correctly.")


def display_file_encryption_keys():
    """Display file encryption keys (DEKs wrapped by KEK)"""
    print_header("FILE ENCRYPTION KEYS (Data Encryption Keys)")
    
    files = EncryptedFile.query.limit(10).all()
    
    if not files:
        print("No encrypted files found in database.")
        return
    
    print(f"Showing first 10 files (Total: {EncryptedFile.query.count()})\n")
    
    for file in files:
        print(f"📄 File: {file.original_filename}")
        print(f"   File ID: {file.file_id}")
        print(f"   Owner: {file.owner.username if file.owner else 'Unknown'}")
        print(f"   Algorithm: {file.algorithm}")
        print(f"   Uploaded: {file.uploaded_at.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Check wrapped key
        if file.wrapped_key:
            print(f"\n   🔑 WRAPPED DEK (Data Encryption Key):")
            print(f"   Wrapped by: KEK (Key Encryption Key from environment)")
            print(f"   Wrapped Key Length: {len(file.wrapped_key)} bytes")
            print(f"   Wrapped Key Version: {file.wrapped_key_version or 'N/A'}")
            
            # Show preview
            wrapped_preview = base64.b64encode(file.wrapped_key[:50]).decode('utf-8')
            print(f"   Preview: {wrapped_preview}...")
            
            # Check if it's the new format
            if file.wrapped_key[:2] == b'V1':
                print(f"   ✓ Format: V1 (KEK-wrapped)")
            else:
                print(f"   ⚠️  Format: Unknown")
        elif file.encryption_key:
            print(f"\n   🔑 LEGACY ENCRYPTION KEY:")
            print(f"   Key Length: {len(file.encryption_key)} bytes")
            print(f"   ⚠️  Warning: Using legacy key format")
        else:
            print(f"   ✗ No encryption key found!")
        
        # Check IV
        if file.iv:
            print(f"\n   🎲 IV (Initialization Vector):")
            print(f"   Length: {len(file.iv)} bytes")
            iv_hex = file.iv.hex()[:32]
            print(f"   Hex Preview: {iv_hex}...")
        
        print()


def display_access_request_keys():
    """Display wrapped symmetric keys in access requests"""
    print_header("ACCESS REQUEST KEYS (RSA-Wrapped Symmetric Keys)")
    
    requests = AccessRequest.query.filter(
        AccessRequest.wrapped_symmetric_key.isnot(None)
    ).limit(10).all()
    
    if not requests:
        print("No access requests with wrapped keys found.")
        return
    
    print(f"Showing approved requests with wrapped keys\n")
    
    for req in requests:
        print(f"🔐 Access Request ID: {req.id}")
        print(f"   Consultant: {req.consultant.username if req.consultant else 'Unknown'}")
        print(f"   Organization: {req.organization.username if req.organization else 'Unknown'}")
        print(f"   File: {req.file.original_filename if req.file else 'Unknown'}")
        print(f"   Status: {req.status}")
        print(f"   Processed: {req.processed_at.strftime('%Y-%m-%d %H:%M:%S') if req.processed_at else 'N/A'}")
        
        if req.wrapped_symmetric_key:
            print(f"\n   🔑 RSA-WRAPPED SYMMETRIC KEY:")
            print(f"   Wrapped for: {req.consultant.username}'s RSA public key")
            print(f"   Wrapped Key Length: {len(req.wrapped_symmetric_key)} bytes")
            
            # Show preview
            wrapped_preview = base64.b64encode(req.wrapped_symmetric_key[:50]).decode('utf-8')
            print(f"   Preview: {wrapped_preview}...")
            
            # This key can only be decrypted by consultant's RSA private key
            print(f"   ✓ Can be decrypted by: Consultant's RSA private key only")
        
        print()


def display_key_summary():
    """Display summary of all keys in the system"""
    print_header("KEY MANAGEMENT SUMMARY")
    
    total_users = User.query.count()
    users_with_keys = User.query.filter(User.public_key.isnot(None)).count()
    total_files = EncryptedFile.query.count()
    files_with_wrapped_keys = EncryptedFile.query.filter(EncryptedFile.wrapped_key.isnot(None)).count()
    total_requests = AccessRequest.query.count()
    approved_requests = AccessRequest.query.filter(AccessRequest.status == 'approved').count()
    requests_with_keys = AccessRequest.query.filter(AccessRequest.wrapped_symmetric_key.isnot(None)).count()
    
    print(f"""
📊 SYSTEM STATISTICS:

Users:
  - Total Users: {total_users}
  - Users with RSA Keys: {users_with_keys}
  - Coverage: {(users_with_keys/total_users*100) if total_users > 0 else 0:.1f}%

Files:
  - Total Encrypted Files: {total_files}
  - Files with Wrapped DEKs: {files_with_wrapped_keys}
  - Files with Legacy Keys: {total_files - files_with_wrapped_keys}

Access Requests:
  - Total Requests: {total_requests}
  - Approved Requests: {approved_requests}
  - Requests with Wrapped Keys: {requests_with_keys}

🔐 ENCRYPTION ARCHITECTURE:

1. User Keys (RSA-2048):
   - Public Key: Stored in SQLite (User table)
   - Private Key: Encrypted and stored in MongoDB
   - Used for: Key exchange between organization and consultant

2. File Encryption (Symmetric):
   - Algorithms: AES-256, DES, RC4
   - DEK (Data Encryption Key): Generated per file
   - KEK (Key Encryption Key): From environment variable
   - Storage: DEK wrapped by KEK, stored in SQLite

3. Key Sharing (Asymmetric):
   - Organization unwraps DEK using KEK
   - Organization wraps DEK with consultant's RSA public key
   - Consultant unwraps DEK using their RSA private key
   - Consultant can then decrypt file data
""")


def main():
    """Main function to display all keys"""
    app = create_app()
    
    with app.app_context():
        print("\n")
        print("=" * 80)
        print("  SECURE FILE EXCHANGE - KEY DATABASE INSPECTOR")
        print("=" * 80)
        print()
        
        # Display summary first
        display_key_summary()
        
        # Display detailed key information
        display_user_keys()
        display_private_keys()
        display_file_encryption_keys()
        display_access_request_keys()
        
        print_separator()
        print("✓ Key inspection complete!")
        print_separator()
        print()


if __name__ == '__main__':
    main()
