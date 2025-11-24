#!/usr/bin/env python
"""
Quick MongoDB connection test with multiple strategies

This script tests different connection strategies to help diagnose
and fix MongoDB SSL/TLS connection issues.
"""

import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError


def test_ssl_info():
    """Display SSL/TLS information"""
    print("="*70)
    print("SSL/TLS INFORMATION")
    print("="*70)
    
    try:
        import ssl
        print(f"OpenSSL Version: {ssl.OPENSSL_VERSION}")
        print(f"TLS v1.3 Support: {ssl.HAS_TLSv1_3}")
        print(f"TLS v1.2 Support: {ssl.HAS_TLSv1_2}")
    except Exception as e:
        print(f"Error getting SSL info: {e}")
    
    try:
        import certifi
        print(f"Certifi Location: {certifi.where()}")
    except ImportError:
        print("Certifi not installed (pip install certifi)")
    
    print()


def test_connection_strategy(uri, strategy_name, options):
    """Test a specific connection strategy"""
    print(f"Testing: {strategy_name}")
    print(f"Options: {options}")
    
    try:
        client = MongoClient(uri, **options)
        
        # Test connection
        client.admin.command('ping')
        
        # Get server info
        server_info = client.server_info()
        
        print(f"  ✓ SUCCESS!")
        print(f"  MongoDB Version: {server_info.get('version', 'unknown')}")
        
        # List databases
        try:
            dbs = client.list_database_names()
            print(f"  Databases: {', '.join(dbs[:5])}")
        except:
            pass
        
        client.close()
        return True
        
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        error_msg = str(e)
        if len(error_msg) > 150:
            error_msg = error_msg[:150] + "..."
        print(f"  ❌ Failed: {error_msg}")
        return False
    except Exception as e:
        print(f"  ❌ Unexpected error: {e}")
        return False


def main():
    """Main test function"""
    print("\n" + "="*70)
    print("MONGODB CONNECTION DIAGNOSTIC TOOL")
    print("="*70)
    print()
    
    # Get MongoDB URI
    uri = os.getenv('MONGODB_URI')
    
    if not uri:
        print("❌ Error: MONGODB_URI environment variable not set")
        print("\nPlease set it in your .env file or environment:")
        print("  MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/")
        return 1
    
    # Mask password in display
    display_uri = uri
    if '@' in uri and '://' in uri:
        parts = uri.split('://')
        if len(parts) == 2 and '@' in parts[1]:
            creds, rest = parts[1].split('@', 1)
            if ':' in creds:
                user = creds.split(':')[0]
                display_uri = f"{parts[0]}://{user}:****@{rest}"
    
    print(f"MongoDB URI: {display_uri}")
    print(f"Database: {os.getenv('MONGODB_DB_NAME', 'secure_file_exchange_keys')}")
    print()
    
    # Display SSL info
    test_ssl_info()
    
    # Define test strategies
    strategies = [
        {
            'name': 'Strategy 1: Default Connection',
            'options': {
                'serverSelectionTimeoutMS': 10000,
                'connectTimeoutMS': 10000
            }
        },
        {
            'name': 'Strategy 2: With TLS Enabled',
            'options': {
                'tls': True,
                'tlsAllowInvalidCertificates': False,
                'serverSelectionTimeoutMS': 10000,
                'connectTimeoutMS': 10000
            }
        },
        {
            'name': 'Strategy 3: With Relaxed TLS (Testing Only)',
            'options': {
                'tls': True,
                'tlsAllowInvalidCertificates': True,
                'serverSelectionTimeoutMS': 10000,
                'connectTimeoutMS': 10000
            }
        },
        {
            'name': 'Strategy 4: With Extended Timeout',
            'options': {
                'tls': True,
                'tlsAllowInvalidCertificates': False,
                'serverSelectionTimeoutMS': 30000,
                'connectTimeoutMS': 30000,
                'socketTimeoutMS': 30000
            }
        },
        {
            'name': 'Strategy 5: With Retry Writes',
            'options': {
                'tls': True,
                'retryWrites': True,
                'w': 'majority',
                'serverSelectionTimeoutMS': 10000,
                'connectTimeoutMS': 10000
            }
        }
    ]
    
    # Test each strategy
    print("="*70)
    print("TESTING CONNECTION STRATEGIES")
    print("="*70)
    print()
    
    success = False
    for i, strategy in enumerate(strategies, 1):
        print(f"[{i}/{len(strategies)}] {strategy['name']}")
        if test_connection_strategy(uri, strategy['name'], strategy['options']):
            success = True
            print("\n" + "="*70)
            print("✓ SOLUTION FOUND!")
            print("="*70)
            print(f"\nUse these connection options:")
            for key, value in strategy['options'].items():
                print(f"  {key}: {value}")
            print("\nThe key_store.py has been updated to use appropriate settings.")
            break
        print()
    
    if not success:
        print("="*70)
        print("❌ ALL STRATEGIES FAILED")
        print("="*70)
        print("\nTroubleshooting steps:")
        print("\n1. Update SSL libraries:")
        print("   pip install --upgrade certifi pymongo cryptography")
        print("   pip install certifi-win32")
        print("\n2. Check MongoDB Atlas settings:")
        print("   - Verify IP whitelist (Network Access)")
        print("   - Verify database user credentials")
        print("   - Check connection string format")
        print("\n3. Test with MongoDB Compass:")
        print("   Download: https://www.mongodb.com/try/download/compass")
        print("\n4. Check Windows Firewall:")
        print("   - Allow Python through firewall")
        print("   - Temporarily disable antivirus")
        print("\n5. Use local MongoDB for development:")
        print("   docker run -d -p 27017:27017 mongo:latest")
        print("   MONGODB_URI=mongodb://localhost:27017/")
        print("\nFor detailed help, see: migrations/FIX_MONGODB_SSL.md")
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
