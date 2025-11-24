#!/usr/bin/env python
"""
Apply MongoDB SSL/TLS fixes automatically

This script attempts to fix common MongoDB SSL connection issues
by updating dependencies and testing the connection.
"""

import subprocess
import sys
import os


def run_command(command, description):
    """Run a command and display results"""
    print(f"\n{'='*70}")
    print(f"{description}")
    print(f"{'='*70}")
    print(f"Running: {command}")
    
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode == 0:
            print(f"✓ Success!")
            if result.stdout:
                print(result.stdout[:500])
            return True
        else:
            print(f"❌ Failed with exit code {result.returncode}")
            if result.stderr:
                print(result.stderr[:500])
            return False
            
    except subprocess.TimeoutExpired:
        print(f"❌ Command timed out")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def main():
    """Main fix application"""
    print("\n" + "="*70)
    print("MONGODB SSL/TLS FIX TOOL")
    print("="*70)
    print("\nThis script will:")
    print("1. Update SSL/TLS libraries")
    print("2. Install Windows certificate support")
    print("3. Test MongoDB connection")
    print("\nThis may take a few minutes...")
    
    input("\nPress Enter to continue or Ctrl+C to cancel...")
    
    # Step 1: Update pip
    run_command(
        "python -m pip install --upgrade pip",
        "Step 1: Updating pip"
    )
    
    # Step 2: Update SSL libraries
    run_command(
        "pip install --upgrade certifi cryptography pyOpenSSL",
        "Step 2: Updating SSL libraries"
    )
    
    # Step 3: Update pymongo
    run_command(
        "pip install --upgrade pymongo",
        "Step 3: Updating pymongo"
    )
    
    # Step 4: Install Windows certificate support
    print(f"\n{'='*70}")
    print("Step 4: Installing Windows certificate support")
    print(f"{'='*70}")
    
    # Try certifi-win32 first
    if not run_command("pip install certifi-win32", "Installing certifi-win32"):
        # If that fails, try python-certifi-win32
        run_command("pip install python-certifi-win32", "Installing python-certifi-win32")
    
    # Step 5: Verify SSL installation
    print(f"\n{'='*70}")
    print("Step 5: Verifying SSL installation")
    print(f"{'='*70}")
    
    try:
        import ssl
        import certifi
        print(f"✓ OpenSSL Version: {ssl.OPENSSL_VERSION}")
        print(f"✓ Certifi Location: {certifi.where()}")
        print(f"✓ TLS v1.3 Support: {ssl.HAS_TLSv1_3}")
    except Exception as e:
        print(f"❌ Verification failed: {e}")
    
    # Step 6: Test MongoDB connection
    print(f"\n{'='*70}")
    print("Step 6: Testing MongoDB connection")
    print(f"{'='*70}")
    
    test_script = os.path.join(
        os.path.dirname(__file__),
        'test_mongo_fix.py'
    )
    
    if os.path.exists(test_script):
        print("Running connection test...")
        result = subprocess.run(
            f"python {test_script}",
            shell=True
        )
        
        if result.returncode == 0:
            print("\n" + "="*70)
            print("✓ FIX SUCCESSFUL!")
            print("="*70)
            print("\nMongoDB connection is now working.")
            print("You can now run the migration script:")
            print("  python migrations/002_migrate_existing_users_keys.py --dry-run")
            return 0
        else:
            print("\n" + "="*70)
            print("⚠️  FIX PARTIALLY SUCCESSFUL")
            print("="*70)
            print("\nSSL libraries updated, but connection still failing.")
            print("\nAdditional steps to try:")
            print("1. Check MongoDB Atlas IP whitelist")
            print("2. Verify database credentials")
            print("3. Try using local MongoDB for development")
            print("4. See migrations/FIX_MONGODB_SSL.md for more options")
            return 1
    else:
        print(f"Test script not found: {test_script}")
        print("Please run manually: python migrations/test_mongo_fix.py")
        return 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(1)
