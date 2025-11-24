"""
Cleanup script for test data that accumulates during testing.

This script removes:
- Temporary test files in uploads/ and encrypted_files/
- Test databases
- Hypothesis cache
- Pytest cache
- Python cache files (__pycache__)
"""

import os
import shutil
import glob
from pathlib import Path

def cleanup_test_data():
    """Remove all test-generated data to free up disk space"""
    
    base_dir = Path(__file__).parent
    removed_size = 0
    
    print("🧹 Starting cleanup of test data...")
    
    # 1. Clean uploads folder (keep only template files)
    uploads_dir = base_dir / 'uploads'
    if uploads_dir.exists():
        for file in uploads_dir.glob('*'):
            if file.is_file() and 'Template' not in file.name:
                size = file.stat().st_size
                file.unlink()
                removed_size += size
                print(f"  ✓ Removed: {file.name} ({size / 1024:.2f} KB)")
    
    # 2. Clean encrypted_files folder
    encrypted_dir = base_dir / 'encrypted_files'
    if encrypted_dir.exists():
        for file in encrypted_dir.glob('*'):
            if file.is_file():
                size = file.stat().st_size
                file.unlink()
                removed_size += size
                print(f"  ✓ Removed: {file.name} ({size / 1024:.2f} KB)")
    
    # 3. Clean test databases
    instance_dir = base_dir / 'instance'
    if instance_dir.exists():
        for db_file in instance_dir.glob('*.db'):
            if 'test' in db_file.name.lower():
                size = db_file.stat().st_size
                db_file.unlink()
                removed_size += size
                print(f"  ✓ Removed: {db_file.name} ({size / 1024:.2f} KB)")
    
    # 4. Clean Hypothesis cache
    hypothesis_dir = base_dir.parent / '.hypothesis'
    if hypothesis_dir.exists():
        size = sum(f.stat().st_size for f in hypothesis_dir.rglob('*') if f.is_file())
        shutil.rmtree(hypothesis_dir)
        removed_size += size
        print(f"  ✓ Removed .hypothesis cache ({size / 1024 / 1024:.2f} MB)")
    
    # 5. Clean pytest cache
    pytest_cache = base_dir / '.pytest_cache'
    if pytest_cache.exists():
        size = sum(f.stat().st_size for f in pytest_cache.rglob('*') if f.is_file())
        shutil.rmtree(pytest_cache)
        removed_size += size
        print(f"  ✓ Removed .pytest_cache ({size / 1024:.2f} KB)")
    
    # 6. Clean __pycache__ directories
    pycache_size = 0
    for pycache in base_dir.rglob('__pycache__'):
        if pycache.is_dir():
            size = sum(f.stat().st_size for f in pycache.rglob('*') if f.is_file())
            shutil.rmtree(pycache)
            pycache_size += size
    if pycache_size > 0:
        removed_size += pycache_size
        print(f"  ✓ Removed __pycache__ directories ({pycache_size / 1024 / 1024:.2f} MB)")
    
    # 7. Clean .pyc files
    pyc_files = list(base_dir.rglob('*.pyc'))
    for pyc in pyc_files:
        size = pyc.stat().st_size
        pyc.unlink()
        removed_size += size
    if pyc_files:
        print(f"  ✓ Removed {len(pyc_files)} .pyc files")
    
    print(f"\n✅ Cleanup complete! Freed up {removed_size / 1024 / 1024:.2f} MB")
    print("\n💡 Tip: Run this script regularly during development to prevent disk space issues.")
    print("   You can also run: python cleanup_test_data.py")

if __name__ == '__main__':
    try:
        cleanup_test_data()
    except Exception as e:
        print(f"❌ Error during cleanup: {e}")
        exit(1)
