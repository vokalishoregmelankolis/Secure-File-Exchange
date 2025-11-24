#!/usr/bin/env python3
"""
Test Runner - Main entry point for all testing suites
Runs functional, security, and performance tests
"""

import os
import sys
import time
import argparse
from datetime import datetime

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)


def print_banner():
    """Print test suite banner"""
    print("=" * 80)
    print("🧪 SECURE FINANCIAL REPORT SHARING - TEST SUITE")
    print("=" * 80)
    print(f"📅 Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🐍 Python Version: {sys.version}")
    print(f"📂 Project Root: {project_root}")
    print("=" * 80)


def check_dependencies():
    """Check if required dependencies are available"""
    print("🔍 Checking Dependencies...")
    
    required_modules = ['requests', 'flask', 'flask_sqlalchemy']
    optional_modules = ['pytest', 'psutil', 'locust']
    
    missing_required = []
    missing_optional = []
    
    for module in required_modules:
        try:
            __import__(module)
            print(f"  ✅ {module}")
        except ImportError:
            missing_required.append(module)
            print(f"  ❌ {module} (REQUIRED)")
    
    for module in optional_modules:
        try:
            __import__(module)
            print(f"  ✅ {module}")
        except ImportError:
            missing_optional.append(module)
            print(f"  ⚠️  {module} (OPTIONAL)")
    
    if missing_required:
        print(f"\n❌ Missing required dependencies: {', '.join(missing_required)}")
        print("Please install with: pip install -r requirements.txt")
        return False
    
    if missing_optional:
        print(f"\n⚠️  Missing optional dependencies: {', '.join(missing_optional)}")
        print("Install for full functionality: pip install pytest psutil locust")
    
    return True


def check_application_status():
    """Check if the Flask application is running"""
    print("\n🌐 Checking Application Status...")
    
    try:
        import requests
        response = requests.get("http://localhost:8080", timeout=5)
        print("  ✅ Application is running on http://localhost:8080")
        return True
    except ImportError:
        print("  ❌ requests module not available")
        return False
    except requests.exceptions.RequestException:
        print("  ❌ Application is not running on http://localhost:8080")
        print("  💡 Start the application with: python run.py")
        return False


def run_functional_tests():
    """Run functional tests"""
    print("\n" + "="*60)
    print("🔧 FUNCTIONAL TESTS")
    print("="*60)
    
    try:
        from tests.test_functional import run_functional_tests
        return run_functional_tests()
    except ImportError as e:
        print(f"❌ Cannot import functional tests: {e}")
        return False
    except Exception as e:
        print(f"❌ Functional tests failed: {e}")
        return False


def run_security_tests():
    """Run security tests"""
    print("\n" + "="*60)
    print("🔒 SECURITY TESTS")
    print("="*60)
    
    try:
        from tests.test_security import run_security_tests
        return run_security_tests()
    except ImportError as e:
        print(f"❌ Cannot import security tests: {e}")
        return False
    except Exception as e:
        print(f"❌ Security tests failed: {e}")
        return False


def run_performance_tests():
    """Run performance tests"""
    print("\n" + "="*60)
    print("⚡ PERFORMANCE TESTS")
    print("="*60)
    
    try:
        from tests.test_performance import run_performance_tests
        return run_performance_tests()
    except ImportError as e:
        print(f"❌ Cannot import performance tests: {e}")
        return False
    except Exception as e:
        print(f"❌ Performance tests failed: {e}")
        return False


def run_quick_smoke_tests():
    """Run quick smoke tests to verify basic functionality"""
    print("\n" + "="*60)
    print("💨 SMOKE TESTS (Quick Verification)")
    print("="*60)
    
    tests_passed = 0
    total_tests = 0
    
    # Test 1: Import main application modules
    print("📦 Testing module imports...")
    total_tests += 1
    try:
        from app import create_app
        from app.models import User, EncryptedFile
        from app.crypto_utils import CryptoEngine
        print("  ✅ All core modules import successfully")
        tests_passed += 1
    except ImportError as e:
        print(f"  ❌ Import error: {e}")
    
    # Test 2: Create test app
    print("🔧 Testing app creation...")
    total_tests += 1
    try:
        app = create_app()
        print("  ✅ Flask app creates successfully")
        tests_passed += 1
    except Exception as e:
        print(f"  ❌ App creation failed: {e}")
    
    # Test 3: Test encryption engine
    print("🔐 Testing encryption engine...")
    total_tests += 1
    try:
        engine = CryptoEngine()
        test_data = b"Test encryption data"
        
        # Test AES
        encrypted, key, iv, _ = engine.encrypt_aes(test_data)
        decrypted, _ = engine.decrypt_aes(encrypted, key, iv)
        
        assert decrypted == test_data, "AES encryption/decryption failed"
        print("  ✅ Encryption engine works correctly")
        tests_passed += 1
    except Exception as e:
        print(f"  ❌ Encryption test failed: {e}")
    
    # Test 4: Test database operations
    print("🗄️ Testing database operations...")
    total_tests += 1
    try:
        from tests import create_test_app
        app, db = create_test_app()
        
        with app.app_context():
            db.create_all()
            
            # Create test user (use unique name each time)
            import random
            from app.models import User
            username = f'smoketest_{random.randint(1000, 9999)}'
            user = User(username=username, email=f'smoke{random.randint(100,999)}@test.com')
            user.set_password('testpass123')
            db.session.add(user)
            db.session.commit()
            
            # Verify user was created
            found_user = User.query.filter_by(username=username).first()
            assert found_user is not None, "User creation failed"
            assert found_user.check_password('testpass123'), "Password verification failed"
            
            print("  ✅ Database operations work correctly")
            tests_passed += 1
    except Exception as e:
        print(f"  ❌ Database test failed: {e}")
    
    print(f"\n📊 Smoke Test Results: {tests_passed}/{total_tests} tests passed")
    
    if tests_passed == total_tests:
        print("🎉 All smoke tests passed! System is ready for full testing.")
        return True
    else:
        print("⚠️  Some smoke tests failed. Fix issues before running full tests.")
        return False


def generate_test_report(results):
    """Generate final test report"""
    print("\n" + "="*80)
    print("📊 FINAL TEST REPORT")
    print("="*80)
    
    total_suites = len(results)
    passed_suites = sum(1 for result in results.values() if result)
    
    print(f"📅 Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📊 Test Suites: {passed_suites}/{total_suites} passed")
    print()
    
    for suite_name, result in results.items():
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"  {suite_name:<20} {status}")
    
    print(f"\n🎯 OVERALL RESULT: ", end="")
    if passed_suites == total_suites:
        print("🟢 ALL TESTS PASSED")
        print("🎉 System is ready for production deployment!")
    elif passed_suites >= total_suites * 0.7:  # 70% pass rate
        print("🟡 MOSTLY PASSED")
        print("⚠️  Some issues found, review failed tests above.")
    else:
        print("🔴 TESTS FAILED")
        print("❌ Significant issues found, system needs attention.")
    
    # Recommendations
    print(f"\n💡 RECOMMENDATIONS:")
    if not results.get('functional', True):
        print("  • Fix functional test failures before proceeding")
    if not results.get('security', True):
        print("  • Address security vulnerabilities immediately")
    if not results.get('performance', True):
        print("  • Optimize performance bottlenecks")
    
    if passed_suites == total_suites:
        print("  • System is ready for deployment")
        print("  • Consider setting up automated testing pipeline")
    
    return passed_suites == total_suites


def main():
    """Main test runner function"""
    parser = argparse.ArgumentParser(description='Secure Financial Report Sharing Test Suite')
    parser.add_argument('--functional', action='store_true', help='Run only functional tests')
    parser.add_argument('--security', action='store_true', help='Run only security tests')
    parser.add_argument('--performance', action='store_true', help='Run only performance tests')
    parser.add_argument('--smoke', action='store_true', help='Run only smoke tests')
    parser.add_argument('--skip-deps', action='store_true', help='Skip dependency check')
    parser.add_argument('--skip-app-check', action='store_true', help='Skip application status check')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Check dependencies
    if not args.skip_deps:
        if not check_dependencies():
            return False
    
    # Check if any specific test suite is requested
    run_specific = args.functional or args.security or args.performance or args.smoke
    
    results = {}
    
    if args.smoke or not run_specific:
        # Run smoke tests first
        smoke_result = run_quick_smoke_tests()
        results['smoke'] = smoke_result
        
        if not smoke_result and run_specific:
            print("\n❌ Smoke tests failed! Fix basic issues before running other tests.")
            return False
    
    # Check application status for security tests
    app_running = True
    if (args.security or not run_specific) and not args.skip_app_check:
        app_running = check_application_status()
        if not app_running:
            print("⚠️  Security tests require the application to be running.")
    
    # Run requested test suites
    if args.functional or not run_specific:
        results['functional'] = run_functional_tests()
    
    if args.security or not run_specific:
        if app_running:
            results['security'] = run_security_tests()
        else:
            results['security'] = False
            print("❌ Security tests skipped - application not running")
    
    if args.performance or not run_specific:
        results['performance'] = run_performance_tests()
    
    # Generate final report
    if len(results) > 1 or not args.smoke:  # Don't show report for smoke-only tests
        overall_success = generate_test_report(results)
    else:
        overall_success = results.get('smoke', False)
    
    return overall_success


if __name__ == '__main__':
    start_time = time.time()
    
    try:
        success = main()
        end_time = time.time()
        
        print(f"\n⏱️  Total execution time: {end_time - start_time:.2f} seconds")
        
        if success:
            print("\n🎊 Testing completed successfully!")
            sys.exit(0)
        else:
            print("\n💥 Testing completed with failures!")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⚡ Testing interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n💥 Unexpected error during testing: {e}")
        sys.exit(1)