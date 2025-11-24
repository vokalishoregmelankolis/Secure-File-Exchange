# Test Setup and Utilities

import os
import sys
import tempfile
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def create_test_app():
    """Create Flask app configured for testing"""
    from app import create_app, db
    
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SECRET_KEY'] = 'test-secret-key'
    
    return app, db

def create_test_users(app, db):
    """Create test users for testing"""
    import time
    from app.models import User
    
    with app.app_context():
        # Add timestamp to ensure uniqueness
        timestamp = str(int(time.time() * 1000000))  # microseconds
        users_data = [
            {'username': f'testuser1_{timestamp}', 'email': f'user1_{timestamp}@test.com', 'password': 'TestPass123'},
            {'username': f'testuser2_{timestamp}', 'email': f'user2_{timestamp}@test.com', 'password': 'TestPass123'},
            {'username': f'testuser3_{timestamp}', 'email': f'user3_{timestamp}@test.com', 'password': 'TestPass123'},
            {'username': f'admin_{timestamp}', 'email': f'admin_{timestamp}@test.com', 'password': 'AdminPass123'}
        ]
        
        created_users = []
        for user_data in users_data:
            user = User(username=user_data['username'], email=user_data['email'])
            user.set_password(user_data['password'])
            db.session.add(user)
            created_users.append(user)
        
        db.session.commit()
        return created_users

def create_test_files():
    """Create test files of various sizes"""
    test_files = {}
    
    # Small text file
    test_files['small.txt'] = b"This is a small test file content."
    
    # Medium file (1MB)
    test_files['medium.dat'] = os.urandom(1024 * 1024)
    
    # Large file (5MB) 
    test_files['large.dat'] = os.urandom(5 * 1024 * 1024)
    
    # Excel-like content
    test_files['report.xlsx'] = b"PK\x03\x04" + os.urandom(10240)  # Fake Excel header + random data
    
    # PDF-like content
    test_files['document.pdf'] = b"%PDF-1.4" + os.urandom(5120)  # Fake PDF header + random data
    
    # Image-like content
    test_files['image.png'] = b"\x89PNG\r\n\x1a\n" + os.urandom(2048)  # PNG header + random data
    
    return test_files

def save_test_files_to_disk(test_files, directory):
    """Save test files to disk for upload testing"""
    os.makedirs(directory, exist_ok=True)
    
    file_paths = {}
    for filename, content in test_files.items():
        file_path = os.path.join(directory, filename)
        with open(file_path, 'wb') as f:
            f.write(content)
        file_paths[filename] = file_path
    
    return file_paths

class TestConfig:
    """Test configuration constants"""
    
    # Performance benchmarks (in milliseconds)
    ENCRYPTION_TIME_LIMITS = {
        'AES-256': {'1MB': 200, '5MB': 1000, '10MB': 2000},
        'DES': {'1MB': 100, '5MB': 500, '10MB': 1000}, 
        'RC4': {'1MB': 50, '5MB': 250, '10MB': 500}
    }
    
    # Security test payloads
    SQL_INJECTION_PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users --",
        "admin'--",
        "' OR 1=1 #"
    ]
    
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')></iframe>",
        "<svg onload=alert('XSS')>"
    ]
    
    # File upload test cases
    MALICIOUS_FILENAMES = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "test.php.jpg",
        "malicious.exe",
        "script.js",
        "<script>alert('xss')</script>.txt"
    ]
    
    # Load testing configuration
    LOAD_TEST_CONFIG = {
        'concurrent_users': [1, 5, 10, 25, 50],
        'test_duration': 60,  # seconds
        'ramp_up_time': 10    # seconds
    }

def cleanup_test_files(directory):
    """Clean up test files after testing"""
    import shutil
    if os.path.exists(directory):
        shutil.rmtree(directory)

def assert_response_time(func, max_time_ms, *args, **kwargs):
    """Assert that a function completes within specified time"""
    import time
    
    start_time = time.perf_counter()
    result = func(*args, **kwargs)
    end_time = time.perf_counter()
    
    execution_time_ms = (end_time - start_time) * 1000
    
    assert execution_time_ms <= max_time_ms, \
        f"Function took {execution_time_ms:.2f}ms, expected <= {max_time_ms}ms"
    
    return result, execution_time_ms

def generate_performance_report(results):
    """Generate formatted performance test report"""
    
    report = []
    report.append("=" * 80)
    report.append("PERFORMANCE TEST REPORT")
    report.append("=" * 80)
    report.append("")
    
    for test_name, data in results.items():
        report.append(f"Test: {test_name}")
        report.append("-" * 40)
        
        if isinstance(data, dict):
            for metric, value in data.items():
                if isinstance(value, float):
                    report.append(f"  {metric}: {value:.2f}")
                else:
                    report.append(f"  {metric}: {value}")
        else:
            report.append(f"  Result: {data}")
        
        report.append("")
    
    return "\n".join(report)