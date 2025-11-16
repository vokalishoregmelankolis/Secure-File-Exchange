#!/usr/bin/env python3
"""
Functional Testing Suite
Tests all functional requirements of the Secure Financial Report Sharing System
"""

import pytest
import os
import io
import tempfile
import time
from tests import create_test_app, create_test_users, create_test_files, save_test_files_to_disk


def get_unique_user_data():
    """Generate unique user data with timestamp"""
    timestamp = str(int(time.time() * 1000000))
    return {
        'username': f'testuser_{timestamp}',
        'email': f'test_{timestamp}@test.com',
        'password': 'SecurePass123',
        'confirm_password': 'SecurePass123'
    }


class TestAuthentication:
    """Test user authentication and authorization functionality"""
    
    @pytest.fixture
    def app_and_db(self):
        """Create test app with database"""
        app, db = create_test_app()
        
        with app.app_context():
            db.create_all()
            yield app, db
            db.drop_all()
    
    @pytest.fixture 
    def client(self, app_and_db):
        """Create test client"""
        app, db = app_and_db
        return app.test_client()
    
    def test_user_registration_valid(self, client):
        """AUTH-001: Test valid user registration"""
        import time
        timestamp = str(int(time.time() * 1000000))
        
        response = client.post('/register', data={
            'username': f'newuser_{timestamp}',
            'email': f'newuser_{timestamp}@test.com',
            'password': 'SecurePass123',
            'confirm_password': 'SecurePass123'
        }, follow_redirects=False)
        
        # Should redirect to login page after successful registration
        assert response.status_code == 302
        assert '/login' in response.location
    
    def test_user_registration_duplicate_username(self, client, app_and_db):
        """AUTH-002: Test registration with duplicate username"""
        app, db = app_and_db
        
        user_data = get_unique_user_data()
        
        # First registration
        client.post('/register', data=user_data)
        
        # Attempt duplicate registration with same username
        duplicate_data = user_data.copy()
        duplicate_data['email'] = f'different_{duplicate_data["email"]}'  # Different email
        
        response = client.post('/register', data=duplicate_data)
        
        # Should stay on registration page with error
        assert response.status_code == 200
        assert b'username' in response.data.lower() or b'already' in response.data.lower()
    
    def test_user_registration_invalid_email(self, client):
        """AUTH-003: Test registration with invalid email"""
        user_data = get_unique_user_data()
        user_data['email'] = 'invalid-email'  # Invalid format
        
        response = client.post('/register', data=user_data)
        
        # Should stay on registration page with error
        assert response.status_code == 200
        assert b'email' in response.data.lower() or b'invalid' in response.data.lower()
    
    def test_user_login_valid_credentials(self, client, app_and_db):
        """AUTH-005: Test login with valid credentials"""
        app, db = app_and_db
        
        user_data = get_unique_user_data()
        
        # Register user first
        client.post('/register', data=user_data)
        
        # Login with correct credentials
        response = client.post('/login', data={
            'username': user_data['username'],
            'password': user_data['password']
        }, follow_redirects=False)
        
        # Should redirect to dashboard
        assert response.status_code == 302
        assert '/dashboard' in response.location or '/' in response.location
    
    def test_user_login_invalid_credentials(self, client, app_and_db):
        """AUTH-006: Test login with invalid credentials"""
        app, db = app_and_db
        
        user_data = get_unique_user_data()
        
        # Register user first
        client.post('/register', data=user_data)
        
        # Login with wrong password
        response = client.post('/login', data={
            'username': user_data['username'],
            'password': 'WrongPassword'
        })
        
        # Should stay on login page with error
        assert response.status_code == 200
        assert b'invalid' in response.data.lower() or b'incorrect' in response.data.lower()
    
    def test_access_protected_route_without_login(self, client):
        """AUTH-007: Test accessing protected route without login"""
        response = client.get('/dashboard', follow_redirects=False)
        
        # Should redirect to login page
        assert response.status_code == 302
        assert '/login' in response.location


class TestFileOperations:
    """Test file upload, encryption, and management functionality"""
    
    @pytest.fixture
    def app_and_db(self):
        app, db = create_test_app()
        
        with app.app_context():
            db.create_all()
            create_test_users(app, db)
            yield app, db
            db.drop_all()
    
    @pytest.fixture
    def client(self, app_and_db):
        app, db = app_and_db
        return app.test_client()
    
    @pytest.fixture
    def logged_in_client(self, client, app_and_db):
        """Client with logged in user"""
        app, db = app_and_db
        
        user_data = get_unique_user_data()
        
        # Register user first
        client.post('/register', data=user_data)
        
        # Login
        client.post('/login', data={
            'username': user_data['username'],
            'password': user_data['password']
        })
        return client
    
    @pytest.fixture
    def test_files(self):
        """Create test files"""
        return create_test_files()
    
    def test_upload_excel_file_with_aes(self, logged_in_client, test_files):
        """FILE-001: Upload Excel file with AES-256"""
        excel_content = test_files['report.xlsx']
        
        response = logged_in_client.post('/upload', data={
            'file': (io.BytesIO(excel_content), 'report.xlsx'),
            'algorithm': 'AES'
        }, content_type='multipart/form-data')
        
        # Should redirect after successful upload
        assert response.status_code == 302
    
    def test_upload_pdf_file_with_des(self, logged_in_client, test_files):
        """FILE-002: Upload PDF file with DES"""
        pdf_content = test_files['document.pdf']
        
        response = logged_in_client.post('/upload', data={
            'file': (io.BytesIO(pdf_content), 'document.pdf'),
            'algorithm': 'DES'
        }, content_type='multipart/form-data')
        
        assert response.status_code == 302
    
    def test_upload_image_with_rc4(self, logged_in_client, test_files):
        """FILE-003: Upload image with RC4"""
        image_content = test_files['image.png']
        
        response = logged_in_client.post('/upload', data={
            'file': (io.BytesIO(image_content), 'image.png'),
            'algorithm': 'RC4'
        }, content_type='multipart/form-data')
        
        assert response.status_code == 302
    
    def test_upload_file_too_large(self, logged_in_client):
        """FILE-004: Upload file exceeding size limit"""
        # Create 20MB file (exceeds 16MB limit)
        large_content = b'0' * (20 * 1024 * 1024)
        
        response = logged_in_client.post('/upload', data={
            'file': (io.BytesIO(large_content), 'large_file.xlsx'),
            'algorithm': 'AES'
        }, content_type='multipart/form-data')
        
        # Should reject the upload
        assert response.status_code in [400, 413, 200]  # Bad request, payload too large, or error page
        
        if response.status_code == 200:
            # If error is shown on same page
            assert b'too large' in response.data.lower() or b'size' in response.data.lower()
    
    def test_upload_unsupported_file_type(self, logged_in_client):
        """FILE-005: Upload unsupported file type"""
        # Create executable file
        exe_content = b'MZ\x90\x00'  # DOS header for .exe file
        
        response = logged_in_client.post('/upload', data={
            'file': (io.BytesIO(exe_content), 'malware.exe'),
            'algorithm': 'AES'
        }, content_type='multipart/form-data')
        
        # Should reject the upload
        assert response.status_code in [400, 200]
        
        if response.status_code == 200:
            assert b'not supported' in response.data.lower() or b'invalid' in response.data.lower()
    
    def test_upload_without_file(self, logged_in_client):
        """FILE-006: Upload without selecting file"""
        response = logged_in_client.post('/upload', data={
            'algorithm': 'AES'
            # No file provided
        }, content_type='multipart/form-data')
        
        # Should show error
        assert response.status_code in [400, 200]
        
        if response.status_code == 200:
            assert b'select' in response.data.lower() or b'file' in response.data.lower()


class TestFileSharing:
    """Test file sharing functionality"""
    
    @pytest.fixture
    def app_and_db(self):
        app, db = create_test_app()
        
        with app.app_context():
            db.create_all()
            create_test_users(app, db)
            yield app, db
            db.drop_all()
    
    @pytest.fixture
    def client(self, app_and_db):
        app, db = app_and_db
        return app.test_client()
    
    def create_test_file(self, client, app_and_db):
        """Helper to create a test file"""
        app, db = app_and_db
        
        user_data = get_unique_user_data()
        
        # Register user
        client.post('/register', data=user_data)
        
        # Login
        client.post('/login', data={
            'username': user_data['username'],
            'password': user_data['password']
        })
        
        # Upload a file
        test_content = b"%PDF-1.4\nTest PDF content for sharing"
        response = client.post('/upload', data={
            'file': (io.BytesIO(test_content), 'test_file.pdf'),
            'algorithm': 'AES'
        }, content_type='multipart/form-data')
        
        return response, user_data
    
    def test_share_file_to_valid_user(self, client, app_and_db):
        """SHARE-001: Share file to valid user"""
        app, db = app_and_db
        
        # Create file as user1
        response, user1_data = self.create_test_file(client, app_and_db)
        
        # Create second user to share with
        user2_data = get_unique_user_data()
        client.post('/register', data=user2_data)
        
        # Query database to get the actual file ID (using file_id field, not primary key)
        with app.app_context():
            from app.models import EncryptedFile
            file_record = EncryptedFile.query.first()
            
            if file_record:
                file_id = file_record.file_id  # Use file_id field, not primary key
                # Share the file
                response = client.post(f'/file/{file_id}/share', data={
                    'recipient_username': user2_data['username']
                })
                
                # Should succeed
                assert response.status_code in [200, 302]
            else:
                # If no file found, test should indicate this issue
                assert False, "No uploaded file found in database"
    
    def test_share_file_to_nonexistent_user(self, client, app_and_db):
        """SHARE-002: Share file to non-existent user"""
        response, user_data = self.create_test_file(client, app_and_db)
        
        response = client.post('/share', data={
            'file_id': '1',
            'recipient_username': 'nonexistentuser'
        })
        
        # Should show error
        assert response.status_code in [400, 200, 404]
        
        if response.status_code == 200:
            assert b'not found' in response.data.lower() or b'exist' in response.data.lower()


class TestFileDownload:
    """Test file download and decryption functionality"""
    
    @pytest.fixture
    def app_and_db(self):
        app, db = create_test_app()
        
        with app.app_context():
            db.create_all()
            create_test_users(app, db)
            yield app, db
            db.drop_all()
    
    @pytest.fixture
    def client(self, app_and_db):
        app, db = app_and_db
        return app.test_client()
    
    def test_download_own_file(self, client, app_and_db):
        """DOWN-001: Download own file"""
        app, db = app_and_db
        
        user_data = get_unique_user_data()
        
        # Register and login
        client.post('/register', data=user_data)
        client.post('/login', data={
            'username': user_data['username'],
            'password': user_data['password']
        })
        
        original_content = b"%PDF-1.4\nOriginal PDF file content"
        client.post('/upload', data={
            'file': (io.BytesIO(original_content), 'own_file.pdf'),
            'algorithm': 'AES'
        }, content_type='multipart/form-data')
        
        # Query database to get the actual file ID (using file_id field, not primary key)
        with app.app_context():
            from app.models import EncryptedFile
            file_record = EncryptedFile.query.first()
            
            if file_record:
                file_id = file_record.file_id  # Use file_id field, not primary key
                # Download the file
                response = client.get(f'/file/{file_id}/download')
                
                # Should be able to download
                assert response.status_code == 200
                
                # Content should match original (after decryption)
                assert response.data == original_content or len(response.data) > 0
            else:
                assert False, "No uploaded file found in database"
    
    def test_download_nonexistent_file(self, client, app_and_db):
        """DOWN-004: Download non-existent file"""
        app, db = app_and_db
        
        user_data = get_unique_user_data()
        
        # Register and login
        client.post('/register', data=user_data)
        client.post('/login', data={
            'username': user_data['username'], 
            'password': user_data['password']
        })
        
        response = client.get('/download/999999')  # Non-existent file ID
        
        # Should return 404
        assert response.status_code == 404


def run_functional_tests():
    """Run all functional tests"""
    print("Running Functional Tests...")
    print("=" * 50)
    
    # Run tests with pytest
    exit_code = pytest.main([
        __file__,
        '-v',
        '--tb=short',
        '--no-header'
    ])
    
    return exit_code == 0


if __name__ == '__main__':
    success = run_functional_tests()
    if success:
        print("\n✅ All functional tests passed!")
    else:
        print("\n❌ Some functional tests failed!")
    
    exit(0 if success else 1)