"""
Unit Tests for Consultant File Download

This module contains unit tests for consultant file download functionality,
verifying that consultants can download files with approved access and
that access control is properly enforced.

Requirements tested: 7.1, 7.2, 7.3, 7.5
"""

import os
import sys
import pytest
import tempfile
from io import BytesIO
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
from app.models import User, EncryptedFile, AccessRequest, UserRole, CryptoLog
from app.asymmetric_crypto import AsymmetricCrypto
from app.key_store import KeyStore
from app.crypto_utils import CryptoEngine


@pytest.fixture(scope='function')
def app_context():
    """Create Flask app context for testing"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture(scope='function')
def client(app_context):
    """Create test client"""
    return app_context.test_client()


class TestConsultantDownload:
    """Unit tests for consultant file download functionality"""
    
    def test_download_succeeds_with_approved_access(self, client, app_context):
        """
        Test that download succeeds when consultant has approved access.
        
        Requirements: 7.1, 7.2, 7.3
        """
        # Create organization user
        org_user = User(
            username='org_user_test',
            email='org@test.com',
            role=UserRole.ORGANIZATION
        )
        org_user.set_password('password123')
        db.session.add(org_user)
        db.session.flush()
        
        # Create consultant user
        consultant = User(
            username='consultant_test',
            email='consultant@test.com',
            role=UserRole.CONSULTANT
        )
        consultant.set_password('password123')
        db.session.add(consultant)
        db.session.flush()
        
        # Create a temporary encrypted file with actual encrypted content
        test_content = b'This is test file content for download testing.'
        
        # Encrypt the content using AES
        encrypted_data, wrapped_key, iv, _ = CryptoEngine.encrypt_aes(test_content)
        
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='_encrypted')
        temp_file.write(encrypted_data)
        temp_file.close()
        
        try:
            # Create file record
            file = EncryptedFile(
                file_id='test-file-download-001',
                filename='test_encrypted',
                original_filename='test.txt',
                file_type='text',
                file_size=len(test_content),
                encrypted_path=temp_file.name,
                algorithm='AES',
                wrapped_key=wrapped_key,
                iv=iv,
                user_id=org_user.id
            )
            db.session.add(file)
            db.session.flush()
            
            # Generate RSA keys for consultant
            public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
            consultant.public_key = public_key
            
            # Unwrap the DEK from KEK wrapping
            from app.crypto_utils import _unwrap_key
            dek = _unwrap_key(wrapped_key)
            
            # Wrap DEK with consultant's public key
            wrapped_symmetric_key = AsymmetricCrypto.wrap_symmetric_key(dek, public_key)
            
            # Create approved access request
            access_request = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org_user.id,
                file_id=file.id,
                status='approved',
                wrapped_symmetric_key=wrapped_symmetric_key
            )
            db.session.add(access_request)
            db.session.commit()
            
            # Log in as consultant
            with client.session_transaction() as sess:
                sess['_user_id'] = str(consultant.id)
                sess['_fresh'] = True
                # Store decrypted symmetric key in session
                sess[f'symmetric_key_{access_request.id}'] = dek.hex()
            
            # Attempt to download file
            response = client.get(f'/file/{file.file_id}/download')
            
            # Verify download succeeds
            assert response.status_code == 200, \
                f"Download should succeed with approved access (got {response.status_code})"
            
            # Verify content is decrypted correctly
            assert response.data == test_content, \
                "Downloaded content should match original"
            
            # Verify download was logged
            log = CryptoLog.query.filter_by(
                user_id=consultant.id,
                operation='download'
            ).first()
            # Note: The current implementation uses EncryptionLog, not CryptoLog for downloads
            # So we'll check the response instead
            
        finally:
            # Cleanup
            try:
                os.unlink(temp_file.name)
            except:
                pass
    
    def test_download_fails_without_approved_access(self, client, app_context):
        """
        Test that download fails when consultant doesn't have approved access.
        
        Requirements: 7.1
        """
        # Create organization user
        org_user = User(
            username='org_user_test2',
            email='org2@test.com',
            role=UserRole.ORGANIZATION
        )
        org_user.set_password('password123')
        db.session.add(org_user)
        db.session.flush()
        
        # Create consultant user
        consultant = User(
            username='consultant_test2',
            email='consultant2@test.com',
            role=UserRole.CONSULTANT
        )
        consultant.set_password('password123')
        db.session.add(consultant)
        db.session.flush()
        
        # Create a temporary encrypted file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='_encrypted')
        temp_file.write(b'encrypted_test_data')
        temp_file.close()
        
        try:
            # Create file record
            file = EncryptedFile(
                file_id='test-file-download-002',
                filename='test_encrypted',
                original_filename='test.txt',
                file_type='text',
                file_size=1024,
                encrypted_path=temp_file.name,
                algorithm='AES',
                wrapped_key=b'wrapped_key_data',
                iv=b'1234567890123456',
                user_id=org_user.id
            )
            db.session.add(file)
            db.session.commit()
            
            # Log in as consultant (no access request created)
            with client.session_transaction() as sess:
                sess['_user_id'] = str(consultant.id)
                sess['_fresh'] = True
            
            # Attempt to download file
            response = client.get(f'/file/{file.file_id}/download', follow_redirects=False)
            
            # Verify download is denied
            assert response.status_code == 302, \
                f"Download should be denied without approved access (got {response.status_code})"
            
            # Verify redirect is to dashboard or error page
            location = response.headers.get('Location', '')
            assert 'dashboard' in location or 'login' in location, \
                "Should redirect to dashboard or login"
            
        finally:
            # Cleanup
            try:
                os.unlink(temp_file.name)
            except:
                pass
    
    def test_download_fails_with_revoked_access(self, client, app_context):
        """
        Test that download fails when access has been revoked.
        
        Requirements: 7.1, 10.4
        """
        # Create organization user
        org_user = User(
            username='org_user_test3',
            email='org3@test.com',
            role=UserRole.ORGANIZATION
        )
        org_user.set_password('password123')
        db.session.add(org_user)
        db.session.flush()
        
        # Create consultant user
        consultant = User(
            username='consultant_test3',
            email='consultant3@test.com',
            role=UserRole.CONSULTANT
        )
        consultant.set_password('password123')
        db.session.add(consultant)
        db.session.flush()
        
        # Create a temporary encrypted file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='_encrypted')
        temp_file.write(b'encrypted_test_data')
        temp_file.close()
        
        try:
            # Create file record
            file = EncryptedFile(
                file_id='test-file-download-003',
                filename='test_encrypted',
                original_filename='test.txt',
                file_type='text',
                file_size=1024,
                encrypted_path=temp_file.name,
                algorithm='AES',
                wrapped_key=b'wrapped_key_data',
                iv=b'1234567890123456',
                user_id=org_user.id
            )
            db.session.add(file)
            db.session.flush()
            
            # Create revoked access request
            access_request = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org_user.id,
                file_id=file.id,
                status='revoked',
                wrapped_symmetric_key=b'wrapped_key'
            )
            db.session.add(access_request)
            db.session.commit()
            
            # Log in as consultant
            with client.session_transaction() as sess:
                sess['_user_id'] = str(consultant.id)
                sess['_fresh'] = True
            
            # Attempt to download file
            response = client.get(f'/file/{file.file_id}/download', follow_redirects=False)
            
            # Verify download is denied
            assert response.status_code == 302, \
                f"Download should be denied with revoked access (got {response.status_code})"
            
            # Verify redirect is to my-requests
            location = response.headers.get('Location', '')
            assert 'my-requests' in location or 'dashboard' in location, \
                "Should redirect to my-requests or dashboard"
            
        finally:
            # Cleanup
            try:
                os.unlink(temp_file.name)
            except:
                pass
    
    def test_download_logs_operation(self, client, app_context):
        """
        Test that download operation is logged.
        
        Requirements: 7.5
        """
        # Create organization user
        org_user = User(
            username='org_user_test4',
            email='org4@test.com',
            role=UserRole.ORGANIZATION
        )
        org_user.set_password('password123')
        db.session.add(org_user)
        db.session.flush()
        
        # Create consultant user
        consultant = User(
            username='consultant_test4',
            email='consultant4@test.com',
            role=UserRole.CONSULTANT
        )
        consultant.set_password('password123')
        db.session.add(consultant)
        db.session.flush()
        
        # Create a temporary encrypted file with actual encrypted content
        test_content = b'Test content for logging'
        encrypted_data, wrapped_key, iv, _ = CryptoEngine.encrypt_aes(test_content)
        
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='_encrypted')
        temp_file.write(encrypted_data)
        temp_file.close()
        
        try:
            # Create file record
            file = EncryptedFile(
                file_id='test-file-download-004',
                filename='test_encrypted',
                original_filename='test.txt',
                file_type='text',
                file_size=len(test_content),
                encrypted_path=temp_file.name,
                algorithm='AES',
                wrapped_key=wrapped_key,
                iv=iv,
                user_id=org_user.id
            )
            db.session.add(file)
            db.session.flush()
            
            # Generate RSA keys and create approved access
            public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
            consultant.public_key = public_key
            
            from app.crypto_utils import _unwrap_key
            dek = _unwrap_key(wrapped_key)
            wrapped_symmetric_key = AsymmetricCrypto.wrap_symmetric_key(dek, public_key)
            
            access_request = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org_user.id,
                file_id=file.id,
                status='approved',
                wrapped_symmetric_key=wrapped_symmetric_key
            )
            db.session.add(access_request)
            db.session.commit()
            
            # Log in as consultant
            with client.session_transaction() as sess:
                sess['_user_id'] = str(consultant.id)
                sess['_fresh'] = True
                sess[f'symmetric_key_{access_request.id}'] = dek.hex()
            
            # Download file
            response = client.get(f'/file/{file.file_id}/download')
            
            # Verify download succeeded
            assert response.status_code == 200
            
            # Verify operation was logged (using EncryptionLog model)
            from app.models import EncryptionLog
            log = EncryptionLog.query.filter_by(
                user_id=consultant.id,
                file_id=file.file_id,
                operation='download'
            ).first()
            
            assert log is not None, "Download operation should be logged"
            assert log.success == True, "Log should indicate success"
            assert log.algorithm == 'AES', "Log should record algorithm"
            
        finally:
            # Cleanup
            try:
                os.unlink(temp_file.name)
            except:
                pass
    
    def test_file_decrypts_correctly(self, client, app_context):
        """
        Test that file is decrypted correctly for consultant download.
        
        Requirements: 7.2, 7.3
        """
        # Create organization user
        org_user = User(
            username='org_user_test5',
            email='org5@test.com',
            role=UserRole.ORGANIZATION
        )
        org_user.set_password('password123')
        db.session.add(org_user)
        db.session.flush()
        
        # Create consultant user
        consultant = User(
            username='consultant_test5',
            email='consultant5@test.com',
            role=UserRole.CONSULTANT
        )
        consultant.set_password('password123')
        db.session.add(consultant)
        db.session.flush()
        
        # Create test content with specific pattern
        test_content = b'SPECIFIC_TEST_PATTERN_FOR_DECRYPTION_VERIFICATION_12345'
        
        # Encrypt the content
        encrypted_data, wrapped_key, iv, _ = CryptoEngine.encrypt_aes(test_content)
        
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='_encrypted')
        temp_file.write(encrypted_data)
        temp_file.close()
        
        try:
            # Create file record
            file = EncryptedFile(
                file_id='test-file-download-005',
                filename='test_encrypted',
                original_filename='test.txt',
                file_type='text',
                file_size=len(test_content),
                encrypted_path=temp_file.name,
                algorithm='AES',
                wrapped_key=wrapped_key,
                iv=iv,
                user_id=org_user.id
            )
            db.session.add(file)
            db.session.flush()
            
            # Generate RSA keys and create approved access
            public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
            consultant.public_key = public_key
            
            from app.crypto_utils import _unwrap_key
            dek = _unwrap_key(wrapped_key)
            wrapped_symmetric_key = AsymmetricCrypto.wrap_symmetric_key(dek, public_key)
            
            access_request = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org_user.id,
                file_id=file.id,
                status='approved',
                wrapped_symmetric_key=wrapped_symmetric_key
            )
            db.session.add(access_request)
            db.session.commit()
            
            # Log in as consultant
            with client.session_transaction() as sess:
                sess['_user_id'] = str(consultant.id)
                sess['_fresh'] = True
                sess[f'symmetric_key_{access_request.id}'] = dek.hex()
            
            # Download file
            response = client.get(f'/file/{file.file_id}/download')
            
            # Verify download succeeded
            assert response.status_code == 200, "Download should succeed"
            
            # Verify content matches exactly
            assert response.data == test_content, \
                f"Decrypted content should match original. Expected: {test_content}, Got: {response.data}"
            
            # Verify content contains expected pattern
            assert b'SPECIFIC_TEST_PATTERN' in response.data, \
                "Decrypted content should contain expected pattern"
            
        finally:
            # Cleanup
            try:
                os.unlink(temp_file.name)
            except:
                pass


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
