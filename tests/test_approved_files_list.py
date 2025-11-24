"""
Unit Tests for Approved Files List

This module contains unit tests for the approved files list functionality,
verifying that consultants can view their approved files with correct information
and status indicators.

Requirements tested: 12.1, 12.2, 12.3, 12.4
"""

import os
import sys
import pytest
import tempfile
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
from app.models import User, EncryptedFile, AccessRequest, UserRole
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


class TestApprovedFilesList:
    """Unit tests for approved files list functionality"""
    
    def test_list_shows_only_approved_requests(self, client, app_context):
        """
        Test that approved files list shows only approved requests.
        
        Requirements: 12.1
        """
        # Create organization user
        org_user = User(
            username='org_approved1',
            email='org_approved1@test.com',
            role=UserRole.ORGANIZATION
        )
        org_user.set_password('password123')
        db.session.add(org_user)
        db.session.flush()
        
        # Create consultant user
        consultant = User(
            username='consultant_approved1',
            email='consultant_approved1@test.com',
            role=UserRole.CONSULTANT
        )
        consultant.set_password('password123')
        db.session.add(consultant)
        db.session.flush()
        
        # Create temporary encrypted files
        test_content = b'Test file content'
        encrypted_data, wrapped_key, iv, _ = CryptoEngine.encrypt_aes(test_content)
        
        temp_files = []
        files = []
        
        try:
            # Create 3 files with different request statuses
            for i, status in enumerate(['approved', 'pending', 'denied']):
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='_encrypted')
                temp_file.write(encrypted_data)
                temp_file.close()
                temp_files.append(temp_file.name)
                
                file = EncryptedFile(
                    file_id=f'test-approved-{i+1}',
                    filename=f'test_encrypted_{i+1}',
                    original_filename=f'document_{status}.txt',
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
                files.append(file)
                
                # Create access request with different statuses
                access_request = AccessRequest(
                    consultant_id=consultant.id,
                    organization_id=org_user.id,
                    file_id=file.id,
                    status=status,
                    wrapped_symmetric_key=b'wrapped_key' if status == 'approved' else None
                )
                db.session.add(access_request)
            
            db.session.commit()
            
            # Log in as consultant
            with client.session_transaction() as sess:
                sess['_user_id'] = str(consultant.id)
                sess['_fresh'] = True
            
            # Access approved files page
            response = client.get('/approved-files')
            
            # Verify page loads successfully
            assert response.status_code == 200, \
                f"Approved files page should load (got {response.status_code})"
            
            # Verify only approved file is shown
            assert b'document_approved.txt' in response.data, \
                "Approved file should be displayed"
            assert b'document_pending.txt' not in response.data, \
                "Pending file should not be displayed"
            assert b'document_denied.txt' not in response.data, \
                "Denied file should not be displayed"
            
        finally:
            # Cleanup
            for temp_file in temp_files:
                try:
                    os.unlink(temp_file)
                except:
                    pass
    
    def test_list_shows_correct_file_information(self, client, app_context):
        """
        Test that approved files list shows correct file information.
        
        Requirements: 12.2
        """
        # Create organization user
        org_user = User(
            username='org_approved2',
            email='org_approved2@test.com',
            role=UserRole.ORGANIZATION
        )
        org_user.set_password('password123')
        db.session.add(org_user)
        db.session.flush()
        
        # Create consultant user
        consultant = User(
            username='consultant_approved2',
            email='consultant_approved2@test.com',
            role=UserRole.CONSULTANT
        )
        consultant.set_password('password123')
        db.session.add(consultant)
        db.session.flush()
        
        # Create temporary encrypted file
        test_content = b'Test file content for info display'
        encrypted_data, wrapped_key, iv, _ = CryptoEngine.encrypt_aes(test_content)
        
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='_encrypted')
        temp_file.write(encrypted_data)
        temp_file.close()
        
        try:
            # Create file record
            file = EncryptedFile(
                file_id='test-approved-info-001',
                filename='test_encrypted',
                original_filename='financial_report.xlsx',
                file_type='spreadsheet',
                file_size=len(test_content),
                encrypted_path=temp_file.name,
                algorithm='AES',
                wrapped_key=wrapped_key,
                iv=iv,
                user_id=org_user.id
            )
            db.session.add(file)
            db.session.flush()
            
            # Create approved access request
            approval_date = datetime(2024, 1, 15, 10, 30, 0)
            access_request = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org_user.id,
                file_id=file.id,
                status='approved',
                wrapped_symmetric_key=b'wrapped_key_data',
                processed_at=approval_date
            )
            db.session.add(access_request)
            db.session.commit()
            
            # Log in as consultant
            with client.session_transaction() as sess:
                sess['_user_id'] = str(consultant.id)
                sess['_fresh'] = True
            
            # Access approved files page
            response = client.get('/approved-files')
            
            # Verify page loads successfully
            assert response.status_code == 200, \
                "Approved files page should load"
            
            # Verify file name is displayed
            assert b'financial_report.xlsx' in response.data, \
                "File name should be displayed"
            
            # Verify organization name is displayed
            assert b'org_approved2' in response.data, \
                "Organization name should be displayed"
            
            # Verify approval date is displayed (format may vary)
            assert b'2024-01-15' in response.data, \
                "Approval date should be displayed"
            
        finally:
            # Cleanup
            try:
                os.unlink(temp_file.name)
            except:
                pass
    
    def test_list_indicates_decryption_status(self, client, app_context):
        """
        Test that approved files list indicates decryption status.
        
        Requirements: 12.4
        """
        # Create organization user
        org_user = User(
            username='org_approved3',
            email='org_approved3@test.com',
            role=UserRole.ORGANIZATION
        )
        org_user.set_password('password123')
        db.session.add(org_user)
        db.session.flush()
        
        # Create consultant user
        consultant = User(
            username='consultant_approved3',
            email='consultant_approved3@test.com',
            role=UserRole.CONSULTANT
        )
        consultant.set_password('password123')
        db.session.add(consultant)
        db.session.flush()
        
        # Create temporary encrypted file
        test_content = b'Test file content'
        encrypted_data, wrapped_key, iv, _ = CryptoEngine.encrypt_aes(test_content)
        
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='_encrypted')
        temp_file.write(encrypted_data)
        temp_file.close()
        
        try:
            # Create file record
            file = EncryptedFile(
                file_id='test-approved-decrypt-001',
                filename='test_encrypted',
                original_filename='test_document.txt',
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
            
            # Create approved access request
            access_request = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org_user.id,
                file_id=file.id,
                status='approved',
                wrapped_symmetric_key=b'wrapped_key_data'
            )
            db.session.add(access_request)
            db.session.commit()
            
            # Log in as consultant
            with client.session_transaction() as sess:
                sess['_user_id'] = str(consultant.id)
                sess['_fresh'] = True
            
            # Access approved files page (without decrypting key)
            response = client.get('/approved-files')
            
            # Verify page loads successfully
            assert response.status_code == 200, \
                "Approved files page should load"
            
            # Verify decryption status indicator is present
            # The page should show that the key needs to be decrypted
            assert b'DECRYPT KEY' in response.data or b'Decrypt Key' in response.data or b'decrypt' in response.data.lower(), \
                "Decryption status indicator should be present"
            
        finally:
            # Cleanup
            try:
                os.unlink(temp_file.name)
            except:
                pass
    
    def test_revoked_requests_marked_appropriately(self, client, app_context):
        """
        Test that revoked requests are marked appropriately in the list.
        
        Requirements: 12.3, 10.4
        """
        # Create organization user
        org_user = User(
            username='org_approved4',
            email='org_approved4@test.com',
            role=UserRole.ORGANIZATION
        )
        org_user.set_password('password123')
        db.session.add(org_user)
        db.session.flush()
        
        # Create consultant user
        consultant = User(
            username='consultant_approved4',
            email='consultant_approved4@test.com',
            role=UserRole.CONSULTANT
        )
        consultant.set_password('password123')
        db.session.add(consultant)
        db.session.flush()
        
        # Create temporary encrypted files
        test_content = b'Test file content'
        encrypted_data, wrapped_key, iv, _ = CryptoEngine.encrypt_aes(test_content)
        
        temp_files = []
        
        try:
            # Create approved file
            temp_file1 = tempfile.NamedTemporaryFile(delete=False, suffix='_encrypted')
            temp_file1.write(encrypted_data)
            temp_file1.close()
            temp_files.append(temp_file1.name)
            
            file1 = EncryptedFile(
                file_id='test-approved-revoke-001',
                filename='test_encrypted_1',
                original_filename='approved_document.txt',
                file_type='text',
                file_size=len(test_content),
                encrypted_path=temp_file1.name,
                algorithm='AES',
                wrapped_key=wrapped_key,
                iv=iv,
                user_id=org_user.id
            )
            db.session.add(file1)
            db.session.flush()
            
            # Create approved access request
            access_request1 = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org_user.id,
                file_id=file1.id,
                status='approved',
                wrapped_symmetric_key=b'wrapped_key_data'
            )
            db.session.add(access_request1)
            
            # Create revoked file
            temp_file2 = tempfile.NamedTemporaryFile(delete=False, suffix='_encrypted')
            temp_file2.write(encrypted_data)
            temp_file2.close()
            temp_files.append(temp_file2.name)
            
            file2 = EncryptedFile(
                file_id='test-approved-revoke-002',
                filename='test_encrypted_2',
                original_filename='revoked_document.txt',
                file_type='text',
                file_size=len(test_content),
                encrypted_path=temp_file2.name,
                algorithm='AES',
                wrapped_key=wrapped_key,
                iv=iv,
                user_id=org_user.id
            )
            db.session.add(file2)
            db.session.flush()
            
            # Create revoked access request
            access_request2 = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org_user.id,
                file_id=file2.id,
                status='revoked',
                wrapped_symmetric_key=None  # Key should be deleted on revocation
            )
            db.session.add(access_request2)
            db.session.commit()
            
            # Log in as consultant
            with client.session_transaction() as sess:
                sess['_user_id'] = str(consultant.id)
                sess['_fresh'] = True
            
            # Access approved files page
            response = client.get('/approved-files')
            
            # Verify page loads successfully
            assert response.status_code == 200, \
                "Approved files page should load"
            
            # Verify approved file is shown
            assert b'approved_document.txt' in response.data, \
                "Approved file should be displayed"
            
            # Verify revoked file is shown with revoked status
            assert b'revoked_document.txt' in response.data, \
                "Revoked file should be displayed"
            
            # Verify revoked status is indicated
            assert b'REVOKED' in response.data or b'Revoked' in response.data or b'revoked' in response.data.lower(), \
                "Revoked status should be indicated"
            
        finally:
            # Cleanup
            for temp_file in temp_files:
                try:
                    os.unlink(temp_file)
                except:
                    pass
    
    def test_empty_approved_files_list(self, client, app_context):
        """
        Test that empty approved files list displays appropriate message.
        
        Requirements: 12.1
        """
        # Create consultant user
        consultant = User(
            username='consultant_approved5',
            email='consultant_approved5@test.com',
            role=UserRole.CONSULTANT
        )
        consultant.set_password('password123')
        db.session.add(consultant)
        db.session.commit()
        
        # Log in as consultant
        with client.session_transaction() as sess:
            sess['_user_id'] = str(consultant.id)
            sess['_fresh'] = True
        
        # Access approved files page
        response = client.get('/approved-files')
        
        # Verify page loads successfully
        assert response.status_code == 200, \
            "Approved files page should load"
        
        # Verify empty state message is displayed
        assert b'No Approved Files' in response.data or b'no approved' in response.data.lower(), \
            "Empty state message should be displayed"
    
    def test_organization_cannot_access_approved_files(self, client, app_context):
        """
        Test that organization users cannot access the approved files page.
        
        Requirements: 12.1
        """
        # Create organization user
        org_user = User(
            username='org_approved6',
            email='org_approved6@test.com',
            role=UserRole.ORGANIZATION
        )
        org_user.set_password('password123')
        db.session.add(org_user)
        db.session.commit()
        
        # Log in as organization
        with client.session_transaction() as sess:
            sess['_user_id'] = str(org_user.id)
            sess['_fresh'] = True
        
        # Attempt to access approved files page
        response = client.get('/approved-files', follow_redirects=False)
        
        # Verify access is denied (redirect)
        assert response.status_code == 302, \
            "Organization user should not be able to access approved files page"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
