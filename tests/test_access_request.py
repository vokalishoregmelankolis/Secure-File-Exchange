"""
Unit Tests for Access Request Submission

This module contains unit tests for the access request submission workflow,
including request creation, duplicate prevention, and field validation.

Requirements: 2.2, 2.3, 2.4
"""

import pytest
from unittest.mock import patch, MagicMock
from tests import create_test_app
from app.models import User, UserRole, EncryptedFile, AccessRequest, CryptoLog
from datetime import datetime


class TestAccessRequestSubmission:
    """Unit tests for access request submission"""
    
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
    
    @pytest.fixture
    def test_users(self, app_and_db):
        """Create test users (organization and consultant)"""
        app, db = app_and_db
        
        with app.app_context():
            # Create organization user
            org_user = User(
                username='org_user',
                email='org@example.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('password123')
            
            # Create consultant user
            consultant_user = User(
                username='consultant_user',
                email='consultant@example.com',
                role=UserRole.CONSULTANT
            )
            consultant_user.set_password('password123')
            
            db.session.add(org_user)
            db.session.add(consultant_user)
            db.session.commit()
            
            return {
                'organization': org_user,
                'consultant': consultant_user
            }
    
    @pytest.fixture
    def test_file(self, app_and_db, test_users):
        """Create test encrypted file"""
        app, db = app_and_db
        
        with app.app_context():
            org_user = User.query.filter_by(username='org_user').first()
            
            file = EncryptedFile(
                file_id='test-file-123',
                filename='test_encrypted',
                original_filename='test.txt',
                file_type='text',
                file_size=1024,
                encrypted_path='/path/to/encrypted',
                algorithm='AES',
                wrapped_key=b'wrapped_key_data',
                iv=b'initialization_vector',
                user_id=org_user.id
            )
            
            db.session.add(file)
            db.session.commit()
            
            return file
    
    def test_request_creation_with_valid_data(self, app_and_db, client, test_users, test_file):
        """Test request creation with valid data"""
        app, db = app_and_db
        
        with app.app_context():
            consultant = User.query.filter_by(username='consultant_user').first()
            file = EncryptedFile.query.filter_by(file_id='test-file-123').first()
            
            # Login as consultant
            client.post('/login', data={
                'username': 'consultant_user',
                'password': 'password123'
            })
            
            # Submit access request
            response = client.post(f'/request-access/{file.id}', data={
                'message': 'I need access to this file for audit purposes',
                'submit': 'Submit Request'
            }, follow_redirects=False)
            
            # Verify redirect
            assert response.status_code == 302
            
            # Verify request was created
            request = AccessRequest.query.filter_by(
                consultant_id=consultant.id,
                file_id=file.id
            ).first()
            
            assert request is not None
            assert request.status == 'pending'
            assert request.organization_id == file.user_id
            assert request.requested_at is not None
            assert request.processed_at is None
            assert request.wrapped_symmetric_key is None
    
    def test_duplicate_request_prevention(self, app_and_db, client, test_users, test_file):
        """Test duplicate request prevention"""
        app, db = app_and_db
        
        with app.app_context():
            consultant = User.query.filter_by(username='consultant_user').first()
            file = EncryptedFile.query.filter_by(file_id='test-file-123').first()
            
            # Create existing request
            existing_request = AccessRequest(
                consultant_id=consultant.id,
                organization_id=file.user_id,
                file_id=file.id,
                status='pending'
            )
            db.session.add(existing_request)
            db.session.commit()
            
            # Login as consultant
            client.post('/login', data={
                'username': 'consultant_user',
                'password': 'password123'
            })
            
            # Try to submit duplicate request
            response = client.post(f'/request-access/{file.id}', data={
                'message': 'Another request',
                'submit': 'Submit Request'
            }, follow_redirects=True)
            
            # Verify error message
            assert b'already have' in response.data or b'pending' in response.data
            
            # Verify only one request exists
            requests = AccessRequest.query.filter_by(
                consultant_id=consultant.id,
                file_id=file.id
            ).all()
            
            assert len(requests) == 1
    
    def test_request_stores_all_required_fields(self, app_and_db, client, test_users, test_file):
        """Test request stores all required fields"""
        app, db = app_and_db
        
        with app.app_context():
            consultant = User.query.filter_by(username='consultant_user').first()
            org_user = User.query.filter_by(username='org_user').first()
            file = EncryptedFile.query.filter_by(file_id='test-file-123').first()
            
            # Login as consultant
            client.post('/login', data={
                'username': 'consultant_user',
                'password': 'password123'
            })
            
            # Submit access request
            client.post(f'/request-access/{file.id}', data={
                'message': 'Test message',
                'submit': 'Submit Request'
            })
            
            # Verify all required fields
            request = AccessRequest.query.filter_by(
                consultant_id=consultant.id,
                file_id=file.id
            ).first()
            
            # Requirement 2.4: consultant_id, organization_id, file_id, timestamp
            assert request.consultant_id == consultant.id
            assert request.organization_id == org_user.id
            assert request.file_id == file.id
            assert request.requested_at is not None
            assert isinstance(request.requested_at, datetime)
            
            # Verify relationships work
            assert request.consultant.username == 'consultant_user'
            assert request.organization.username == 'org_user'
            assert request.file.file_id == 'test-file-123'
    
    def test_consultant_can_only_request_their_own_access(self, app_and_db, client, test_users, test_file):
        """Test consultant can only request their own access"""
        app, db = app_and_db
        
        with app.app_context():
            # Create another consultant
            consultant2 = User(
                username='consultant2',
                email='consultant2@example.com',
                role=UserRole.CONSULTANT
            )
            consultant2.set_password('password123')
            db.session.add(consultant2)
            db.session.commit()
            
            consultant1 = User.query.filter_by(username='consultant_user').first()
            file = EncryptedFile.query.filter_by(file_id='test-file-123').first()
            
            # Login as consultant1
            client.post('/login', data={
                'username': 'consultant_user',
                'password': 'password123'
            })
            
            # Submit request
            client.post(f'/request-access/{file.id}', data={
                'message': 'Request from consultant1',
                'submit': 'Submit Request'
            })
            
            # Verify request is associated with logged-in consultant
            request = AccessRequest.query.filter_by(file_id=file.id).first()
            assert request.consultant_id == consultant1.id
            assert request.consultant_id != consultant2.id
            
            # Verify consultant2 cannot see consultant1's request as their own
            # (This is enforced by the route checking current_user.id)
    
    def test_organization_cannot_request_access(self, app_and_db, client, test_users, test_file):
        """Test organization users cannot request access"""
        app, db = app_and_db
        
        with app.app_context():
            file = EncryptedFile.query.filter_by(file_id='test-file-123').first()
            
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Try to request access
            response = client.post(f'/request-access/{file.id}', data={
                'message': 'Request from org',
                'submit': 'Submit Request'
            }, follow_redirects=True)
            
            # Verify access denied
            assert b'Access denied' in response.data or b'Only consultants' in response.data
            
            # Verify no request was created
            org_user = User.query.filter_by(username='org_user').first()
            request = AccessRequest.query.filter_by(
                consultant_id=org_user.id,
                file_id=file.id
            ).first()
            
            assert request is None
    
    def test_request_default_status_is_pending(self, app_and_db, client, test_users, test_file):
        """Test request default status is pending"""
        app, db = app_and_db
        
        with app.app_context():
            consultant = User.query.filter_by(username='consultant_user').first()
            file = EncryptedFile.query.filter_by(file_id='test-file-123').first()
            
            # Login as consultant
            client.post('/login', data={
                'username': 'consultant_user',
                'password': 'password123'
            })
            
            # Submit request
            client.post(f'/request-access/{file.id}', data={
                'submit': 'Submit Request'
            })
            
            # Verify status is pending
            request = AccessRequest.query.filter_by(
                consultant_id=consultant.id,
                file_id=file.id
            ).first()
            
            assert request.status == 'pending'
    
    def test_request_without_message(self, app_and_db, client, test_users, test_file):
        """Test request can be submitted without optional message"""
        app, db = app_and_db
        
        with app.app_context():
            consultant = User.query.filter_by(username='consultant_user').first()
            file = EncryptedFile.query.filter_by(file_id='test-file-123').first()
            
            # Login as consultant
            client.post('/login', data={
                'username': 'consultant_user',
                'password': 'password123'
            })
            
            # Submit request without message
            response = client.post(f'/request-access/{file.id}', data={
                'submit': 'Submit Request'
            }, follow_redirects=False)
            
            # Verify request was created
            assert response.status_code == 302
            
            request = AccessRequest.query.filter_by(
                consultant_id=consultant.id,
                file_id=file.id
            ).first()
            
            assert request is not None
    
    def test_request_for_nonexistent_file(self, app_and_db, client, test_users):
        """Test request for nonexistent file returns 404"""
        app, db = app_and_db
        
        with app.app_context():
            # Login as consultant
            client.post('/login', data={
                'username': 'consultant_user',
                'password': 'password123'
            })
            
            # Try to request access to nonexistent file
            response = client.post('/request-access/99999', data={
                'submit': 'Submit Request'
            })
            
            # Verify 404 response
            assert response.status_code == 404
    
    def test_unauthenticated_user_cannot_request_access(self, app_and_db, client, test_file):
        """Test unauthenticated user cannot request access"""
        app, db = app_and_db
        
        with app.app_context():
            file = EncryptedFile.query.filter_by(file_id='test-file-123').first()
            
            # Try to request access without logging in
            response = client.post(f'/request-access/{file.id}', data={
                'submit': 'Submit Request'
            }, follow_redirects=False)
            
            # Verify redirect to login
            assert response.status_code == 302
            assert '/login' in response.location
    
    def test_view_organizations_as_consultant(self, app_and_db, client, test_users, test_file):
        """Test consultant can view organizations and their files"""
        app, db = app_and_db
        
        with app.app_context():
            # Login as consultant
            client.post('/login', data={
                'username': 'consultant_user',
                'password': 'password123'
            })
            
            # View organizations
            response = client.get('/organizations')
            
            # Verify response
            assert response.status_code == 200
            assert b'org_user' in response.data
            assert b'test.txt' in response.data
    
    def test_view_organizations_as_organization_denied(self, app_and_db, client, test_users):
        """Test organization user cannot view organizations page"""
        app, db = app_and_db
        
        with app.app_context():
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Try to view organizations
            response = client.get('/organizations', follow_redirects=True)
            
            # Verify access denied
            assert b'Access denied' in response.data or b'Only' in response.data


def run_access_request_tests():
    """Run all access request tests"""
    print("Running Access Request Submission Tests...")
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
    success = run_access_request_tests()
    if success:
        print("\n✅ All access request tests passed!")
    else:
        print("\n❌ Some access request tests failed!")
    
    exit(0 if success else 1)



class TestOrganizationRequestFiltering:
    """Unit tests for organization request filtering
    
    Requirements: 3.1
    """
    
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
    
    @pytest.fixture
    def test_data(self, app_and_db):
        """Create test data with multiple organizations and consultants"""
        app, db = app_and_db
        
        with app.app_context():
            # Create two organization users
            org1 = User(
                username='org1',
                email='org1@example.com',
                role=UserRole.ORGANIZATION
            )
            org1.set_password('password123')
            
            org2 = User(
                username='org2',
                email='org2@example.com',
                role=UserRole.ORGANIZATION
            )
            org2.set_password('password123')
            
            # Create consultant user
            consultant = User(
                username='consultant',
                email='consultant@example.com',
                role=UserRole.CONSULTANT
            )
            consultant.set_password('password123')
            
            db.session.add_all([org1, org2, consultant])
            db.session.commit()
            
            # Create files for org1
            file1_org1 = EncryptedFile(
                file_id='file1-org1',
                filename='file1_encrypted',
                original_filename='file1.txt',
                file_type='text',
                file_size=1024,
                encrypted_path='/path/to/file1',
                algorithm='AES',
                wrapped_key=b'wrapped_key_1',
                iv=b'iv_1',
                user_id=org1.id
            )
            
            file2_org1 = EncryptedFile(
                file_id='file2-org1',
                filename='file2_encrypted',
                original_filename='file2.txt',
                file_type='text',
                file_size=2048,
                encrypted_path='/path/to/file2',
                algorithm='AES',
                wrapped_key=b'wrapped_key_2',
                iv=b'iv_2',
                user_id=org1.id
            )
            
            # Create files for org2
            file1_org2 = EncryptedFile(
                file_id='file1-org2',
                filename='file3_encrypted',
                original_filename='file3.txt',
                file_type='text',
                file_size=3072,
                encrypted_path='/path/to/file3',
                algorithm='AES',
                wrapped_key=b'wrapped_key_3',
                iv=b'iv_3',
                user_id=org2.id
            )
            
            db.session.add_all([file1_org1, file2_org1, file1_org2])
            db.session.commit()
            
            # Create access requests
            # Requests for org1's files
            request1 = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org1.id,
                file_id=file1_org1.id,
                status='pending'
            )
            
            request2 = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org1.id,
                file_id=file2_org1.id,
                status='pending'
            )
            
            # Request for org2's file
            request3 = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org2.id,
                file_id=file1_org2.id,
                status='pending'
            )
            
            db.session.add_all([request1, request2, request3])
            db.session.commit()
            
            return {
                'org1': org1,
                'org2': org2,
                'consultant': consultant,
                'org1_files': [file1_org1, file2_org1],
                'org2_files': [file1_org2],
                'org1_requests': [request1, request2],
                'org2_requests': [request3]
            }
    
    def test_organization_sees_only_their_file_requests(self, app_and_db, test_data):
        """Test organization sees only requests for their files
        
        Requirement 3.1: Organizations should only see requests for files they own
        """
        app, db = app_and_db
        
        with app.app_context():
            org1 = User.query.filter_by(username='org1').first()
            org2 = User.query.filter_by(username='org2').first()
            
            # Get org1's file IDs
            org1_file_ids = [f.id for f in EncryptedFile.query.filter_by(user_id=org1.id).all()]
            
            # Get requests for org1's files
            org1_requests = AccessRequest.query.filter(
                AccessRequest.file_id.in_(org1_file_ids)
            ).all()
            
            # Verify org1 sees exactly 2 requests
            assert len(org1_requests) == 2, \
                f"Organization 1 should see 2 requests, but sees {len(org1_requests)}"
            
            # Verify all requests are for org1's files
            for request in org1_requests:
                assert request.file_id in org1_file_ids, \
                    "All requests should be for organization 1's files"
                assert request.organization_id == org1.id, \
                    "All requests should be addressed to organization 1"
            
            # Get org2's file IDs
            org2_file_ids = [f.id for f in EncryptedFile.query.filter_by(user_id=org2.id).all()]
            
            # Get requests for org2's files
            org2_requests = AccessRequest.query.filter(
                AccessRequest.file_id.in_(org2_file_ids)
            ).all()
            
            # Verify org2 sees exactly 1 request
            assert len(org2_requests) == 1, \
                f"Organization 2 should see 1 request, but sees {len(org2_requests)}"
            
            # Verify the request is for org2's file
            assert org2_requests[0].file_id in org2_file_ids, \
                "Request should be for organization 2's file"
            assert org2_requests[0].organization_id == org2.id, \
                "Request should be addressed to organization 2"
    
    def test_organization_doesnt_see_other_organizations_requests(self, app_and_db, test_data):
        """Test organization doesn't see other organizations' requests
        
        Requirement 3.1: Request filtering should prevent cross-organization visibility
        """
        app, db = app_and_db
        
        with app.app_context():
            org1 = User.query.filter_by(username='org1').first()
            org2 = User.query.filter_by(username='org2').first()
            
            # Get org1's file IDs
            org1_file_ids = [f.id for f in EncryptedFile.query.filter_by(user_id=org1.id).all()]
            
            # Get requests for org1's files
            org1_requests = AccessRequest.query.filter(
                AccessRequest.file_id.in_(org1_file_ids)
            ).all()
            
            # Get org2's file IDs
            org2_file_ids = [f.id for f in EncryptedFile.query.filter_by(user_id=org2.id).all()]
            
            # Verify org1's requests don't include org2's files
            for request in org1_requests:
                assert request.file_id not in org2_file_ids, \
                    "Organization 1 should not see requests for organization 2's files"
            
            # Get requests for org2's files
            org2_requests = AccessRequest.query.filter(
                AccessRequest.file_id.in_(org2_file_ids)
            ).all()
            
            # Verify org2's requests don't include org1's files
            for request in org2_requests:
                assert request.file_id not in org1_file_ids, \
                    "Organization 2 should not see requests for organization 1's files"
    
    def test_filtering_by_status_works_correctly(self, app_and_db, test_data):
        """Test filtering by status works correctly
        
        Requirement 3.1: Organizations should be able to filter requests by status
        """
        app, db = app_and_db
        
        with app.app_context():
            org1 = User.query.filter_by(username='org1').first()
            consultant = User.query.filter_by(username='consultant').first()
            
            # Update one request to approved status
            org1_files = EncryptedFile.query.filter_by(user_id=org1.id).all()
            request_to_approve = AccessRequest.query.filter_by(
                file_id=org1_files[0].id,
                consultant_id=consultant.id
            ).first()
            request_to_approve.status = 'approved'
            db.session.commit()
            
            # Get org1's file IDs
            org1_file_ids = [f.id for f in org1_files]
            
            # Filter for pending requests
            pending_requests = AccessRequest.query.filter(
                AccessRequest.file_id.in_(org1_file_ids),
                AccessRequest.status == 'pending'
            ).all()
            
            # Verify only pending requests are returned
            assert len(pending_requests) == 1, \
                f"Should have 1 pending request, but found {len(pending_requests)}"
            
            for request in pending_requests:
                assert request.status == 'pending', \
                    "All filtered requests should have status 'pending'"
            
            # Filter for approved requests
            approved_requests = AccessRequest.query.filter(
                AccessRequest.file_id.in_(org1_file_ids),
                AccessRequest.status == 'approved'
            ).all()
            
            # Verify only approved requests are returned
            assert len(approved_requests) == 1, \
                f"Should have 1 approved request, but found {len(approved_requests)}"
            
            for request in approved_requests:
                assert request.status == 'approved', \
                    "All filtered requests should have status 'approved'"
            
            # Filter for denied requests (should be empty)
            denied_requests = AccessRequest.query.filter(
                AccessRequest.file_id.in_(org1_file_ids),
                AccessRequest.status == 'denied'
            ).all()
            
            assert len(denied_requests) == 0, \
                "Should have no denied requests"
    
    def test_organization_with_no_files_sees_no_requests(self, app_and_db):
        """Test organization with no files sees no requests"""
        app, db = app_and_db
        
        with app.app_context():
            # Create organization with no files
            org_no_files = User(
                username='org_no_files',
                email='org_no_files@example.com',
                role=UserRole.ORGANIZATION
            )
            org_no_files.set_password('password123')
            db.session.add(org_no_files)
            db.session.commit()
            
            # Get file IDs (should be empty)
            file_ids = [f.id for f in EncryptedFile.query.filter_by(user_id=org_no_files.id).all()]
            
            # Query requests
            requests = AccessRequest.query.filter(
                AccessRequest.file_id.in_(file_ids) if file_ids else False
            ).all()
            
            # Verify no requests
            assert len(requests) == 0, \
                "Organization with no files should see no requests"
    
    def test_multiple_consultants_requests_all_visible_to_organization(self, app_and_db):
        """Test organization sees requests from multiple consultants"""
        app, db = app_and_db
        
        with app.app_context():
            # Create organization
            org = User(
                username='org_multi',
                email='org_multi@example.com',
                role=UserRole.ORGANIZATION
            )
            org.set_password('password123')
            
            # Create multiple consultants
            consultant1 = User(
                username='consultant1',
                email='consultant1@example.com',
                role=UserRole.CONSULTANT
            )
            consultant1.set_password('password123')
            
            consultant2 = User(
                username='consultant2',
                email='consultant2@example.com',
                role=UserRole.CONSULTANT
            )
            consultant2.set_password('password123')
            
            db.session.add_all([org, consultant1, consultant2])
            db.session.commit()
            
            # Create file
            file = EncryptedFile(
                file_id='multi-consultant-file',
                filename='multi_encrypted',
                original_filename='multi.txt',
                file_type='text',
                file_size=1024,
                encrypted_path='/path/to/multi',
                algorithm='AES',
                wrapped_key=b'wrapped_key',
                iv=b'iv',
                user_id=org.id
            )
            db.session.add(file)
            db.session.commit()
            
            # Create requests from both consultants
            request1 = AccessRequest(
                consultant_id=consultant1.id,
                organization_id=org.id,
                file_id=file.id,
                status='pending'
            )
            
            request2 = AccessRequest(
                consultant_id=consultant2.id,
                organization_id=org.id,
                file_id=file.id,
                status='pending'
            )
            
            db.session.add_all([request1, request2])
            db.session.commit()
            
            # Get org's file IDs
            org_file_ids = [f.id for f in EncryptedFile.query.filter_by(user_id=org.id).all()]
            
            # Get all requests for org's files
            requests = AccessRequest.query.filter(
                AccessRequest.file_id.in_(org_file_ids)
            ).all()
            
            # Verify organization sees both requests
            assert len(requests) == 2, \
                f"Organization should see 2 requests from different consultants, but sees {len(requests)}"
            
            # Verify requests are from different consultants
            consultant_ids = {r.consultant_id for r in requests}
            assert len(consultant_ids) == 2, \
                "Requests should be from 2 different consultants"
            assert consultant1.id in consultant_ids
            assert consultant2.id in consultant_ids



class TestAccessRequestApproval:
    """
    Unit tests for access request approval workflow
    
    Requirements: 3.3, 3.5, 5.1, 5.2, 5.3, 5.4, 5.5
    """
    
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
    
    @pytest.fixture
    def test_data(self, app_and_db):
        """Create test data for approval tests"""
        app, db = app_and_db
        
        with app.app_context():
            from app.asymmetric_crypto import AsymmetricCrypto
            from app.crypto_utils import _wrap_key
            from Crypto.Random import get_random_bytes
            
            # Create organization user with keys
            org_user = User(
                username='org_user',
                email='org@example.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('password123')
            
            org_public_key, org_private_key = AsymmetricCrypto.generate_rsa_keypair()
            org_user.public_key = org_public_key
            org_user.public_key_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(org_public_key)
            
            db.session.add(org_user)
            db.session.flush()
            
            # Create consultant user with keys
            consultant_user = User(
                username='consultant_user',
                email='consultant@example.com',
                role=UserRole.CONSULTANT
            )
            consultant_user.set_password('password123')
            
            consultant_public_key, consultant_private_key = AsymmetricCrypto.generate_rsa_keypair()
            consultant_user.public_key = consultant_public_key
            consultant_user.public_key_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(consultant_public_key)
            
            db.session.add(consultant_user)
            db.session.flush()
            
            # Create a file with wrapped DEK
            symmetric_key = get_random_bytes(32)
            wrapped_dek = _wrap_key(symmetric_key)
            
            file = EncryptedFile(
                file_id='test-file-123',
                filename='test_encrypted',
                original_filename='test.txt',
                file_type='text',
                file_size=1024,
                encrypted_path='/path/to/encrypted',
                algorithm='AES',
                wrapped_key=wrapped_dek,
                iv=get_random_bytes(16),
                user_id=org_user.id
            )
            db.session.add(file)
            db.session.flush()
            
            # Create pending access request
            access_request = AccessRequest(
                consultant_id=consultant_user.id,
                organization_id=org_user.id,
                file_id=file.id,
                status='pending'
            )
            db.session.add(access_request)
            db.session.commit()
            
            return {
                'org_user': org_user,
                'consultant_user': consultant_user,
                'file': file,
                'access_request': access_request,
                'symmetric_key': symmetric_key
            }
    
    def test_successful_approval_wraps_key_correctly(self, app_and_db, client, test_data):
        """
        Test successful approval wraps key correctly
        
        Requirements: 3.3, 5.1, 5.2, 5.3, 5.4, 5.5
        """
        app, db = app_and_db
        
        with app.app_context():
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Get the request (query fresh from database)
            request = AccessRequest.query.filter_by(
                consultant_id=User.query.filter_by(username='consultant_user').first().id
            ).first()
            
            # Approve the request
            response = client.post(f'/approve-request/{request.id}')
            
            # Verify redirect
            assert response.status_code == 302
            
            # Verify request was approved
            approved_request = AccessRequest.query.filter_by(
                consultant_id=User.query.filter_by(username='consultant_user').first().id
            ).first()
            assert approved_request.status == 'approved'
            
            # Verify wrapped key was stored
            assert approved_request.wrapped_symmetric_key is not None
            assert len(approved_request.wrapped_symmetric_key) > 0
    
    def test_approval_updates_status_and_timestamp(self, app_and_db, client, test_data):
        """
        Test approval updates status and timestamp
        
        Requirements: 3.3, 3.5
        """
        app, db = app_and_db
        
        with app.app_context():
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Get the request
            request = AccessRequest.query.filter_by(status='pending').first()
            request_id = request.id
            
            # Verify initial state
            assert request.status == 'pending'
            assert request.processed_at is None
            
            # Record time before approval
            time_before = datetime.utcnow()
            
            # Approve the request
            response = client.post(f'/approve-request/{request_id}')
            
            # Record time after approval
            time_after = datetime.utcnow()
            
            # Verify status was updated
            approved_request = AccessRequest.query.get(request_id)
            assert approved_request.status == 'approved'
            
            # Verify timestamp was set
            assert approved_request.processed_at is not None
            assert time_before <= approved_request.processed_at <= time_after
    
    def test_approval_logs_operation(self, app_and_db, client, test_data):
        """
        Test approval logs operation
        
        Requirements: 11.2
        """
        app, db = app_and_db
        
        with app.app_context():
            from app.models import CryptoLog
            
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Get the request (query fresh)
            request = AccessRequest.query.filter_by(status='pending').first()
            request_id = request.id
            
            # Get org user ID
            org_user = User.query.filter_by(username='org_user').first()
            org_user_id = org_user.id
            
            # Count logs before approval
            logs_before = CryptoLog.query.count()
            
            # Approve the request
            response = client.post(f'/approve-request/{request_id}')
            
            # Verify log was created
            logs_after = CryptoLog.query.count()
            assert logs_after == logs_before + 1
            
            # Verify log details
            log = CryptoLog.query.order_by(CryptoLog.timestamp.desc()).first()
            assert log.operation == 'key_wrapped'
            assert log.success == True
            assert log.user_id == org_user_id
    
    def test_approval_with_invalid_public_key_fails(self, app_and_db, client, test_data):
        """
        Test approval with invalid public key fails gracefully
        
        Requirements: 5.3
        """
        app, db = app_and_db
        
        with app.app_context():
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Get the consultant and corrupt their public key
            consultant = User.query.filter_by(username='consultant_user').first()
            consultant.public_key = None
            db.session.commit()
            
            # Get the request
            request = AccessRequest.query.filter_by(status='pending').first()
            request_id = request.id
            
            # Try to approve the request
            response = client.post(f'/approve-request/{request_id}')
            
            # Verify redirect (error handling)
            assert response.status_code == 302
            
            # Verify request was NOT approved
            failed_request = AccessRequest.query.get(request_id)
            assert failed_request.status == 'pending'
            assert failed_request.wrapped_symmetric_key is None
    
    def test_approval_rollback_on_error(self, app_and_db, client, test_data):
        """
        Test approval rollback on error
        
        Requirements: 3.3, 5.4
        """
        app, db = app_and_db
        
        with app.app_context():
            from app.models import CryptoLog
            
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Get the request
            request = AccessRequest.query.filter_by(status='pending').first()
            request_id = request.id
            
            # Corrupt the file's wrapped key to cause an error
            file = EncryptedFile.query.filter_by(file_id='test-file-123').first()
            file.wrapped_key = None
            db.session.commit()
            
            # Try to approve the request
            response = client.post(f'/approve-request/{request_id}')
            
            # Verify redirect (error handling)
            assert response.status_code == 302
            
            # Verify request was NOT approved (rollback occurred)
            failed_request = AccessRequest.query.get(request_id)
            assert failed_request.status == 'pending'
            assert failed_request.wrapped_symmetric_key is None
            assert failed_request.processed_at is None
            
            # Verify error was logged
            error_log = CryptoLog.query.filter_by(
                operation='key_wrapped',
                success=False
            ).first()
            assert error_log is not None
            assert error_log.error_message is not None
    
    def test_non_organization_cannot_approve(self, app_and_db, client, test_data):
        """
        Test that non-organization users cannot approve requests
        
        Requirements: 1.3, 3.3
        """
        app, db = app_and_db
        
        with app.app_context():
            # Login as consultant (not organization)
            client.post('/login', data={
                'username': 'consultant_user',
                'password': 'password123'
            })
            
            # Get the request
            request = AccessRequest.query.filter_by(status='pending').first()
            request_id = request.id
            
            # Try to approve the request
            response = client.post(f'/approve-request/{request_id}')
            
            # Verify redirect (access denied)
            assert response.status_code == 302
            
            # Verify request was NOT approved
            unchanged_request = AccessRequest.query.get(request_id)
            assert unchanged_request.status == 'pending'
    
    def test_organization_cannot_approve_other_org_requests(self, app_and_db, client, test_data):
        """
        Test that organizations can only approve requests for their own files
        
        Requirements: 3.3
        """
        app, db = app_and_db
        
        with app.app_context():
            # Create another organization
            other_org = User(
                username='other_org',
                email='other@example.com',
                role=UserRole.ORGANIZATION
            )
            other_org.set_password('password123')
            db.session.add(other_org)
            db.session.commit()
            
            # Login as the other organization
            client.post('/login', data={
                'username': 'other_org',
                'password': 'password123'
            })
            
            # Get the request (which belongs to org_user, not other_org)
            request = AccessRequest.query.filter_by(status='pending').first()
            request_id = request.id
            
            # Try to approve the request
            response = client.post(f'/approve-request/{request_id}')
            
            # Verify redirect (access denied)
            assert response.status_code == 302
            
            # Verify request was NOT approved
            unchanged_request = AccessRequest.query.get(request_id)
            assert unchanged_request.status == 'pending'
    
    def test_cannot_approve_non_pending_request(self, app_and_db, client, test_data):
        """
        Test that only pending requests can be approved
        
        Requirements: 3.3
        """
        app, db = app_and_db
        
        with app.app_context():
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Get the request and change its status to denied
            request = AccessRequest.query.filter_by(status='pending').first()
            request_id = request.id
            request.status = 'denied'
            db.session.commit()
            
            # Try to approve the denied request
            response = client.post(f'/approve-request/{request_id}')
            
            # Verify redirect
            assert response.status_code == 302
            
            # Verify request status unchanged
            unchanged_request = AccessRequest.query.get(request_id)
            assert unchanged_request.status == 'denied'
            assert unchanged_request.wrapped_symmetric_key is None



class TestAccessRequestDenial:
    """Unit tests for access request denial workflow
    
    Requirements: 3.4, 3.5
    """
    
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
    
    @pytest.fixture
    def test_data(self, app_and_db):
        """Create test data with organization, consultant, file, and pending request"""
        app, db = app_and_db
        
        with app.app_context():
            # Create organization user
            org_user = User(
                username='org_user',
                email='org@example.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('password123')
            
            # Create consultant user
            consultant_user = User(
                username='consultant_user',
                email='consultant@example.com',
                role=UserRole.CONSULTANT
            )
            consultant_user.set_password('password123')
            
            db.session.add_all([org_user, consultant_user])
            db.session.commit()
            
            # Create file
            file = EncryptedFile(
                file_id='test-file-123',
                filename='test_encrypted',
                original_filename='test.txt',
                file_type='text',
                file_size=1024,
                encrypted_path='/path/to/encrypted',
                algorithm='AES',
                wrapped_key=b'wrapped_key_data',
                iv=b'initialization_vector',
                user_id=org_user.id
            )
            
            db.session.add(file)
            db.session.commit()
            
            # Create pending access request
            access_request = AccessRequest(
                consultant_id=consultant_user.id,
                organization_id=org_user.id,
                file_id=file.id,
                status='pending'
            )
            
            db.session.add(access_request)
            db.session.commit()
            
            return {
                'organization': org_user,
                'consultant': consultant_user,
                'file': file,
                'request': access_request
            }
    
    def test_denial_updates_status_correctly(self, app_and_db, client, test_data):
        """Test denial updates status to denied
        
        Requirement 3.4: WHEN an organization denies a request THEN the System SHALL update the request status to denied
        """
        app, db = app_and_db
        
        with app.app_context():
            # Query fresh objects within this context
            org_user = User.query.filter_by(username='org_user').first()
            consultant = User.query.filter_by(username='consultant_user').first()
            file = EncryptedFile.query.filter_by(file_id='test-file-123').first()
            request = AccessRequest.query.filter_by(
                consultant_id=consultant.id,
                file_id=file.id
            ).first()
            
            # Verify initial status is pending
            assert request.status == 'pending'
            request_id = request.id
            
        # Login as organization (outside app context)
        client.post('/login', data={
            'username': 'org_user',
            'password': 'password123'
        })
        
        # Deny the request
        response = client.post(f'/deny-request/{request_id}', follow_redirects=False)
        
        # Verify redirect
        assert response.status_code == 302
        
        with app.app_context():
            # Query request again in new context
            request = AccessRequest.query.get(request_id)
            
            # Verify status is now denied
            assert request.status == 'denied', \
                f"Request status should be 'denied', but is '{request.status}'"
    
    def test_denial_records_timestamp(self, app_and_db, client, test_data):
        """Test denial records processed_at timestamp
        
        Requirement 3.5: WHEN a request status changes THEN the System SHALL record the timestamp of the status change
        """
        app, db = app_and_db
        
        with app.app_context():
            consultant = User.query.filter_by(username='consultant_user').first()
            file = EncryptedFile.query.filter_by(file_id='test-file-123').first()
            request = AccessRequest.query.filter_by(
                consultant_id=consultant.id,
                file_id=file.id
            ).first()
            
            # Verify processed_at is initially None
            assert request.processed_at is None
            request_id = request.id
            
        # Login as organization
        client.post('/login', data={
            'username': 'org_user',
            'password': 'password123'
        })
        
        # Record time before denial
        before_denial = datetime.utcnow()
        
        # Deny the request
        client.post(f'/deny-request/{request_id}')
        
        # Record time after denial
        after_denial = datetime.utcnow()
        
        with app.app_context():
            # Query request again
            request = AccessRequest.query.get(request_id)
            
            # Verify processed_at is now set
            assert request.processed_at is not None, \
                "processed_at timestamp should be set after denial"
            
            # Verify timestamp is within reasonable range
            assert before_denial <= request.processed_at <= after_denial, \
                "processed_at timestamp should be between before and after denial times"
    
    def test_denial_logs_operation(self, app_and_db, client, test_data):
        """Test denial logs the operation
        
        Requirement 3.4, 3.5: Denial operations should be logged for audit purposes
        """
        app, db = app_and_db
        
        with app.app_context():
            org_user = User.query.filter_by(username='org_user').first()
            consultant = User.query.filter_by(username='consultant_user').first()
            file = EncryptedFile.query.filter_by(file_id='test-file-123').first()
            request = AccessRequest.query.filter_by(
                consultant_id=consultant.id,
                file_id=file.id
            ).first()
            
            # Get initial log count
            initial_log_count = CryptoLog.query.filter_by(
                user_id=org_user.id,
                operation='access_denied'
            ).count()
            request_id = request.id
            org_user_id = org_user.id
            
        # Login as organization
        client.post('/login', data={
            'username': 'org_user',
            'password': 'password123'
        })
        
        # Deny the request
        client.post(f'/deny-request/{request_id}')
        
        with app.app_context():
            # Verify log entry was created
            log_entries = CryptoLog.query.filter_by(
                user_id=org_user_id,
                operation='access_denied'
            ).all()
            
            assert len(log_entries) == initial_log_count + 1, \
                "A log entry should be created for the denial operation"
            
            # Verify log entry details
            log_entry = log_entries[-1]  # Get the most recent entry
            assert log_entry.success is True, \
                "Log entry should indicate successful denial"
            assert log_entry.details is not None, \
                "Log entry should contain details about the denial"
    
    def test_consultant_cannot_deny_request(self, app_and_db, client, test_data):
        """Test consultant users cannot deny requests"""
        app, db = app_and_db
        
        with app.app_context():
            consultant = User.query.filter_by(username='consultant_user').first()
            file = EncryptedFile.query.filter_by(file_id='test-file-123').first()
            request = AccessRequest.query.filter_by(
                consultant_id=consultant.id,
                file_id=file.id
            ).first()
            request_id = request.id
            
        # Login as consultant
        client.post('/login', data={
            'username': 'consultant_user',
            'password': 'password123'
        })
        
        # Try to deny the request
        response = client.post(f'/deny-request/{request_id}', follow_redirects=True)
        
        # Verify access denied
        assert b'Access denied' in response.data or b'Only organizations' in response.data
        
        with app.app_context():
            # Query request again
            request = AccessRequest.query.get(request_id)
            
            # Verify status is still pending
            assert request.status == 'pending', \
                "Request status should remain 'pending' when consultant tries to deny"
    
    def test_organization_cannot_deny_other_organizations_request(self, app_and_db, client, test_data):
        """Test organization cannot deny requests for other organizations' files"""
        app, db = app_and_db
        
        with app.app_context():
            # Create another organization
            org2 = User(
                username='org2',
                email='org2@example.com',
                role=UserRole.ORGANIZATION
            )
            org2.set_password('password123')
            db.session.add(org2)
            db.session.commit()
            
            consultant = User.query.filter_by(username='consultant_user').first()
            file = EncryptedFile.query.filter_by(file_id='test-file-123').first()
            request = AccessRequest.query.filter_by(
                consultant_id=consultant.id,
                file_id=file.id
            ).first()
            request_id = request.id
            
        # Login as org2
        client.post('/login', data={
            'username': 'org2',
            'password': 'password123'
        })
        
        # Try to deny the request
        response = client.post(f'/deny-request/{request_id}', follow_redirects=True)
        
        # Verify access denied
        assert b'Access denied' in response.data or b'only deny requests for your own files' in response.data
        
        with app.app_context():
            # Query request again
            request = AccessRequest.query.get(request_id)
            
            # Verify status is still pending
            assert request.status == 'pending', \
                "Request status should remain 'pending' when wrong organization tries to deny"
    
    def test_cannot_deny_already_approved_request(self, app_and_db, client, test_data):
        """Test cannot deny a request that is already approved"""
        app, db = app_and_db
        
        with app.app_context():
            consultant = User.query.filter_by(username='consultant_user').first()
            file = EncryptedFile.query.filter_by(file_id='test-file-123').first()
            request = AccessRequest.query.filter_by(
                consultant_id=consultant.id,
                file_id=file.id
            ).first()
            
            # Update request to approved status
            request.status = 'approved'
            request.processed_at = datetime.utcnow()
            db.session.commit()
            request_id = request.id
            
        # Login as organization
        client.post('/login', data={
            'username': 'org_user',
            'password': 'password123'
        })
        
        # Try to deny the approved request
        response = client.post(f'/deny-request/{request_id}', follow_redirects=True)
        
        # Verify warning message
        assert b'Cannot deny' in response.data or b'approved' in response.data
        
        with app.app_context():
            # Query request again
            request = AccessRequest.query.get(request_id)
            
            # Verify status is still approved
            assert request.status == 'approved', \
                "Request status should remain 'approved' when trying to deny an approved request"
    
    def test_cannot_deny_already_denied_request(self, app_and_db, client, test_data):
        """Test cannot deny a request that is already denied"""
        app, db = app_and_db
        
        with app.app_context():
            consultant = User.query.filter_by(username='consultant_user').first()
            file = EncryptedFile.query.filter_by(file_id='test-file-123').first()
            request = AccessRequest.query.filter_by(
                consultant_id=consultant.id,
                file_id=file.id
            ).first()
            
            # Update request to denied status
            request.status = 'denied'
            request.processed_at = datetime.utcnow()
            db.session.commit()
            request_id = request.id
            
        # Login as organization
        client.post('/login', data={
            'username': 'org_user',
            'password': 'password123'
        })
        
        # Try to deny the already denied request
        response = client.post(f'/deny-request/{request_id}', follow_redirects=True)
        
        # Verify warning message
        assert b'Cannot deny' in response.data or b'denied' in response.data
        
        with app.app_context():
            # Query request again
            request = AccessRequest.query.get(request_id)
            
            # Verify status is still denied
            assert request.status == 'denied', \
                "Request status should remain 'denied' when trying to deny an already denied request"
    
    def test_unauthenticated_user_cannot_deny_request(self, app_and_db, client, test_data):
        """Test unauthenticated user cannot deny requests"""
        app, db = app_and_db
        
        with app.app_context():
            consultant = User.query.filter_by(username='consultant_user').first()
            file = EncryptedFile.query.filter_by(file_id='test-file-123').first()
            request = AccessRequest.query.filter_by(
                consultant_id=consultant.id,
                file_id=file.id
            ).first()
            request_id = request.id
            
        # Try to deny without logging in
        response = client.post(f'/deny-request/{request_id}', follow_redirects=False)
        
        # Verify redirect to login
        assert response.status_code == 302
        assert '/login' in response.location
        
        with app.app_context():
            # Query request again
            request = AccessRequest.query.get(request_id)
            
            # Verify status is still pending
            assert request.status == 'pending', \
                "Request status should remain 'pending' when unauthenticated user tries to deny"
    
    def test_deny_nonexistent_request(self, app_and_db, client, test_data):
        """Test denying a nonexistent request returns 404"""
        app, db = app_and_db
        
        with app.app_context():
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Try to deny nonexistent request
            response = client.post('/deny-request/99999')
            
            # Verify 404 response
            assert response.status_code == 404


def run_denial_tests():
    """Run all denial workflow tests"""
    print("Running Access Request Denial Tests...")
    print("=" * 50)
    
    # Run tests with pytest
    exit_code = pytest.main([
        __file__,
        '-v',
        '--tb=short',
        '--no-header',
        '-k', 'TestAccessRequestDenial'
    ])
    
    return exit_code == 0


if __name__ == '__main__':
    # Run all tests including denial tests
    success = run_access_request_tests()
    denial_success = run_denial_tests()
    
    if success and denial_success:
        print("\n✅ All access request tests passed!")
    else:
        print("\n❌ Some access request tests failed!")
    
    exit(0 if (success and denial_success) else 1)


class TestAccessRevocationWorkflow:
    """Unit tests for access revocation workflow
    
    Requirements: 10.1, 10.2, 10.3, 10.4, 10.5
    """
    
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
    
    @pytest.fixture
    def test_data_with_approved_request(self, app_and_db):
        """Create test data with an approved access request"""
        app, db = app_and_db
        
        with app.app_context():
            from app.asymmetric_crypto import AsymmetricCrypto
            from datetime import datetime
            
            # Create organization user with keys
            org_user = User(
                username='org_user',
                email='org@example.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('password123')
            
            # Generate keys for organization
            public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
            org_user.public_key = public_key
            org_user.public_key_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(public_key)
            org_user.key_generated_at = datetime.utcnow()
            
            # Create consultant user with keys
            consultant_user = User(
                username='consultant_user',
                email='consultant@example.com',
                role=UserRole.CONSULTANT
            )
            consultant_user.set_password('password123')
            
            # Generate keys for consultant
            consultant_public_key, consultant_private_key = AsymmetricCrypto.generate_rsa_keypair()
            consultant_user.public_key = consultant_public_key
            consultant_user.public_key_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(consultant_public_key)
            consultant_user.key_generated_at = datetime.utcnow()
            
            db.session.add_all([org_user, consultant_user])
            db.session.commit()
            
            # Create encrypted file
            file = EncryptedFile(
                file_id='test-file-123',
                filename='test_encrypted',
                original_filename='test.txt',
                file_type='text',
                file_size=1024,
                encrypted_path='/path/to/encrypted',
                algorithm='AES',
                wrapped_key=b'kek_wrapped_symmetric_key_data',
                iv=b'initialization_vector',
                user_id=org_user.id
            )
            db.session.add(file)
            db.session.commit()
            
            # Create approved access request with wrapped key
            test_symmetric_key = b'test_symmetric_key_32_bytes_12'
            wrapped_key = AsymmetricCrypto.wrap_symmetric_key(
                test_symmetric_key,
                consultant_public_key
            )
            
            access_request = AccessRequest(
                consultant_id=consultant_user.id,
                organization_id=org_user.id,
                file_id=file.id,
                status='approved',
                wrapped_symmetric_key=wrapped_key,
                processed_at=datetime.utcnow()
            )
            db.session.add(access_request)
            db.session.commit()
            
            return {
                'organization': org_user,
                'consultant': consultant_user,
                'file': file,
                'request': access_request
            }
    
    def test_revocation_updates_status(self, app_and_db, client, test_data_with_approved_request):
        """Test revocation updates status to 'revoked'
        
        Requirement 10.2: Status should be updated to 'revoked'
        """
        app, db = app_and_db
        
        with app.app_context():
            org_user = User.query.filter_by(username='org_user').first()
            request = AccessRequest.query.filter_by(
                organization_id=org_user.id
            ).first()
            
            # Verify initial status
            assert request.status == 'approved'
            
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Revoke access
            response = client.post(f'/revoke-access/{request.id}', follow_redirects=False)
            
            # Verify redirect
            assert response.status_code == 302
            
            # Verify status updated
            db.session.refresh(request)
            assert request.status == 'revoked', \
                "Request status should be updated to 'revoked'"
    
    def test_revocation_deletes_wrapped_key(self, app_and_db, client, test_data_with_approved_request):
        """Test revocation deletes wrapped symmetric key
        
        Requirement 10.3: Wrapped key should be deleted
        """
        app, db = app_and_db
        
        with app.app_context():
            org_user = User.query.filter_by(username='org_user').first()
            request = AccessRequest.query.filter_by(
                organization_id=org_user.id
            ).first()
            
            # Verify wrapped key exists before revocation
            assert request.wrapped_symmetric_key is not None
            assert len(request.wrapped_symmetric_key) > 0
            
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Revoke access
            client.post(f'/revoke-access/{request.id}')
            
            # Verify wrapped key deleted
            db.session.refresh(request)
            assert request.wrapped_symmetric_key is None, \
                "Wrapped symmetric key should be deleted after revocation"
    
    def test_revocation_records_timestamp(self, app_and_db, client, test_data_with_approved_request):
        """Test revocation records processed_at timestamp
        
        Requirement 10.5: Timestamp should be recorded
        """
        app, db = app_and_db
        
        with app.app_context():
            from datetime import datetime
            
            org_user = User.query.filter_by(username='org_user').first()
            request = AccessRequest.query.filter_by(
                organization_id=org_user.id
            ).first()
            
            # Record original timestamp
            original_timestamp = request.processed_at
            
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Wait a moment to ensure timestamp difference
            import time
            time.sleep(0.1)
            
            # Revoke access
            client.post(f'/revoke-access/{request.id}')
            
            # Verify timestamp updated
            db.session.refresh(request)
            assert request.processed_at is not None, \
                "Processed timestamp should be set"
            assert request.processed_at >= original_timestamp, \
                "Processed timestamp should be updated to revocation time"
    
    def test_revocation_logs_operation(self, app_and_db, client, test_data_with_approved_request):
        """Test revocation logs the operation
        
        Requirement 10.5: Operation should be logged
        """
        app, db = app_and_db
        
        with app.app_context():
            org_user = User.query.filter_by(username='org_user').first()
            consultant = User.query.filter_by(username='consultant_user').first()
            request = AccessRequest.query.filter_by(
                organization_id=org_user.id
            ).first()
            
            # Count existing logs
            initial_log_count = CryptoLog.query.count()
            
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Revoke access
            client.post(f'/revoke-access/{request.id}')
            
            # Verify log created
            final_log_count = CryptoLog.query.count()
            assert final_log_count > initial_log_count, \
                "A log entry should be created for revocation"
            
            # Verify log details
            revocation_log = CryptoLog.query.filter_by(
                operation='access_revoked'
            ).order_by(CryptoLog.timestamp.desc()).first()
            
            assert revocation_log is not None, \
                "Revocation log should exist"
            assert revocation_log.user_id == org_user.id, \
                "Log should be associated with organization user"
            assert revocation_log.success is True, \
                "Log should indicate successful operation"
            assert str(consultant.id) in revocation_log.details or consultant.username in revocation_log.details, \
                "Log should contain consultant information"
    
    def test_revoked_access_prevents_download(self, app_and_db, client, test_data_with_approved_request):
        """Test revoked access prevents file download
        
        Requirement 10.4: Consultant should be denied access after revocation
        """
        app, db = app_and_db
        
        with app.app_context():
            org_user = User.query.filter_by(username='org_user').first()
            consultant = User.query.filter_by(username='consultant_user').first()
            file = EncryptedFile.query.filter_by(user_id=org_user.id).first()
            request = AccessRequest.query.filter_by(
                organization_id=org_user.id
            ).first()
            
            # Login as organization and revoke access
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            client.post(f'/revoke-access/{request.id}')
            client.get('/logout')
            
            # Login as consultant
            client.post('/login', data={
                'username': 'consultant_user',
                'password': 'password123'
            })
            
            # Try to download file
            response = client.get(f'/file/{file.file_id}/download', follow_redirects=True)
            
            # Verify access denied
            assert b'revoked' in response.data or b'denied' in response.data or b'permission' in response.data, \
                "Download should be denied for revoked access"
    
    def test_only_organization_can_revoke(self, app_and_db, client, test_data_with_approved_request):
        """Test only organization can revoke access"""
        app, db = app_and_db
        
        with app.app_context():
            request = AccessRequest.query.first()
            
            # Login as consultant
            client.post('/login', data={
                'username': 'consultant_user',
                'password': 'password123'
            })
            
            # Try to revoke access
            response = client.post(f'/revoke-access/{request.id}', follow_redirects=True)
            
            # Verify access denied
            assert b'Access denied' in response.data or b'Only' in response.data or response.status_code == 403
            
            # Verify request not revoked
            db.session.refresh(request)
            assert request.status == 'approved', \
                "Request should not be revoked by consultant"
    
    def test_revoke_nonexistent_request(self, app_and_db, client, test_data_with_approved_request):
        """Test revoking nonexistent request returns 404"""
        app, db = app_and_db
        
        with app.app_context():
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Try to revoke nonexistent request
            response = client.post('/revoke-access/99999')
            
            # Verify 404 response
            assert response.status_code == 404
    
    def test_revoke_other_organizations_request(self, app_and_db, client):
        """Test organization cannot revoke another organization's request"""
        app, db = app_and_db
        
        with app.app_context():
            from app.asymmetric_crypto import AsymmetricCrypto
            from datetime import datetime
            
            # Create two organizations
            org1 = User(
                username='org1',
                email='org1@example.com',
                role=UserRole.ORGANIZATION
            )
            org1.set_password('password123')
            
            org2 = User(
                username='org2',
                email='org2@example.com',
                role=UserRole.ORGANIZATION
            )
            org2.set_password('password123')
            
            # Create consultant
            consultant = User(
                username='consultant',
                email='consultant@example.com',
                role=UserRole.CONSULTANT
            )
            consultant.set_password('password123')
            
            # Generate keys for consultant
            consultant_public_key, _ = AsymmetricCrypto.generate_rsa_keypair()
            consultant.public_key = consultant_public_key
            consultant.public_key_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(consultant_public_key)
            consultant.key_generated_at = datetime.utcnow()
            
            db.session.add_all([org1, org2, consultant])
            db.session.commit()
            
            # Create file for org2
            file = EncryptedFile(
                file_id='org2-file',
                filename='org2_encrypted',
                original_filename='org2.txt',
                file_type='text',
                file_size=1024,
                encrypted_path='/path/to/org2',
                algorithm='AES',
                wrapped_key=b'wrapped_key',
                iv=b'iv',
                user_id=org2.id
            )
            db.session.add(file)
            db.session.commit()
            
            # Create approved request for org2's file
            test_symmetric_key = b'test_symmetric_key_32_bytes_12'
            wrapped_key = AsymmetricCrypto.wrap_symmetric_key(
                test_symmetric_key,
                consultant_public_key
            )
            
            request = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org2.id,
                file_id=file.id,
                status='approved',
                wrapped_symmetric_key=wrapped_key,
                processed_at=datetime.utcnow()
            )
            db.session.add(request)
            db.session.commit()
            
            # Login as org1
            client.post('/login', data={
                'username': 'org1',
                'password': 'password123'
            })
            
            # Try to revoke org2's request
            response = client.post(f'/revoke-access/{request.id}', follow_redirects=True)
            
            # Verify access denied or not found
            assert response.status_code in [403, 404] or b'permission' in response.data or b'denied' in response.data
            
            # Verify request not revoked
            db.session.refresh(request)
            assert request.status == 'approved', \
                "Request should not be revoked by different organization"
    
    def test_revoke_pending_request(self, app_and_db, client):
        """Test revoking a pending request (edge case)"""
        app, db = app_and_db
        
        with app.app_context():
            # Create organization
            org = User(
                username='org',
                email='org@example.com',
                role=UserRole.ORGANIZATION
            )
            org.set_password('password123')
            
            # Create consultant
            consultant = User(
                username='consultant',
                email='consultant@example.com',
                role=UserRole.CONSULTANT
            )
            consultant.set_password('password123')
            
            db.session.add_all([org, consultant])
            db.session.commit()
            
            # Create file
            file = EncryptedFile(
                file_id='test-file',
                filename='test_encrypted',
                original_filename='test.txt',
                file_type='text',
                file_size=1024,
                encrypted_path='/path/to/test',
                algorithm='AES',
                wrapped_key=b'wrapped_key',
                iv=b'iv',
                user_id=org.id
            )
            db.session.add(file)
            db.session.commit()
            
            # Create pending request (no wrapped key)
            request = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org.id,
                file_id=file.id,
                status='pending'
            )
            db.session.add(request)
            db.session.commit()
            
            # Login as organization
            client.post('/login', data={
                'username': 'org',
                'password': 'password123'
            })
            
            # Revoke pending request
            response = client.post(f'/revoke-access/{request.id}', follow_redirects=False)
            
            # Verify operation succeeds (or is handled gracefully)
            assert response.status_code in [200, 302]
            
            # Verify status updated
            db.session.refresh(request)
            assert request.status == 'revoked'
            assert request.wrapped_symmetric_key is None
    
    def test_unauthenticated_user_cannot_revoke(self, app_and_db, client, test_data_with_approved_request):
        """Test unauthenticated user cannot revoke access"""
        app, db = app_and_db
        
        with app.app_context():
            request = AccessRequest.query.first()
            
            # Try to revoke without logging in
            response = client.post(f'/revoke-access/{request.id}', follow_redirects=False)
            
            # Verify redirect to login
            assert response.status_code == 302
            assert '/login' in response.location
            
            # Verify request not revoked
            db.session.refresh(request)
            assert request.status == 'approved'


def run_revocation_tests():
    """Run all revocation tests"""
    print("Running Access Revocation Tests...")
    print("=" * 50)
    
    # Run tests with pytest
    exit_code = pytest.main([
        __file__,
        'TestAccessRevocationWorkflow',
        '-v',
        '--tb=short',
        '--no-header'
    ])
    
    return exit_code == 0


if __name__ == '__main__':
    # Run all tests including revocation
    success = pytest.main([__file__, '-v'])
    exit(0 if success == 0 else 1)
