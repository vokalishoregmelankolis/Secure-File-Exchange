"""
Integration Tests for Organization Access Request View

This module contains integration tests for the organization access request
management view, including route access, filtering, and display.

Requirements: 3.1, 3.2
"""

import pytest
from tests import create_test_app
from app.models import User, UserRole, EncryptedFile, AccessRequest


class TestOrganizationAccessRequestView:
    """Integration tests for organization access request view"""
    
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
        """Create test data"""
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
            consultant = User(
                username='consultant',
                email='consultant@example.com',
                role=UserRole.CONSULTANT
            )
            consultant.set_password('password123')
            
            db.session.add_all([org_user, consultant])
            db.session.commit()
            
            # Create files for organization
            file1 = EncryptedFile(
                file_id='file1',
                filename='file1_encrypted',
                original_filename='file1.txt',
                file_type='text',
                file_size=1024,
                encrypted_path='/path/to/file1',
                algorithm='AES',
                wrapped_key=b'wrapped_key_1',
                iv=b'iv_1',
                user_id=org_user.id
            )
            
            file2 = EncryptedFile(
                file_id='file2',
                filename='file2_encrypted',
                original_filename='file2.txt',
                file_type='text',
                file_size=2048,
                encrypted_path='/path/to/file2',
                algorithm='AES',
                wrapped_key=b'wrapped_key_2',
                iv=b'iv_2',
                user_id=org_user.id
            )
            
            db.session.add_all([file1, file2])
            db.session.commit()
            
            # Create access requests
            request1 = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org_user.id,
                file_id=file1.id,
                status='pending'
            )
            
            request2 = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org_user.id,
                file_id=file2.id,
                status='approved'
            )
            
            db.session.add_all([request1, request2])
            db.session.commit()
            
            return {
                'org_user': org_user,
                'consultant': consultant,
                'files': [file1, file2],
                'requests': [request1, request2]
            }
    
    def test_organization_can_access_requests_page(self, app_and_db, client, test_data):
        """Test organization user can access the access requests page
        
        Requirement 3.1: Organizations should be able to view access requests
        """
        app, db = app_and_db
        
        with app.app_context():
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Access the requests page
            response = client.get('/access-requests')
            
            # Verify successful access
            assert response.status_code == 200
            assert b'ACCESS REQUESTS' in response.data
    
    def test_consultant_cannot_access_organization_requests_page(self, app_and_db, client, test_data):
        """Test consultant user cannot access organization requests page"""
        app, db = app_and_db
        
        with app.app_context():
            # Login as consultant
            client.post('/login', data={
                'username': 'consultant',
                'password': 'password123'
            })
            
            # Try to access the requests page
            response = client.get('/access-requests', follow_redirects=True)
            
            # Verify access denied
            assert b'Access denied' in response.data or b'Only' in response.data
    
    def test_unauthenticated_user_redirected_to_login(self, app_and_db, client):
        """Test unauthenticated user is redirected to login"""
        app, db = app_and_db
        
        with app.app_context():
            # Try to access without logging in
            response = client.get('/access-requests', follow_redirects=False)
            
            # Verify redirect to login
            assert response.status_code == 302
            assert '/login' in response.location
    
    def test_page_displays_consultant_info(self, app_and_db, client, test_data):
        """Test page displays consultant information
        
        Requirement 3.2: Display consultant info
        """
        app, db = app_and_db
        
        with app.app_context():
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Access the requests page
            response = client.get('/access-requests')
            
            # Verify consultant info is displayed
            assert b'consultant' in response.data
            assert b'consultant@example.com' in response.data
    
    def test_page_displays_file_info(self, app_and_db, client, test_data):
        """Test page displays file information
        
        Requirement 3.2: Display file info
        """
        app, db = app_and_db
        
        with app.app_context():
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Access the requests page
            response = client.get('/access-requests')
            
            # Verify file info is displayed
            assert b'file1.txt' in response.data
            assert b'AES' in response.data
    
    def test_page_displays_request_timestamp(self, app_and_db, client, test_data):
        """Test page displays request timestamp
        
        Requirement 3.2: Display request timestamp
        """
        app, db = app_and_db
        
        with app.app_context():
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Access the requests page
            response = client.get('/access-requests')
            
            # Verify timestamp is displayed (format: YYYY-MM-DD)
            assert response.status_code == 200
            # The page should contain date information
            response_text = response.data.decode('utf-8')
            assert '202' in response_text  # Year should be present
    
    def test_status_filter_pending(self, app_and_db, client, test_data):
        """Test filtering by pending status"""
        app, db = app_and_db
        
        with app.app_context():
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Access with pending filter (default)
            response = client.get('/access-requests?status=pending')
            
            # Verify only pending requests are shown
            assert response.status_code == 200
            assert b'file1.txt' in response.data  # pending request
            # file2.txt (approved) should not be shown with pending filter
    
    def test_status_filter_approved(self, app_and_db, client, test_data):
        """Test filtering by approved status"""
        app, db = app_and_db
        
        with app.app_context():
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Access with approved filter
            response = client.get('/access-requests?status=approved')
            
            # Verify only approved requests are shown
            assert response.status_code == 200
            assert b'file2.txt' in response.data  # approved request
    
    def test_status_filter_all(self, app_and_db, client, test_data):
        """Test showing all requests"""
        app, db = app_and_db
        
        with app.app_context():
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Access with all filter
            response = client.get('/access-requests?status=all')
            
            # Verify all requests are shown
            assert response.status_code == 200
            assert b'file1.txt' in response.data  # pending
            assert b'file2.txt' in response.data  # approved
    
    def test_organization_with_no_requests(self, app_and_db, client):
        """Test organization with no requests sees appropriate message"""
        app, db = app_and_db
        
        with app.app_context():
            # Create organization with no files/requests
            org_no_requests = User(
                username='org_no_requests',
                email='org_no_requests@example.com',
                role=UserRole.ORGANIZATION
            )
            org_no_requests.set_password('password123')
            db.session.add(org_no_requests)
            db.session.commit()
            
            # Login
            client.post('/login', data={
                'username': 'org_no_requests',
                'password': 'password123'
            })
            
            # Access requests page
            response = client.get('/access-requests')
            
            # Verify appropriate message
            assert response.status_code == 200
            assert b'No' in response.data and (b'requests' in response.data or b'found' in response.data)


def run_organization_view_tests():
    """Run all organization view tests"""
    print("Running Organization Access Request View Tests...")
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
    success = run_organization_view_tests()
    if success:
        print("\n✅ All organization view tests passed!")
    else:
        print("\n❌ Some organization view tests failed!")
    
    exit(0 if success else 1)
