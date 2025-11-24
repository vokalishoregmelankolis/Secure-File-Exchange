"""
Unit Tests for User Profile Page

This module contains unit tests for the profile page,
including display of role, fingerprint, and key generation date.
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
from tests import create_test_app
from app.models import User, UserRole


class TestProfilePage:
    """Unit tests for profile page"""
    
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
    def test_user_with_keys(self, app_and_db):
        """Create a test user with encryption keys"""
        app, db = app_and_db
        
        with app.app_context():
            from app.asymmetric_crypto import AsymmetricCrypto
            
            # Generate keys
            public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
            fingerprint = AsymmetricCrypto.get_public_key_fingerprint(public_key)
            
            # Create user
            user = User(
                username='testuser',
                email='test@example.com',
                role=UserRole.ORGANIZATION,
                public_key=public_key,
                public_key_fingerprint=fingerprint,
                key_generated_at=datetime.utcnow()
            )
            user.set_password('password123')
            
            db.session.add(user)
            db.session.commit()
            
            return user
    
    @pytest.fixture
    def test_consultant_with_keys(self, app_and_db):
        """Create a test consultant user with encryption keys"""
        app, db = app_and_db
        
        with app.app_context():
            from app.asymmetric_crypto import AsymmetricCrypto
            
            # Generate keys
            public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
            fingerprint = AsymmetricCrypto.get_public_key_fingerprint(public_key)
            
            # Create user
            user = User(
                username='consultant',
                email='consultant@example.com',
                role=UserRole.CONSULTANT,
                public_key=public_key,
                public_key_fingerprint=fingerprint,
                key_generated_at=datetime.utcnow()
            )
            user.set_password('password123')
            
            db.session.add(user)
            db.session.commit()
            
            return user
    
    def test_profile_displays_role_correctly(self, app_and_db, client, test_user_with_keys):
        """Test profile displays role correctly"""
        app, db = app_and_db
        
        with app.app_context():
            # Login
            client.post('/login', data={
                'username': 'testuser',
                'password': 'password123'
            })
            
            # Access profile page
            response = client.get('/profile')
            
            # Verify response
            assert response.status_code == 200
            assert b'ORGANIZATION' in response.data
            assert b'ROLE' in response.data
    
    def test_profile_displays_consultant_role(self, app_and_db, client, test_consultant_with_keys):
        """Test profile displays consultant role correctly"""
        app, db = app_and_db
        
        with app.app_context():
            # Login
            client.post('/login', data={
                'username': 'consultant',
                'password': 'password123'
            })
            
            # Access profile page
            response = client.get('/profile')
            
            # Verify response
            assert response.status_code == 200
            assert b'CONSULTANT' in response.data
            assert b'ROLE' in response.data
    
    def test_profile_displays_fingerprint(self, app_and_db, client, test_user_with_keys):
        """Test profile displays fingerprint"""
        app, db = app_and_db
        
        with app.app_context():
            # Login
            client.post('/login', data={
                'username': 'testuser',
                'password': 'password123'
            })
            
            # Access profile page
            response = client.get('/profile')
            
            # Verify response
            assert response.status_code == 200
            assert b'PUBLIC KEY FINGERPRINT' in response.data
            
            # Verify the actual fingerprint is displayed
            user = User.query.filter_by(username='testuser').first()
            assert user.public_key_fingerprint.encode() in response.data
    
    def test_profile_displays_key_generation_date(self, app_and_db, client, test_user_with_keys):
        """Test profile displays key generation date"""
        app, db = app_and_db
        
        with app.app_context():
            # Login
            client.post('/login', data={
                'username': 'testuser',
                'password': 'password123'
            })
            
            # Access profile page
            response = client.get('/profile')
            
            # Verify response
            assert response.status_code == 200
            assert b'KEY GENERATED' in response.data
            
            # Verify a date is displayed (check for common date format elements)
            user = User.query.filter_by(username='testuser').first()
            # The template formats as: '%B %d, %Y at %H:%M'
            # So we should see the year at minimum
            year = str(user.key_generated_at.year).encode()
            assert year in response.data
    
    def test_profile_requires_authentication(self, app_and_db, client):
        """Test profile page requires authentication"""
        app, db = app_and_db
        
        with app.app_context():
            # Try to access profile without login
            response = client.get('/profile', follow_redirects=False)
            
            # Should redirect to login
            assert response.status_code == 302
            assert '/login' in response.location
    
    def test_profile_displays_username(self, app_and_db, client, test_user_with_keys):
        """Test profile displays username"""
        app, db = app_and_db
        
        with app.app_context():
            # Login
            client.post('/login', data={
                'username': 'testuser',
                'password': 'password123'
            })
            
            # Access profile page
            response = client.get('/profile')
            
            # Verify response
            assert response.status_code == 200
            assert b'testuser' in response.data
            assert b'USERNAME' in response.data
    
    def test_profile_displays_email(self, app_and_db, client, test_user_with_keys):
        """Test profile displays email"""
        app, db = app_and_db
        
        with app.app_context():
            # Login
            client.post('/login', data={
                'username': 'testuser',
                'password': 'password123'
            })
            
            # Access profile page
            response = client.get('/profile')
            
            # Verify response
            assert response.status_code == 200
            assert b'test@example.com' in response.data
            assert b'EMAIL' in response.data
    
    def test_profile_displays_account_created_date(self, app_and_db, client, test_user_with_keys):
        """Test profile displays account creation date"""
        app, db = app_and_db
        
        with app.app_context():
            # Login
            client.post('/login', data={
                'username': 'testuser',
                'password': 'password123'
            })
            
            # Access profile page
            response = client.get('/profile')
            
            # Verify response
            assert response.status_code == 200
            assert b'ACCOUNT CREATED' in response.data
    
    def test_profile_displays_key_algorithm(self, app_and_db, client, test_user_with_keys):
        """Test profile displays key algorithm"""
        app, db = app_and_db
        
        with app.app_context():
            # Login
            client.post('/login', data={
                'username': 'testuser',
                'password': 'password123'
            })
            
            # Access profile page
            response = client.get('/profile')
            
            # Verify response
            assert response.status_code == 200
            assert b'RSA-2048' in response.data
            assert b'ALGORITHM' in response.data
    
    def test_profile_displays_key_status(self, app_and_db, client, test_user_with_keys):
        """Test profile displays key status as active"""
        app, db = app_and_db
        
        with app.app_context():
            # Login
            client.post('/login', data={
                'username': 'testuser',
                'password': 'password123'
            })
            
            # Access profile page
            response = client.get('/profile')
            
            # Verify response
            assert response.status_code == 200
            assert b'ACTIVE' in response.data
            assert b'STATUS' in response.data
    
    def test_profile_without_keys_shows_message(self, app_and_db, client):
        """Test profile page for user without keys shows appropriate message"""
        app, db = app_and_db
        
        with app.app_context():
            # Create user without keys
            user = User(
                username='nokeyuser',
                email='nokey@example.com',
                role=UserRole.ORGANIZATION
            )
            user.set_password('password123')
            db.session.add(user)
            db.session.commit()
            
            # Login
            client.post('/login', data={
                'username': 'nokeyuser',
                'password': 'password123'
            })
            
            # Access profile page
            response = client.get('/profile')
            
            # Verify response shows no keys message
            assert response.status_code == 200
            assert b'NO ENCRYPTION KEYS' in response.data


def run_profile_tests():
    """Run all profile tests"""
    print("Running Profile Page Tests...")
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
    success = run_profile_tests()
    if success:
        print("\n✅ All profile tests passed!")
    else:
        print("\n❌ Some profile tests failed!")
    
    exit(0 if success else 1)
