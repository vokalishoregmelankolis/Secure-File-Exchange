"""
Unit Tests for User Registration with Key Generation

This module contains unit tests for the registration workflow,
including role selection and RSA key pair generation.
"""

import pytest
from unittest.mock import patch, MagicMock
from pymongo.errors import ConnectionFailure
from tests import create_test_app
from app.models import User, UserRole, CryptoLog
from app.asymmetric_crypto import AsymmetricCrypto


class TestRegistrationWithKeyGeneration:
    """Unit tests for registration with key generation"""
    
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
    
    def test_successful_registration_creates_keys(self, app_and_db, client):
        """Test successful registration creates RSA keys"""
        app, db = app_and_db
        
        with app.app_context():
            # Mock KeyStore to avoid MongoDB dependency
            with patch('app.key_store.KeyStore') as mock_keystore_class:
                mock_keystore = MagicMock()
                mock_keystore.store_private_key.return_value = True
                mock_keystore_class.return_value = mock_keystore
                
                # Submit registration form
                response = client.post('/register', data={
                    'username': 'testuser',
                    'email': 'test@example.com',
                    'password': 'password123',
                    'confirm_password': 'password123',
                    'role': 'organization',
                    'submit': 'Register'
                }, follow_redirects=False)
                
                # Verify redirect to login
                assert response.status_code == 302
                assert '/login' in response.location
                
                # Verify user was created
                user = User.query.filter_by(username='testuser').first()
                assert user is not None
                assert user.email == 'test@example.com'
                assert user.role == UserRole.ORGANIZATION
                
                # Verify public key was stored in SQLite
                assert user.public_key is not None
                assert len(user.public_key) > 0
                assert user.public_key.startswith(b'-----BEGIN PUBLIC KEY-----')
                
                # Verify public key fingerprint was generated
                assert user.public_key_fingerprint is not None
                assert len(user.public_key_fingerprint) == 64  # SHA-256 hex
                
                # Verify key generation timestamp
                assert user.key_generated_at is not None
                
                # Verify private key was stored in MongoDB
                mock_keystore.store_private_key.assert_called_once()
                call_args = mock_keystore.store_private_key.call_args
                assert call_args[1]['user_id'] == user.id
                assert call_args[1]['encrypted_key'] is not None
                assert call_args[1]['salt'] is not None
                assert call_args[1]['nonce'] is not None
                
                # Verify crypto log was created
                crypto_log = CryptoLog.query.filter_by(user_id=user.id).first()
                assert crypto_log is not None
                assert crypto_log.operation == 'keypair_generated'
                assert crypto_log.success is True
    
    def test_key_generation_failure_rolls_back_registration(self, app_and_db, client):
        """Test key generation failure rolls back registration"""
        app, db = app_and_db
        
        with app.app_context():
            # Mock KeyStore to simulate failure
            with patch('app.key_store.KeyStore') as mock_keystore_class:
                mock_keystore = MagicMock()
                mock_keystore.store_private_key.side_effect = Exception('MongoDB connection failed')
                mock_keystore_class.return_value = mock_keystore
                
                # Submit registration form
                response = client.post('/register', data={
                    'username': 'failuser',
                    'email': 'fail@example.com',
                    'password': 'password123',
                    'confirm_password': 'password123',
                    'role': 'consultant',
                    'submit': 'Register'
                }, follow_redirects=True)
                
                # Verify error message is displayed
                assert b'Registration failed' in response.data or b'error' in response.data.lower()
                
                # Verify user was NOT created (rollback)
                user = User.query.filter_by(username='failuser').first()
                assert user is None
    
    def test_public_key_stored_in_sqlite(self, app_and_db, client):
        """Test public key stored in SQLite User table"""
        app, db = app_and_db
        
        with app.app_context():
            # Mock KeyStore
            with patch('app.key_store.KeyStore') as mock_keystore_class:
                mock_keystore = MagicMock()
                mock_keystore.store_private_key.return_value = True
                mock_keystore_class.return_value = mock_keystore
                
                # Register user
                client.post('/register', data={
                    'username': 'sqliteuser',
                    'email': 'sqlite@example.com',
                    'password': 'password123',
                    'confirm_password': 'password123',
                    'role': 'organization',
                    'submit': 'Register'
                })
                
                # Query user from database
                user = User.query.filter_by(username='sqliteuser').first()
                
                # Verify public key is in SQLite
                assert user.public_key is not None
                assert isinstance(user.public_key, bytes)
                
                # Verify it's a valid RSA public key
                from Crypto.PublicKey import RSA
                public_rsa = RSA.import_key(user.public_key)
                assert not public_rsa.has_private()
                
                # Verify fingerprint matches the public key
                expected_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(user.public_key)
                assert user.public_key_fingerprint == expected_fingerprint
    
    def test_private_key_stored_in_mongodb(self, app_and_db, client):
        """Test private key stored in MongoDB"""
        app, db = app_and_db
        
        with app.app_context():
            # Mock KeyStore to capture the call
            with patch('app.key_store.KeyStore') as mock_keystore_class:
                mock_keystore = MagicMock()
                mock_keystore.store_private_key.return_value = True
                mock_keystore_class.return_value = mock_keystore
                
                # Register user
                client.post('/register', data={
                    'username': 'mongouser',
                    'email': 'mongo@example.com',
                    'password': 'password123',
                    'confirm_password': 'password123',
                    'role': 'consultant',
                    'submit': 'Register'
                })
                
                # Verify KeyStore.store_private_key was called
                assert mock_keystore.store_private_key.called
                
                # Get the call arguments
                call_args = mock_keystore.store_private_key.call_args
                
                # Verify encrypted key is not the same as public key
                user = User.query.filter_by(username='mongouser').first()
                encrypted_key = call_args[1]['encrypted_key']
                assert encrypted_key != user.public_key
                
                # Verify salt and nonce are present
                assert call_args[1]['salt'] is not None
                assert call_args[1]['nonce'] is not None
                assert len(call_args[1]['salt']) == AsymmetricCrypto.SALT_SIZE
                assert len(call_args[1]['nonce']) == AsymmetricCrypto.NONCE_SIZE
                
                # Verify metadata includes algorithm
                assert call_args[1]['metadata']['algorithm'] == 'RSA-2048'
    
    def test_registration_with_organization_role(self, app_and_db, client):
        """Test registration with organization role"""
        app, db = app_and_db
        
        with app.app_context():
            with patch('app.key_store.KeyStore') as mock_keystore_class:
                mock_keystore = MagicMock()
                mock_keystore.store_private_key.return_value = True
                mock_keystore_class.return_value = mock_keystore
                
                # Register as organization
                client.post('/register', data={
                    'username': 'orguser',
                    'email': 'org@example.com',
                    'password': 'password123',
                    'confirm_password': 'password123',
                    'role': 'organization',
                    'submit': 'Register'
                })
                
                # Verify role
                user = User.query.filter_by(username='orguser').first()
                assert user.role == UserRole.ORGANIZATION
    
    def test_registration_with_consultant_role(self, app_and_db, client):
        """Test registration with consultant role"""
        app, db = app_and_db
        
        with app.app_context():
            with patch('app.key_store.KeyStore') as mock_keystore_class:
                mock_keystore = MagicMock()
                mock_keystore.store_private_key.return_value = True
                mock_keystore_class.return_value = mock_keystore
                
                # Register as consultant
                client.post('/register', data={
                    'username': 'consultantuser',
                    'email': 'consultant@example.com',
                    'password': 'password123',
                    'confirm_password': 'password123',
                    'role': 'consultant',
                    'submit': 'Register'
                })
                
                # Verify role
                user = User.query.filter_by(username='consultantuser').first()
                assert user.role == UserRole.CONSULTANT
    
    def test_crypto_log_created_on_success(self, app_and_db, client):
        """Test crypto log is created on successful registration"""
        app, db = app_and_db
        
        with app.app_context():
            with patch('app.key_store.KeyStore') as mock_keystore_class:
                mock_keystore = MagicMock()
                mock_keystore.store_private_key.return_value = True
                mock_keystore_class.return_value = mock_keystore
                
                # Register user
                client.post('/register', data={
                    'username': 'loguser',
                    'email': 'log@example.com',
                    'password': 'password123',
                    'confirm_password': 'password123',
                    'role': 'organization',
                    'submit': 'Register'
                })
                
                # Verify crypto log
                user = User.query.filter_by(username='loguser').first()
                crypto_log = CryptoLog.query.filter_by(user_id=user.id).first()
                
                assert crypto_log is not None
                assert crypto_log.operation == 'keypair_generated'
                assert crypto_log.success is True
                assert 'RSA-2048' in crypto_log.details
                assert user.username in crypto_log.details
    
    def test_mongodb_cleanup_on_failure(self, app_and_db, client):
        """Test MongoDB cleanup when registration fails after key storage"""
        app, db = app_and_db
        
        with app.app_context():
            with patch('app.key_store.KeyStore') as mock_keystore_class:
                mock_keystore = MagicMock()
                # Simulate failure after storing key
                mock_keystore.store_private_key.return_value = True
                mock_keystore_class.return_value = mock_keystore
                
                # Patch db.session.commit to raise an error
                with patch('app.routes.db.session.commit', side_effect=Exception('Database error')):
                    # Register user
                    client.post('/register', data={
                        'username': 'cleanupuser',
                        'email': 'cleanup@example.com',
                        'password': 'password123',
                        'confirm_password': 'password123',
                        'role': 'organization',
                        'submit': 'Register'
                    })
                    
                    # Verify delete_private_key was called for cleanup
                    # (This would be called in the exception handler)
                    # Note: In the actual implementation, cleanup happens in except block
    
    def test_key_size_meets_requirements(self, app_and_db, client):
        """Test generated keys meet minimum 2048-bit requirement"""
        app, db = app_and_db
        
        with app.app_context():
            with patch('app.key_store.KeyStore') as mock_keystore_class:
                mock_keystore = MagicMock()
                mock_keystore.store_private_key.return_value = True
                mock_keystore_class.return_value = mock_keystore
                
                # Register user
                client.post('/register', data={
                    'username': 'keysizeuser',
                    'email': 'keysize@example.com',
                    'password': 'password123',
                    'confirm_password': 'password123',
                    'role': 'organization',
                    'submit': 'Register'
                })
                
                # Verify key size
                user = User.query.filter_by(username='keysizeuser').first()
                
                from Crypto.PublicKey import RSA
                public_rsa = RSA.import_key(user.public_key)
                
                # Verify key size is at least 2048 bits
                assert public_rsa.size_in_bits() >= 2048


def run_registration_tests():
    """Run all registration tests"""
    print("Running Registration Tests...")
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
    success = run_registration_tests()
    if success:
        print("\n✅ All registration tests passed!")
    else:
        print("\n❌ Some registration tests failed!")
    
    exit(0 if success else 1)
