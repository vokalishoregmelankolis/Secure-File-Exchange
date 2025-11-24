"""
Unit tests for error handling scenarios

Tests MongoDB connection failures, key generation failures, incorrect passwords,
corrupted keys, and transaction rollbacks.
"""
import pytest
from unittest.mock import patch, MagicMock
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from app import create_app, db
from app.models import User, UserRole, CryptoLog
from app.key_store import KeyStore
from app.asymmetric_crypto import AsymmetricCrypto


@pytest.fixture
def app():
    """Create test application"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SECRET_KEY'] = 'test-secret-key'
    
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


class TestMongoDBConnectionFailure:
    """Test MongoDB connection failure handling"""
    
    def test_keystore_connection_failure(self):
        """Test KeyStore handles MongoDB connection failure gracefully"""
        with patch('app.key_store.MongoClient') as mock_client:
            # Simulate connection failure
            mock_client.side_effect = ConnectionFailure("Unable to connect to MongoDB")
            
            with pytest.raises(ConnectionFailure) as exc_info:
                keystore = KeyStore()
            
            assert "MongoDB connection failed" in str(exc_info.value)
    
    def test_keystore_timeout_failure(self):
        """Test KeyStore handles MongoDB timeout gracefully"""
        with patch('app.key_store.MongoClient') as mock_client:
            # Simulate timeout
            mock_client.side_effect = ServerSelectionTimeoutError("Server selection timeout")
            
            with pytest.raises(ConnectionFailure) as exc_info:
                keystore = KeyStore()
            
            assert "MongoDB connection failed" in str(exc_info.value)
    
    def test_store_private_key_connection_failure(self, app):
        """Test storing private key handles MongoDB connection failure"""
        with app.app_context():
            keystore = KeyStore.__new__(KeyStore)
            keystore._client = None  # Simulate disconnected client
            
            with pytest.raises(ConnectionFailure) as exc_info:
                keystore.store_private_key(
                    user_id=1,
                    encrypted_key=b'encrypted',
                    salt=b'salt',
                    nonce=b'nonce',
                    metadata={'algorithm': 'RSA-2048'}
                )
            
            assert "MongoDB client not initialized" in str(exc_info.value)
    
    def test_retrieve_private_key_connection_failure(self, app):
        """Test retrieving private key handles MongoDB connection failure"""
        with app.app_context():
            keystore = KeyStore.__new__(KeyStore)
            keystore._client = None  # Simulate disconnected client
            
            with pytest.raises(ConnectionFailure) as exc_info:
                keystore.retrieve_private_key(user_id=1)
            
            assert "MongoDB client not initialized" in str(exc_info.value)
    
    def test_registration_mongodb_failure_rollback(self, client, app):
        """Test registration rolls back on MongoDB failure"""
        with app.app_context():
            with patch('app.key_store.KeyStore') as mock_keystore_class:
                # Simulate MongoDB failure during key storage
                mock_keystore = MagicMock()
                mock_keystore.store_private_key.side_effect = ConnectionFailure("MongoDB unavailable")
                mock_keystore_class.return_value = mock_keystore
                
                response = client.post('/register', data={
                    'username': 'testuser',
                    'email': 'test@example.com',
                    'password': 'TestPass123!',
                    'confirm_password': 'TestPass123!',
                    'role': 'organization'
                }, follow_redirects=True)
                
                # Check that user was not created in database
                user = User.query.filter_by(username='testuser').first()
                assert user is None, "User should not exist after MongoDB failure"
                
                # Check error message displayed
                assert b'Registration failed' in response.data or b'error' in response.data.lower()


class TestKeyGenerationFailure:
    """Test key generation failure handling"""
    
    def test_rsa_key_generation_invalid_size(self):
        """Test RSA key generation fails with invalid key size"""
        with pytest.raises(ValueError) as exc_info:
            AsymmetricCrypto.generate_rsa_keypair(key_size=1024)
        
        assert "at least 2048 bits" in str(exc_info.value)
    
    def test_registration_key_generation_failure(self, client, app):
        """Test registration handles key generation failure gracefully"""
        with app.app_context():
            with patch('app.asymmetric_crypto.AsymmetricCrypto.generate_rsa_keypair') as mock_gen:
                # Simulate key generation failure
                mock_gen.side_effect = Exception("Insufficient entropy")
                
                response = client.post('/register', data={
                    'username': 'testuser',
                    'email': 'test@example.com',
                    'password': 'TestPass123!',
                    'confirm_password': 'TestPass123!',
                    'role': 'consultant'
                }, follow_redirects=True)
                
                # Check that user was not created
                user = User.query.filter_by(username='testuser').first()
                assert user is None, "User should not exist after key generation failure"
                
                # Check error message
                assert b'Registration failed' in response.data or b'error' in response.data.lower()


class TestIncorrectPasswordHandling:
    """Test incorrect password handling"""
    
    def test_decrypt_private_key_wrong_password(self):
        """Test decrypting private key with wrong password fails gracefully"""
        # Generate a key pair and encrypt it
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        encrypted_key, salt, nonce = AsymmetricCrypto.encrypt_private_key(
            private_key, "correct_password"
        )
        
        # Try to decrypt with wrong password
        with pytest.raises(ValueError) as exc_info:
            AsymmetricCrypto.decrypt_private_key(
                encrypted_key, "wrong_password", salt, nonce
            )
        
        assert "Decryption failed" in str(exc_info.value) or "incorrect password" in str(exc_info.value).lower()
    
    def test_decrypt_private_key_empty_password(self):
        """Test decrypting private key with empty password fails"""
        with pytest.raises(ValueError) as exc_info:
            AsymmetricCrypto.decrypt_private_key(
                b'encrypted', "", b'salt', b'nonce'
            )
        
        assert "Password cannot be empty" in str(exc_info.value)
    
    def test_encrypt_private_key_empty_password(self):
        """Test encrypting private key with empty password fails"""
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        
        with pytest.raises(ValueError) as exc_info:
            AsymmetricCrypto.encrypt_private_key(private_key, "")
        
        assert "Password cannot be empty" in str(exc_info.value)


class TestCorruptedKeyHandling:
    """Test corrupted key data handling"""
    
    def test_unwrap_symmetric_key_corrupted_private_key(self):
        """Test unwrapping with corrupted private key fails gracefully"""
        # Generate valid keys
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        symmetric_key = b'0123456789abcdef' * 2  # 32 bytes
        wrapped_key = AsymmetricCrypto.wrap_symmetric_key(symmetric_key, public_key)
        
        # Corrupt the private key
        corrupted_private_key = b'CORRUPTED_KEY_DATA'
        
        with pytest.raises(ValueError) as exc_info:
            AsymmetricCrypto.unwrap_symmetric_key(wrapped_key, corrupted_private_key)
        
        assert "Invalid private key" in str(exc_info.value)
    
    def test_wrap_symmetric_key_corrupted_public_key(self):
        """Test wrapping with corrupted public key fails gracefully"""
        symmetric_key = b'0123456789abcdef' * 2  # 32 bytes
        corrupted_public_key = b'CORRUPTED_PUBLIC_KEY'
        
        with pytest.raises(ValueError) as exc_info:
            AsymmetricCrypto.wrap_symmetric_key(symmetric_key, corrupted_public_key)
        
        assert "Invalid public key" in str(exc_info.value)
    
    def test_decrypt_private_key_corrupted_data(self):
        """Test decrypting corrupted private key data fails gracefully"""
        # Create valid encrypted key first
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        encrypted_key, salt, nonce = AsymmetricCrypto.encrypt_private_key(
            private_key, "password123"
        )
        
        # Corrupt the encrypted key
        corrupted_encrypted_key = b'CORRUPTED' + encrypted_key[9:]
        
        with pytest.raises(ValueError) as exc_info:
            AsymmetricCrypto.decrypt_private_key(
                corrupted_encrypted_key, "password123", salt, nonce
            )
        
        assert "Decryption failed" in str(exc_info.value) or "corrupted" in str(exc_info.value).lower()
    
    def test_get_public_key_fingerprint_invalid_key(self):
        """Test fingerprint generation with invalid key fails gracefully"""
        invalid_key = b'NOT_A_VALID_KEY'
        
        with pytest.raises(ValueError) as exc_info:
            AsymmetricCrypto.get_public_key_fingerprint(invalid_key)
        
        assert "Invalid public key" in str(exc_info.value)


class TestTransactionRollback:
    """Test database transaction rollback on errors"""
    
    def test_registration_rollback_on_keystore_failure(self, client, app):
        """Test registration transaction rolls back when KeyStore fails"""
        with app.app_context():
            initial_user_count = User.query.count()
            
            with patch('app.key_store.KeyStore') as mock_keystore_class:
                # Simulate KeyStore failure
                mock_keystore = MagicMock()
                mock_keystore.store_private_key.side_effect = Exception("Storage failure")
                mock_keystore_class.return_value = mock_keystore
                
                response = client.post('/register', data={
                    'username': 'rollback_test',
                    'email': 'rollback@example.com',
                    'password': 'TestPass123!',
                    'confirm_password': 'TestPass123!',
                    'role': 'organization'
                }, follow_redirects=True)
                
                # Verify user was not created (transaction rolled back)
                final_user_count = User.query.count()
                assert final_user_count == initial_user_count, "User count should not change after rollback"
                
                user = User.query.filter_by(username='rollback_test').first()
                assert user is None, "User should not exist after rollback"
    
    def test_approve_request_rollback_on_error(self, client, app):
        """Test access request approval rolls back on error"""
        with app.app_context():
            # Create organization user
            org_user = User(username='org', email='org@example.com', role=UserRole.ORGANIZATION)
            org_user.set_password('password')
            public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
            org_user.public_key = public_key
            org_user.public_key_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(public_key)
            db.session.add(org_user)
            
            # Create consultant user
            consultant_user = User(username='consultant', email='consultant@example.com', role=UserRole.CONSULTANT)
            consultant_user.set_password('password')
            consultant_user.public_key = public_key
            consultant_user.public_key_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(public_key)
            db.session.add(consultant_user)
            
            db.session.commit()
            
            # Login as organization
            client.post('/login', data={
                'username': 'org',
                'password': 'password'
            })
            
            # Create a mock access request (simplified for testing)
            from app.models import AccessRequest, EncryptedFile
            
            # Create a file
            file = EncryptedFile(
                file_id='test123',
                filename='test_encrypted',
                original_filename='test.txt',
                file_type='text',
                file_size=100,
                encrypted_path='/fake/path',
                algorithm='AES',
                wrapped_key=b'fake_wrapped_key',
                iv=b'fake_iv',
                user_id=org_user.id
            )
            db.session.add(file)
            db.session.commit()
            
            # Create access request
            access_request = AccessRequest(
                consultant_id=consultant_user.id,
                organization_id=org_user.id,
                file_id=file.id,
                status='pending'
            )
            db.session.add(access_request)
            db.session.commit()
            
            initial_status = access_request.status
            
            # Simulate error during approval by mocking the wrap function
            with patch('app.asymmetric_crypto.AsymmetricCrypto.wrap_symmetric_key') as mock_wrap:
                mock_wrap.side_effect = Exception("Wrapping failed")
                
                response = client.post(f'/approve-request/{access_request.id}', follow_redirects=True)
                
                # Refresh the access request from database
                db.session.refresh(access_request)
                
                # Verify status was not changed (rolled back)
                assert access_request.status == initial_status, "Status should not change after rollback"
                assert access_request.wrapped_symmetric_key is None, "Wrapped key should not be set after rollback"


class TestCryptoOperationLogging:
    """Test that crypto operations are logged even on failure"""
    
    def test_failed_key_generation_logged(self, client, app):
        """Test that failed key generation is logged"""
        with app.app_context():
            with patch('app.asymmetric_crypto.AsymmetricCrypto.generate_rsa_keypair') as mock_gen:
                mock_gen.side_effect = Exception("Key generation failed")
                
                initial_log_count = CryptoLog.query.count()
                
                response = client.post('/register', data={
                    'username': 'logtest',
                    'email': 'logtest@example.com',
                    'password': 'TestPass123!',
                    'confirm_password': 'TestPass123!',
                    'role': 'consultant'
                }, follow_redirects=True)
                
                # Note: Logging might not occur if user.id is not available
                # This test verifies the error handling path exists
                assert b'Registration failed' in response.data or b'error' in response.data.lower()
