"""
Unit Tests for Key Decryption

This module contains unit tests for the symmetric key decryption workflow,
including successful decryption, incorrect password handling, and logging.

Requirements: 6.2, 6.3, 6.4, 11.3, 11.4
"""

import pytest
from unittest.mock import patch, MagicMock
from tests import create_test_app
from app.models import User, UserRole, EncryptedFile, AccessRequest, CryptoLog
from app.asymmetric_crypto import AsymmetricCrypto
from app.key_store import KeyStore
from pymongo.errors import ConnectionFailure
from datetime import datetime


class TestKeyDecryption:
    """Unit tests for key decryption workflow"""
    
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
        """Create test data with approved access request"""
        app, db = app_and_db
        
        with app.app_context():
            # Create organization user
            org_user = User(
                username='org_user',
                email='org@example.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('password123')
            
            # Create consultant user with RSA keys
            consultant_user = User(
                username='consultant_user',
                email='consultant@example.com',
                role=UserRole.CONSULTANT
            )
            consultant_user.set_password('password123')
            
            # Generate RSA key pair for consultant
            public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
            consultant_user.public_key = public_key
            consultant_user.public_key_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(public_key)
            consultant_user.key_generated_at = datetime.utcnow()
            
            db.session.add(org_user)
            db.session.add(consultant_user)
            db.session.commit()
            
            # Store encrypted private key in MongoDB (mocked)
            encrypted_key, salt, nonce = AsymmetricCrypto.encrypt_private_key(
                private_key, 'password123'
            )
            
            # Create file
            file = EncryptedFile(
                file_id='test-file-123',
                filename='test_encrypted',
                original_filename='test.txt',
                file_type='text',
                file_size=1024,
                encrypted_path='/path/to/encrypted',
                algorithm='AES',
                wrapped_key=b'wrapped_dek_data',
                iv=b'initialization_vector',
                user_id=org_user.id
            )
            db.session.add(file)
            db.session.commit()
            
            # Create symmetric key and wrap it
            symmetric_key = b'test_symmetric_key_32_bytes_!'
            wrapped_symmetric_key = AsymmetricCrypto.wrap_symmetric_key(
                symmetric_key, public_key
            )
            
            # Create approved access request
            access_request = AccessRequest(
                consultant_id=consultant_user.id,
                organization_id=org_user.id,
                file_id=file.id,
                status='approved',
                wrapped_symmetric_key=wrapped_symmetric_key,
                processed_at=datetime.utcnow()
            )
            db.session.add(access_request)
            db.session.commit()
            
            return {
                'organization': org_user,
                'consultant': consultant_user,
                'file': file,
                'access_request': access_request,
                'private_key': private_key,
                'encrypted_key': encrypted_key,
                'salt': salt,
                'nonce': nonce,
                'symmetric_key': symmetric_key
            }
    
    @patch('app.key_store.KeyStore')
    def test_successful_decryption_with_correct_password(self, mock_keystore_class, app_and_db, client, test_data):
        """Test successful decryption with correct password
        
        Requirement 6.2: Consultant should be able to decrypt key with correct password
        """
        app, db = app_and_db
        
        with app.app_context():
            # Setup mock KeyStore
            mock_keystore = MagicMock()
            mock_keystore_class.return_value = mock_keystore
            
            consultant = User.query.filter_by(username='consultant_user').first()
            access_request = AccessRequest.query.filter_by(consultant_id=consultant.id).first()
            
            # Mock retrieve_private_key to return test data
            mock_keystore.retrieve_private_key.return_value = {
                'encrypted_key': test_data['encrypted_key'],
                'salt': test_data['salt'],
                'nonce': test_data['nonce'],
                'created_at': datetime.utcnow(),
                'algorithm': 'RSA-2048'
            }
            
            # Login as consultant
            client.post('/login', data={
                'username': 'consultant_user',
                'password': 'password123'
            })
            
            # Submit decrypt key form with correct password
            response = client.post(f'/decrypt-key/{access_request.id}', data={
                'password': 'password123',
                'submit': 'Decrypt Key'
            }, follow_redirects=True)
            
            # Verify success
            assert response.status_code == 200
            assert b'successfully' in response.data or b'success' in response.data.lower()
            
            # Verify KeyStore was called
            mock_keystore.retrieve_private_key.assert_called_once_with(consultant.id)
            mock_keystore.close.assert_called()
    
    @patch('app.key_store.KeyStore')
    def test_decryption_failure_with_incorrect_password(self, mock_keystore_class, app_and_db, client, test_data):
        """Test decryption failure with incorrect password
        
        Requirement 6.3: Decryption should fail with incorrect password
        """
        app, db = app_and_db
        
        with app.app_context():
            # Setup mock KeyStore
            mock_keystore = MagicMock()
            mock_keystore_class.return_value = mock_keystore
            
            consultant = User.query.filter_by(username='consultant_user').first()
            access_request = AccessRequest.query.filter_by(consultant_id=consultant.id).first()
            
            # Mock retrieve_private_key to return test data
            mock_keystore.retrieve_private_key.return_value = {
                'encrypted_key': test_data['encrypted_key'],
                'salt': test_data['salt'],
                'nonce': test_data['nonce'],
                'created_at': datetime.utcnow(),
                'algorithm': 'RSA-2048'
            }
            
            # Login as consultant
            client.post('/login', data={
                'username': 'consultant_user',
                'password': 'password123'
            })
            
            # Submit decrypt key form with incorrect password
            response = client.post(f'/decrypt-key/{access_request.id}', data={
                'password': 'wrong_password',
                'submit': 'Decrypt Key'
            }, follow_redirects=True)
            
            # Verify error message
            assert response.status_code == 200
            assert b'Incorrect password' in response.data or b'Error' in response.data
            
            # Verify KeyStore was called
            mock_keystore.retrieve_private_key.assert_called_once_with(consultant.id)
            mock_keystore.close.assert_called()
    
    @patch('app.key_store.KeyStore')
    def test_decryption_logs_operation(self, mock_keystore_class, app_and_db, client, test_data):
        """Test decryption logs operation
        
        Requirement 11.3: Key unwrapping should be logged
        """
        app, db = app_and_db
        
        with app.app_context():
            # Setup mock KeyStore
            mock_keystore = MagicMock()
            mock_keystore_class.return_value = mock_keystore
            
            consultant = User.query.filter_by(username='consultant_user').first()
            access_request = AccessRequest.query.filter_by(consultant_id=consultant.id).first()
            
            # Mock retrieve_private_key to return test data
            mock_keystore.retrieve_private_key.return_value = {
                'encrypted_key': test_data['encrypted_key'],
                'salt': test_data['salt'],
                'nonce': test_data['nonce'],
                'created_at': datetime.utcnow(),
                'algorithm': 'RSA-2048'
            }
            
            # Login as consultant
            client.post('/login', data={
                'username': 'consultant_user',
                'password': 'password123'
            })
            
            # Get initial log count
            initial_log_count = CryptoLog.query.filter_by(
                user_id=consultant.id,
                operation='key_unwrapped'
            ).count()
            
            # Submit decrypt key form
            client.post(f'/decrypt-key/{access_request.id}', data={
                'password': 'password123',
                'submit': 'Decrypt Key'
            })
            
            # Verify log was created
            final_log_count = CryptoLog.query.filter_by(
                user_id=consultant.id,
                operation='key_unwrapped'
            ).count()
            
            assert final_log_count == initial_log_count + 1, \
                "A crypto log entry should be created for key unwrapping"
            
            # Verify log details
            log = CryptoLog.query.filter_by(
                user_id=consultant.id,
                operation='key_unwrapped'
            ).order_by(CryptoLog.timestamp.desc()).first()
            
            assert log is not None
            assert log.success is True
            assert 'unwrapped' in log.details.lower() or 'symmetric key' in log.details.lower()
    
    @patch('app.key_store.KeyStore')
    def test_failed_decryption_logs_error(self, mock_keystore_class, app_and_db, client, test_data):
        """Test failed decryption logs error
        
        Requirement 11.4: Failed decryption should be logged with error details
        """
        app, db = app_and_db
        
        with app.app_context():
            # Setup mock KeyStore
            mock_keystore = MagicMock()
            mock_keystore_class.return_value = mock_keystore
            
            consultant = User.query.filter_by(username='consultant_user').first()
            access_request = AccessRequest.query.filter_by(consultant_id=consultant.id).first()
            
            # Mock retrieve_private_key to return test data
            mock_keystore.retrieve_private_key.return_value = {
                'encrypted_key': test_data['encrypted_key'],
                'salt': test_data['salt'],
                'nonce': test_data['nonce'],
                'created_at': datetime.utcnow(),
                'algorithm': 'RSA-2048'
            }
            
            # Login as consultant
            client.post('/login', data={
                'username': 'consultant_user',
                'password': 'password123'
            })
            
            # Get initial log count
            initial_log_count = CryptoLog.query.filter_by(
                user_id=consultant.id,
                operation='key_unwrapped',
                success=False
            ).count()
            
            # Submit decrypt key form with wrong password
            client.post(f'/decrypt-key/{access_request.id}', data={
                'password': 'wrong_password',
                'submit': 'Decrypt Key'
            })
            
            # Verify error log was created
            final_log_count = CryptoLog.query.filter_by(
                user_id=consultant.id,
                operation='key_unwrapped',
                success=False
            ).count()
            
            assert final_log_count == initial_log_count + 1, \
                "A crypto log entry should be created for failed key unwrapping"
            
            # Verify log details
            log = CryptoLog.query.filter_by(
                user_id=consultant.id,
                operation='key_unwrapped',
                success=False
            ).order_by(CryptoLog.timestamp.desc()).first()
            
            assert log is not None
            assert log.success is False
            assert log.error_message is not None
            assert len(log.error_message) > 0
    
    @patch('app.key_store.KeyStore')
    def test_private_key_retrieved_from_mongodb(self, mock_keystore_class, app_and_db, client, test_data):
        """Test private key retrieved from MongoDB
        
        Requirement 6.4: Private key should be retrieved from MongoDB for decryption
        """
        app, db = app_and_db
        
        with app.app_context():
            # Setup mock KeyStore
            mock_keystore = MagicMock()
            mock_keystore_class.return_value = mock_keystore
            
            consultant = User.query.filter_by(username='consultant_user').first()
            access_request = AccessRequest.query.filter_by(consultant_id=consultant.id).first()
            
            # Mock retrieve_private_key to return test data
            mock_keystore.retrieve_private_key.return_value = {
                'encrypted_key': test_data['encrypted_key'],
                'salt': test_data['salt'],
                'nonce': test_data['nonce'],
                'created_at': datetime.utcnow(),
                'algorithm': 'RSA-2048'
            }
            
            # Login as consultant
            client.post('/login', data={
                'username': 'consultant_user',
                'password': 'password123'
            })
            
            # Submit decrypt key form
            client.post(f'/decrypt-key/{access_request.id}', data={
                'password': 'password123',
                'submit': 'Decrypt Key'
            })
            
            # Verify KeyStore.retrieve_private_key was called with correct user_id
            mock_keystore.retrieve_private_key.assert_called_once_with(consultant.id)
    
    def test_consultant_cannot_decrypt_other_consultant_key(self, app_and_db, client, test_data):
        """Test consultant cannot decrypt another consultant's key"""
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
            access_request = AccessRequest.query.filter_by(consultant_id=consultant1.id).first()
            
            # Login as consultant2
            client.post('/login', data={
                'username': 'consultant2',
                'password': 'password123'
            })
            
            # Try to decrypt consultant1's key
            response = client.post(f'/decrypt-key/{access_request.id}', data={
                'password': 'password123',
                'submit': 'Decrypt Key'
            }, follow_redirects=True)
            
            # Verify access denied
            assert b'Access denied' in response.data or b'only decrypt keys for your own' in response.data
    
    def test_organization_cannot_decrypt_key(self, app_and_db, client, test_data):
        """Test organization user cannot decrypt keys"""
        app, db = app_and_db
        
        with app.app_context():
            consultant = User.query.filter_by(username='consultant_user').first()
            access_request = AccessRequest.query.filter_by(consultant_id=consultant.id).first()
            
            # Login as organization
            client.post('/login', data={
                'username': 'org_user',
                'password': 'password123'
            })
            
            # Try to decrypt key
            response = client.post(f'/decrypt-key/{access_request.id}', data={
                'password': 'password123',
                'submit': 'Decrypt Key'
            }, follow_redirects=True)
            
            # Verify access denied
            assert b'Access denied' in response.data or b'Only consultants' in response.data
    
    def test_cannot_decrypt_pending_request(self, app_and_db, client):
        """Test cannot decrypt key for pending request"""
        app, db = app_and_db
        
        with app.app_context():
            # Create consultant
            consultant = User(
                username='consultant_pending',
                email='consultant_pending@example.com',
                role=UserRole.CONSULTANT
            )
            consultant.set_password('password123')
            
            # Create organization
            org = User(
                username='org_pending',
                email='org_pending@example.com',
                role=UserRole.ORGANIZATION
            )
            org.set_password('password123')
            
            db.session.add_all([consultant, org])
            db.session.commit()
            
            # Create file
            file = EncryptedFile(
                file_id='pending-file',
                filename='pending_encrypted',
                original_filename='pending.txt',
                file_type='text',
                file_size=1024,
                encrypted_path='/path/to/pending',
                algorithm='AES',
                wrapped_key=b'wrapped_key',
                iv=b'iv',
                user_id=org.id
            )
            db.session.add(file)
            db.session.commit()
            
            # Create pending access request (not approved)
            access_request = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org.id,
                file_id=file.id,
                status='pending'
            )
            db.session.add(access_request)
            db.session.commit()
            
            # Login as consultant
            client.post('/login', data={
                'username': 'consultant_pending',
                'password': 'password123'
            })
            
            # Try to decrypt key for pending request
            response = client.post(f'/decrypt-key/{access_request.id}', data={
                'password': 'password123',
                'submit': 'Decrypt Key'
            }, follow_redirects=True)
            
            # Verify error
            assert b'Cannot decrypt' in response.data or b'pending' in response.data
    
    def test_unauthenticated_user_cannot_decrypt(self, app_and_db, client, test_data):
        """Test unauthenticated user cannot decrypt keys"""
        app, db = app_and_db
        
        with app.app_context():
            consultant = User.query.filter_by(username='consultant_user').first()
            access_request = AccessRequest.query.filter_by(consultant_id=consultant.id).first()
            
            # Try to decrypt without logging in
            response = client.post(f'/decrypt-key/{access_request.id}', data={
                'password': 'password123',
                'submit': 'Decrypt Key'
            }, follow_redirects=False)
            
            # Verify redirect to login
            assert response.status_code == 302
            assert '/login' in response.location


def run_decrypt_key_tests():
    """Run all decrypt key tests"""
    print("Running Key Decryption Tests...")
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
    success = run_decrypt_key_tests()
    if success:
        print("\n✅ All decrypt key tests passed!")
    else:
        print("\n❌ Some decrypt key tests failed!")
    
    exit(0 if success else 1)
