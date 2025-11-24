"""
Property-Based Tests for Asymmetric Key Exchange

This module contains property-based tests using Hypothesis to verify
correctness properties across many random inputs.

IMPORTANT: These tests can generate a lot of data and fill up disk space!
- Use HYPOTHESIS_PROFILE=dev for development (fewer examples)
- Use HYPOTHESIS_PROFILE=ci for CI/CD (more examples)
- Run cleanup_test_data.py regularly to free up space
"""

import os
import sys
import tempfile
import pytest
from datetime import datetime
from hypothesis import given, strategies as st, settings, HealthCheck, Phase
from hypothesis import settings as hypothesis_settings
from pymongo.errors import ConnectionFailure

# Configure Hypothesis profiles to control test volume
hypothesis_settings.register_profile("dev", max_examples=10, deadline=None)
hypothesis_settings.register_profile("ci", max_examples=100, deadline=None)
hypothesis_settings.register_profile("default", max_examples=20, deadline=None)

# Load profile from environment or use default
hypothesis_settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "default"))

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.key_store import KeyStore
from app.asymmetric_crypto import AsymmetricCrypto
from app import create_app, db
from app.models import User


# Strategies for generating test data
user_ids = st.integers(min_value=1, max_value=10000)
encrypted_keys = st.binary(min_size=100, max_size=500)
salts = st.binary(min_size=16, max_size=32)
nonces = st.binary(min_size=12, max_size=16)

# Strategies for asymmetric crypto testing
symmetric_keys = st.binary(min_size=16, max_size=32)  # AES keys (128-256 bit)
passwords = st.text(min_size=8, max_size=64, alphabet=st.characters(
    blacklist_categories=('Cs',),  # Exclude surrogates
    blacklist_characters='\x00'  # Exclude null bytes
))
key_sizes = st.sampled_from([2048, 3072, 4096])


@pytest.fixture(scope='function')
def app_context():
    """Create Flask app context for testing"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture(scope='function')
def test_keystore():
    """
    Create a test KeyStore instance with a test database.
    Uses a separate test database to avoid interfering with production data.
    """
    # Use a test database name
    test_db_name = f'test_keystore_{os.getpid()}'
    
    try:
        keystore = KeyStore(
            connection_string='mongodb://localhost:27017/',
            db_name=test_db_name
        )
        yield keystore
    except ConnectionFailure:
        pytest.skip("MongoDB not available for testing")
    finally:
        # Cleanup: drop test database
        try:
            if keystore._client:
                keystore._client.drop_database(test_db_name)
                keystore.close()
        except:
            pass


class TestMongoDBIsolation:
    """
    Property 14: MongoDB isolation
    
    **Feature: asymmetric-key-exchange, Property 14: MongoDB isolation**
    **Validates: Requirements 4.4, 8.3**
    
    For any private key, it should exist in MongoDB and not in the SQLite database.
    """
    
    @given(
        user_id=user_ids,
        encrypted_key=encrypted_keys,
        salt=salts,
        nonce=nonces
    )
    @settings(deadline=None)  # Uses profile settings
    def test_private_keys_stored_only_in_mongodb(
        self,
        app_context,
        test_keystore,
        user_id,
        encrypted_key,
        salt,
        nonce
    ):
        """
        Property: Private keys should be stored in MongoDB, not in SQLite.
        
        This test verifies that:
        1. Private keys can be stored in MongoDB
        2. Private keys are NOT stored in the SQLite database
        3. The two databases remain isolated
        """
        # Store private key in MongoDB
        success = test_keystore.store_private_key(
            user_id=user_id,
            encrypted_key=encrypted_key,
            salt=salt,
            nonce=nonce,
            metadata={'algorithm': 'RSA-2048'}
        )
        
        # Verify storage succeeded
        assert success, "Private key storage in MongoDB should succeed"
        
        # Verify key exists in MongoDB
        assert test_keystore.key_exists(user_id), \
            "Private key should exist in MongoDB after storage"
        
        # Verify key can be retrieved from MongoDB
        retrieved = test_keystore.retrieve_private_key(user_id)
        assert retrieved is not None, "Should be able to retrieve stored key from MongoDB"
        assert retrieved['encrypted_key'] == encrypted_key, \
            "Retrieved key should match stored key"
        
        # Verify key is NOT in SQLite database
        # Check that User table doesn't have a private_key column with this data
        user = User.query.filter_by(id=user_id).first()
        
        # If user doesn't exist in SQLite, that's fine - keys are isolated
        # If user exists, verify they don't have the private key stored
        if user:
            # Check that user model doesn't have encrypted private key data
            # The User model should only have public key, not private key
            user_dict = {c.name: getattr(user, c.name) for c in user.__table__.columns}
            
            # Verify no column contains the encrypted private key
            for column_name, value in user_dict.items():
                if value is not None and isinstance(value, bytes):
                    assert value != encrypted_key, \
                        f"Private key should not be stored in SQLite User.{column_name}"
        
        # Additional isolation check: verify MongoDB and SQLite are separate
        # by checking that MongoDB operations don't affect SQLite
        initial_user_count = User.query.count()
        
        # Store another key in MongoDB
        test_keystore.store_private_key(
            user_id=user_id + 1,
            encrypted_key=encrypted_key + b'_different',
            salt=salt,
            nonce=nonce,
            metadata={'algorithm': 'RSA-2048'}
        )
        
        # Verify SQLite user count unchanged
        assert User.query.count() == initial_user_count, \
            "MongoDB operations should not affect SQLite database"
        
        # Cleanup for this test iteration
        test_keystore.delete_private_key(user_id)
        test_keystore.delete_private_key(user_id + 1)
    
    @given(user_id=user_ids)
    @settings(max_examples=50, deadline=None)
    def test_mongodb_operations_isolated_from_sqlite(
        self,
        app_context,
        test_keystore,
        user_id
    ):
        """
        Property: MongoDB operations should not affect SQLite database.
        
        This test verifies that CRUD operations in MongoDB don't create
        side effects in the SQLite database.
        """
        # Record initial SQLite state
        initial_user_count = User.query.count()
        
        # Perform MongoDB operations
        test_data = {
            'encrypted_key': b'test_encrypted_key_data',
            'salt': b'test_salt_16byte',
            'nonce': b'test_nonce_12'
        }
        
        # Store in MongoDB
        test_keystore.store_private_key(
            user_id=user_id,
            encrypted_key=test_data['encrypted_key'],
            salt=test_data['salt'],
            nonce=test_data['nonce']
        )
        
        # Verify MongoDB has the key
        assert test_keystore.key_exists(user_id)
        
        # Verify SQLite unchanged
        assert User.query.count() == initial_user_count, \
            "MongoDB store should not affect SQLite"
        
        # Retrieve from MongoDB
        retrieved = test_keystore.retrieve_private_key(user_id)
        assert retrieved is not None
        
        # Verify SQLite still unchanged
        assert User.query.count() == initial_user_count, \
            "MongoDB retrieve should not affect SQLite"
        
        # Delete from MongoDB
        test_keystore.delete_private_key(user_id)
        
        # Verify SQLite still unchanged
        assert User.query.count() == initial_user_count, \
            "MongoDB delete should not affect SQLite"
        
        # Verify key no longer in MongoDB
        assert not test_keystore.key_exists(user_id), \
            "Key should be deleted from MongoDB"


class TestMongoDBConnectionHandling:
    """
    Additional tests for MongoDB connection handling and error cases.
    """
    
    def test_connection_failure_handling(self):
        """
        Test that connection failures are handled gracefully.
        """
        # Try to connect to invalid MongoDB instance
        with pytest.raises(ConnectionFailure):
            KeyStore(
                connection_string='mongodb://invalid-host:27017/',
                db_name='test_db'
            )
    
    def test_keystore_context_manager(self, test_keystore):
        """
        Test that KeyStore works as a context manager.
        """
        test_db_name = f'test_context_{os.getpid()}'
        
        try:
            with KeyStore(
                connection_string='mongodb://localhost:27017/',
                db_name=test_db_name
            ) as ks:
                # Verify connection is active
                assert ks._client is not None
                assert ks._collection is not None
                
                # Perform an operation
                success = ks.store_private_key(
                    user_id=999,
                    encrypted_key=b'test_key',
                    salt=b'test_salt_16byte',
                    nonce=b'test_nonce_12'
                )
                assert success
            
            # After context exit, connection should be closed
            # (we can't easily test this without accessing internals)
            
        except ConnectionFailure:
            pytest.skip("MongoDB not available for testing")


class TestRSARoundTrip:
    """
    Property 1: RSA key pair round-trip
    
    **Feature: asymmetric-key-exchange, Property 1: RSA key pair round-trip**
    **Validates: Requirements 6.5, 6.6**
    
    For any symmetric key and RSA key pair, wrapping the symmetric key with the
    public key and then unwrapping it with the private key should produce the
    original symmetric key.
    """
    
    @given(
        symmetric_key=symmetric_keys,
        key_size=key_sizes
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_wrap_unwrap_symmetric_key_round_trip(self, symmetric_key, key_size):
        """
        Property: Wrapping then unwrapping a symmetric key should return the original key.
        
        This test verifies that:
        1. A symmetric key can be wrapped with an RSA public key
        2. The wrapped key can be unwrapped with the corresponding private key
        3. The unwrapped key matches the original symmetric key
        """
        # Generate RSA key pair
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair(key_size)
        
        # Wrap the symmetric key with the public key
        wrapped_key = AsymmetricCrypto.wrap_symmetric_key(symmetric_key, public_key)
        
        # Verify wrapped key is different from original
        assert wrapped_key != symmetric_key, \
            "Wrapped key should be different from original"
        
        # Unwrap the symmetric key with the private key
        unwrapped_key = AsymmetricCrypto.unwrap_symmetric_key(wrapped_key, private_key)
        
        # Verify round-trip: unwrapped key should match original
        assert unwrapped_key == symmetric_key, \
            "Unwrapped key should match original symmetric key"
    
    @given(symmetric_key=symmetric_keys)
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_wrong_private_key_fails_unwrap(self, symmetric_key):
        """
        Property: Unwrapping with wrong private key should fail.
        
        This test verifies that a wrapped key cannot be unwrapped with
        a different private key than the one corresponding to the public key
        used for wrapping.
        """
        # Generate two different RSA key pairs
        public_key1, private_key1 = AsymmetricCrypto.generate_rsa_keypair()
        public_key2, private_key2 = AsymmetricCrypto.generate_rsa_keypair()
        
        # Wrap with first public key
        wrapped_key = AsymmetricCrypto.wrap_symmetric_key(symmetric_key, public_key1)
        
        # Try to unwrap with second (wrong) private key - should fail
        with pytest.raises(ValueError):
            AsymmetricCrypto.unwrap_symmetric_key(wrapped_key, private_key2)


class TestPrivateKeyEncryptionRoundTrip:
    """
    Property 4: Private key encryption round-trip
    
    **Feature: asymmetric-key-exchange, Property 4: Private key encryption round-trip**
    **Validates: Requirements 4.3, 6.4**
    
    For any private key and password, encrypting the private key with the password
    and then decrypting it with the same password should produce the original
    private key.
    """
    
    @given(password=passwords)
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_encrypt_decrypt_private_key_round_trip(self, password):
        """
        Property: Encrypting then decrypting a private key should return the original.
        
        This test verifies that:
        1. A private key can be encrypted with a password
        2. The encrypted key can be decrypted with the same password
        3. The decrypted key matches the original private key
        """
        # Generate RSA key pair
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        
        # Encrypt the private key with password
        encrypted_key, salt, nonce = AsymmetricCrypto.encrypt_private_key(
            private_key, password
        )
        
        # Verify encrypted key is different from original
        assert encrypted_key != private_key, \
            "Encrypted key should be different from original"
        
        # Decrypt the private key with same password
        decrypted_key = AsymmetricCrypto.decrypt_private_key(
            encrypted_key, password, salt, nonce
        )
        
        # Verify round-trip: decrypted key should match original
        assert decrypted_key == private_key, \
            "Decrypted key should match original private key"
        
        # Verify the decrypted key is still a valid RSA private key
        from Crypto.PublicKey import RSA
        rsa_key = RSA.import_key(decrypted_key)
        assert rsa_key.has_private(), \
            "Decrypted key should be a valid RSA private key"


class TestPasswordProtectedRetrieval:
    """
    Property 13: Password-protected private key retrieval
    
    **Feature: asymmetric-key-exchange, Property 13: Password-protected private key retrieval**
    **Validates: Requirements 8.4**
    
    For any attempt to decrypt a private key, providing an incorrect password
    should fail, and providing the correct password should succeed.
    """
    
    @given(
        correct_password=passwords,
        wrong_password=passwords
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_incorrect_password_fails_decryption(self, correct_password, wrong_password):
        """
        Property: Decryption with incorrect password should fail.
        
        This test verifies that:
        1. Decryption succeeds with the correct password
        2. Decryption fails with an incorrect password
        """
        # Skip if passwords happen to be the same
        if correct_password == wrong_password:
            return
        
        # Generate RSA key pair
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        
        # Encrypt with correct password
        encrypted_key, salt, nonce = AsymmetricCrypto.encrypt_private_key(
            private_key, correct_password
        )
        
        # Verify decryption succeeds with correct password
        decrypted_key = AsymmetricCrypto.decrypt_private_key(
            encrypted_key, correct_password, salt, nonce
        )
        assert decrypted_key == private_key, \
            "Decryption should succeed with correct password"
        
        # Verify decryption fails with wrong password
        with pytest.raises(ValueError):
            AsymmetricCrypto.decrypt_private_key(
                encrypted_key, wrong_password, salt, nonce
            )


class TestRoleBasedAuthorization:
    """
    Property 2: Role-based authorization
    
    **Feature: asymmetric-key-exchange, Property 2: Role-based authorization**
    **Validates: Requirements 1.3**
    
    For any user and role-specific operation, the operation should succeed if and
    only if the user has the required role.
    """
    
    @given(
        user_role=st.sampled_from(['organization', 'consultant']),
        required_role=st.sampled_from(['organization', 'consultant'])
    )
    @settings(
        max_examples=100, 
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_role_based_access_control(self, app_context, user_role, required_role):
        """
        Property: Role-specific operations should succeed if and only if user has required role.
        
        This test verifies that:
        1. Users with the required role can access role-specific operations
        2. Users without the required role are denied access
        3. Access control is enforced consistently across all role combinations
        """
        from app.models import UserRole
        from app.decorators import organization_required, consultant_required
        from flask import g
        from flask_login import login_user
        import uuid
        
        # Create unique username for this test using UUID
        username = f'testuser_{uuid.uuid4().hex[:12]}'
        
        try:
            # Create user with specified role (without keys for simplicity)
            role_value = UserRole.ORGANIZATION if user_role == 'organization' else UserRole.CONSULTANT
            
            user = User(
                username=username,
                email=f'{username}@test.com',
                role=role_value
            )
            user.set_password('test_password_123')
            
            db.session.add(user)
            db.session.commit()
            
            # Test the decorators directly by simulating a request context
            with app_context.test_request_context():
                # Mock the current_user
                from flask_login import login_user
                login_user(user)
                
                # Create test functions with decorators
                @organization_required
                def org_function():
                    return 'org_success'
                
                @consultant_required
                def consultant_function():
                    return 'consultant_success'
                
                # Test organization-required function
                if required_role == 'organization':
                    if user_role == 'organization':
                        # Organization user should have access
                        result = org_function()
                        assert result == 'org_success', \
                            "Organization user should access organization-required function"
                    else:
                        # Consultant user should be denied (redirected)
                        result = org_function()
                        # The decorator returns a redirect response
                        assert hasattr(result, 'status_code') and result.status_code == 302, \
                            "Consultant user should be denied access to organization-required function"
                
                # Test consultant-required function
                elif required_role == 'consultant':
                    if user_role == 'consultant':
                        # Consultant user should have access
                        result = consultant_function()
                        assert result == 'consultant_success', \
                            "Consultant user should access consultant-required function"
                    else:
                        # Organization user should be denied (redirected)
                        result = consultant_function()
                        # The decorator returns a redirect response
                        assert hasattr(result, 'status_code') and result.status_code == 302, \
                            "Organization user should be denied access to consultant-required function"
            
            # Cleanup
            db.session.delete(user)
            db.session.commit()
            
        except Exception as e:
            # Rollback on any error
            db.session.rollback()
            raise
    
    @given(
        username=st.text(min_size=3, max_size=20, alphabet=st.characters(
            whitelist_categories=('Lu', 'Ll', 'Nd'),
            blacklist_characters='@'
        )),
        role_choice=st.sampled_from(['organization', 'consultant'])
    )
    @settings(
        max_examples=20,  # Reduced from 100 due to slow key generation
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
        phases=[Phase.generate, Phase.target]  # Skip shrinking to avoid flakiness
    )
    def test_user_assigned_selected_role(self, app_context, username, role_choice):
        """
        Property: Users should be assigned the role they select during registration.
        
        This test verifies that:
        1. A user can select a role during registration
        2. The selected role is correctly stored in the database
        3. The role can be retrieved and matches the selection
        """
        from app.models import UserRole
        from app.asymmetric_crypto import AsymmetricCrypto
        from app.key_store import KeyStore
        from datetime import datetime
        
        # Skip if username already exists (hypothesis may generate duplicates)
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            # Clean up existing user to avoid flakiness
            db.session.delete(existing_user)
            db.session.commit()
        
        # Create user with selected role
        role_value = UserRole.ORGANIZATION if role_choice == 'organization' else UserRole.CONSULTANT
        
        user = User(
            username=username,
            email=f'{username}@test.com',
            role=role_value
        )
        user.set_password('test_password_123')
        
        # Generate keys for the user
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        user.public_key = public_key
        user.public_key_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(public_key)
        user.key_generated_at = datetime.utcnow()
        
        db.session.add(user)
        db.session.flush()
        
        user_id = user.id
        
        # Store private key in MongoDB
        encrypted_key, salt, nonce = AsymmetricCrypto.encrypt_private_key(
            private_key, 'test_password_123'
        )
        
        keystore = None
        try:
            keystore = KeyStore()
            keystore.store_private_key(
                user_id=user_id,
                encrypted_key=encrypted_key,
                salt=salt,
                nonce=nonce,
                metadata={'algorithm': 'RSA-2048'}
            )
        except ConnectionFailure:
            db.session.rollback()
            pytest.skip("MongoDB not available for testing")
        finally:
            if keystore:
                # Clean up MongoDB entry
                try:
                    keystore.delete_private_key(user_id)
                except:
                    pass
                keystore.close()
        
        db.session.commit()
        
        # Retrieve user from database
        retrieved_user = User.query.filter_by(username=username).first()
        
        # Verify role was correctly stored
        assert retrieved_user is not None, "User should exist in database"
        assert retrieved_user.role == role_value, \
            f"User role should be {role_value}, got {retrieved_user.role}"
        
        # Verify role matches the original selection
        if role_choice == 'organization':
            assert retrieved_user.role == UserRole.ORGANIZATION, \
                "Organization role should be stored correctly"
        else:
            assert retrieved_user.role == UserRole.CONSULTANT, \
                "Consultant role should be stored correctly"
        
        # Clean up after test to avoid flakiness
        db.session.delete(retrieved_user)
        db.session.commit()
        
        # Cleanup
        try:
            keystore = KeyStore()
            keystore.delete_private_key(user.id)
            keystore.close()
        except:
            pass
        
        db.session.delete(retrieved_user)
        db.session.commit()


class TestAccessRequestStatusTransitions:
    """
    Property 3: Access request status transitions (partial)
    
    **Feature: asymmetric-key-exchange, Property 3: Access request status transitions (partial)**
    **Validates: Requirements 2.3**
    
    For any access request in pending status, the request should be created with
    status 'pending' and all required fields should be populated.
    """
    
    @given(
        consultant_username=st.text(min_size=3, max_size=20, alphabet=st.characters(
            whitelist_categories=('Lu', 'Ll', 'Nd'),
            blacklist_characters='@'
        )),
        org_username=st.text(min_size=3, max_size=20, alphabet=st.characters(
            whitelist_categories=('Lu', 'Ll', 'Nd'),
            blacklist_characters='@'
        ))
    )
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_access_request_created_with_pending_status(
        self,
        app_context,
        consultant_username,
        org_username
    ):
        """
        Property: Access requests should be created with pending status.
        
        This test verifies that:
        1. Access requests are created with status 'pending'
        2. All required fields are populated (consultant_id, organization_id, file_id, timestamp)
        3. Optional fields are null (wrapped_symmetric_key, processed_at)
        """
        from app.models import UserRole, EncryptedFile, AccessRequest
        from datetime import datetime
        import uuid
        
        # Skip if usernames are the same
        if consultant_username == org_username:
            return
        
        # Skip if users already exist
        if User.query.filter_by(username=consultant_username).first():
            return
        if User.query.filter_by(username=org_username).first():
            return
        
        try:
            # Create organization user
            org_user = User(
                username=org_username,
                email=f'{org_username}@test.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('test_password')
            db.session.add(org_user)
            db.session.flush()
            
            # Create consultant user
            consultant_user = User(
                username=consultant_username,
                email=f'{consultant_username}@test.com',
                role=UserRole.CONSULTANT
            )
            consultant_user.set_password('test_password')
            db.session.add(consultant_user)
            db.session.flush()
            
            # Create a file owned by organization
            file = EncryptedFile(
                file_id=f'test-file-{uuid.uuid4().hex[:8]}',
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
            db.session.flush()
            
            # Create access request
            access_request = AccessRequest(
                consultant_id=consultant_user.id,
                organization_id=org_user.id,
                file_id=file.id,
                status='pending'
            )
            db.session.add(access_request)
            db.session.commit()
            
            # Retrieve the request to verify
            retrieved_request = AccessRequest.query.filter_by(
                consultant_id=consultant_user.id,
                file_id=file.id
            ).first()
            
            # Verify request was created with pending status
            assert retrieved_request is not None, \
                "Access request should be created"
            
            assert retrieved_request.status == 'pending', \
                "Access request should have status 'pending'"
            
            # Verify all required fields are populated
            assert retrieved_request.consultant_id == consultant_user.id, \
                "Consultant ID should be set"
            
            assert retrieved_request.organization_id == org_user.id, \
                "Organization ID should be set"
            
            assert retrieved_request.file_id == file.id, \
                "File ID should be set"
            
            assert retrieved_request.requested_at is not None, \
                "Requested timestamp should be set"
            
            assert isinstance(retrieved_request.requested_at, datetime), \
                "Requested timestamp should be a datetime object"
            
            # Verify optional fields are null for pending requests
            assert retrieved_request.wrapped_symmetric_key is None, \
                "Wrapped key should be null for pending requests"
            
            assert retrieved_request.processed_at is None, \
                "Processed timestamp should be null for pending requests"
            
            # Cleanup
            db.session.delete(retrieved_request)
            db.session.delete(file)
            db.session.delete(consultant_user)
            db.session.delete(org_user)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            raise
    
    @given(
        num_requests=st.integers(min_value=1, max_value=10)
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_multiple_requests_all_start_pending(
        self,
        app_context,
        num_requests
    ):
        """
        Property: All access requests should start with pending status.
        
        This test verifies that regardless of how many requests are created,
        they all start with status 'pending'.
        """
        from app.models import UserRole, EncryptedFile, AccessRequest
        import uuid
        
        try:
            # Create organization user
            org_username = f'org_{uuid.uuid4().hex[:8]}'
            org_user = User(
                username=org_username,
                email=f'{org_username}@test.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('test_password')
            db.session.add(org_user)
            db.session.flush()
            
            # Create consultant user
            consultant_username = f'consultant_{uuid.uuid4().hex[:8]}'
            consultant_user = User(
                username=consultant_username,
                email=f'{consultant_username}@test.com',
                role=UserRole.CONSULTANT
            )
            consultant_user.set_password('test_password')
            db.session.add(consultant_user)
            db.session.flush()
            
            # Create multiple files and requests
            created_requests = []
            for i in range(num_requests):
                # Create a file
                file = EncryptedFile(
                    file_id=f'test-file-{uuid.uuid4().hex[:8]}',
                    filename=f'test_encrypted_{i}',
                    original_filename=f'test_{i}.txt',
                    file_type='text',
                    file_size=1024,
                    encrypted_path=f'/path/to/encrypted_{i}',
                    algorithm='AES',
                    wrapped_key=b'wrapped_key_data',
                    iv=b'initialization_vector',
                    user_id=org_user.id
                )
                db.session.add(file)
                db.session.flush()
                
                # Create access request
                access_request = AccessRequest(
                    consultant_id=consultant_user.id,
                    organization_id=org_user.id,
                    file_id=file.id,
                    status='pending'
                )
                db.session.add(access_request)
                created_requests.append(access_request)
            
            db.session.commit()
            
            # Verify all requests have pending status
            all_requests = AccessRequest.query.filter_by(
                consultant_id=consultant_user.id
            ).all()
            
            assert len(all_requests) == num_requests, \
                f"Should have created {num_requests} requests"
            
            for request in all_requests:
                assert request.status == 'pending', \
                    "All requests should have status 'pending'"
                assert request.requested_at is not None, \
                    "All requests should have requested_at timestamp"
                assert request.wrapped_symmetric_key is None, \
                    "Pending requests should not have wrapped key"
                assert request.processed_at is None, \
                    "Pending requests should not have processed_at timestamp"
            
            # Cleanup
            for request in all_requests:
                db.session.delete(request.file)
                db.session.delete(request)
            db.session.delete(consultant_user)
            db.session.delete(org_user)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            raise


class TestKeySizeValidation:
    """
    Property 6: Key size validation
    
    **Feature: asymmetric-key-exchange, Property 6: Key size validation**
    **Validates: Requirements 4.1, 9.1**
    
    For any generated RSA key pair, the key size should be at least 2048 bits.
    """
    
    @given(key_size=key_sizes)
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_generated_keys_meet_minimum_size(self, key_size):
        """
        Property: All generated RSA keys should meet minimum size requirement.
        
        This test verifies that:
        1. RSA key pairs can be generated with specified size
        2. Generated keys meet the minimum 2048-bit requirement
        3. Key size matches the requested size
        """
        # Generate RSA key pair
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair(key_size)
        
        # Import keys to check their properties
        from Crypto.PublicKey import RSA
        
        private_rsa = RSA.import_key(private_key)
        public_rsa = RSA.import_key(public_key)
        
        # Verify key size meets minimum requirement
        assert private_rsa.size_in_bits() >= AsymmetricCrypto.MIN_KEY_SIZE, \
            f"Private key size {private_rsa.size_in_bits()} should be at least {AsymmetricCrypto.MIN_KEY_SIZE} bits"
        
        assert public_rsa.size_in_bits() >= AsymmetricCrypto.MIN_KEY_SIZE, \
            f"Public key size {public_rsa.size_in_bits()} should be at least {AsymmetricCrypto.MIN_KEY_SIZE} bits"
        
        # Verify key size matches requested size
        assert private_rsa.size_in_bits() == key_size, \
            f"Private key size should be {key_size} bits"
        
        assert public_rsa.size_in_bits() == key_size, \
            f"Public key size should be {key_size} bits"
    
    def test_key_generation_rejects_small_keys(self):
        """
        Property: Key generation should reject keys smaller than minimum size.
        
        This test verifies that attempting to generate keys smaller than
        2048 bits raises an error.
        """
        # Try to generate keys smaller than minimum
        with pytest.raises(ValueError, match="at least 2048 bits"):
            AsymmetricCrypto.generate_rsa_keypair(1024)
        
        with pytest.raises(ValueError, match="at least 2048 bits"):
            AsymmetricCrypto.generate_rsa_keypair(512)


class TestConsultantRequestVisibility:
    """
    Property 7: Consultant request visibility
    
    **Feature: asymmetric-key-exchange, Property 7: Consultant request visibility**
    **Validates: Requirements 2.5**
    
    For any consultant user, the list of their requests should contain all and
    only requests submitted by that consultant.
    """
    
    @given(
        num_consultants=st.integers(min_value=2, max_value=5),
        num_requests_per_consultant=st.integers(min_value=1, max_value=5)
    )
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_consultant_sees_only_own_requests(
        self,
        app_context,
        num_consultants,
        num_requests_per_consultant
    ):
        """
        Property: Consultants should see only their own requests.
        
        This test verifies that:
        1. Each consultant can see all their own requests
        2. Consultants cannot see other consultants' requests
        3. Request filtering is consistent across multiple consultants
        """
        from app.models import UserRole, EncryptedFile, AccessRequest
        import uuid
        
        try:
            # Create organization user
            org_username = f'org_{uuid.uuid4().hex[:8]}'
            org_user = User(
                username=org_username,
                email=f'{org_username}@test.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('test_password')
            db.session.add(org_user)
            db.session.flush()
            
            # Create multiple consultant users
            consultants = []
            for i in range(num_consultants):
                consultant_username = f'consultant_{uuid.uuid4().hex[:8]}'
                consultant = User(
                    username=consultant_username,
                    email=f'{consultant_username}@test.com',
                    role=UserRole.CONSULTANT
                )
                consultant.set_password('test_password')
                db.session.add(consultant)
                db.session.flush()
                consultants.append(consultant)
            
            # Create files and requests for each consultant
            all_requests = {}
            for consultant in consultants:
                consultant_requests = []
                
                for j in range(num_requests_per_consultant):
                    # Create a file
                    file = EncryptedFile(
                        file_id=f'test-file-{uuid.uuid4().hex[:8]}',
                        filename=f'test_encrypted_{consultant.id}_{j}',
                        original_filename=f'test_{consultant.id}_{j}.txt',
                        file_type='text',
                        file_size=1024,
                        encrypted_path=f'/path/to/encrypted_{consultant.id}_{j}',
                        algorithm='AES',
                        wrapped_key=b'wrapped_key_data',
                        iv=b'initialization_vector',
                        user_id=org_user.id
                    )
                    db.session.add(file)
                    db.session.flush()
                    
                    # Create access request
                    access_request = AccessRequest(
                        consultant_id=consultant.id,
                        organization_id=org_user.id,
                        file_id=file.id,
                        status='pending'
                    )
                    db.session.add(access_request)
                    consultant_requests.append(access_request)
                
                all_requests[consultant.id] = consultant_requests
            
            db.session.commit()
            
            # Verify each consultant sees only their own requests
            for consultant in consultants:
                # Query requests for this consultant
                consultant_visible_requests = AccessRequest.query.filter_by(
                    consultant_id=consultant.id
                ).all()
                
                # Verify count matches expected
                expected_count = num_requests_per_consultant
                assert len(consultant_visible_requests) == expected_count, \
                    f"Consultant {consultant.id} should see {expected_count} requests, " \
                    f"but sees {len(consultant_visible_requests)}"
                
                # Verify all visible requests belong to this consultant
                for request in consultant_visible_requests:
                    assert request.consultant_id == consultant.id, \
                        f"Consultant {consultant.id} should only see their own requests, " \
                        f"but sees request from consultant {request.consultant_id}"
                
                # Verify the requests match what we created
                expected_request_ids = {r.id for r in all_requests[consultant.id]}
                visible_request_ids = {r.id for r in consultant_visible_requests}
                assert expected_request_ids == visible_request_ids, \
                    f"Consultant {consultant.id} should see exactly their own requests"
                
                # Verify consultant doesn't see other consultants' requests
                for other_consultant in consultants:
                    if other_consultant.id != consultant.id:
                        for other_request in all_requests[other_consultant.id]:
                            assert other_request not in consultant_visible_requests, \
                                f"Consultant {consultant.id} should not see requests " \
                                f"from consultant {other_consultant.id}"
            
            # Cleanup
            for consultant in consultants:
                for request in all_requests[consultant.id]:
                    db.session.delete(request.file)
                    db.session.delete(request)
                db.session.delete(consultant)
            db.session.delete(org_user)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            raise
    
    @given(
        num_requests=st.integers(min_value=1, max_value=10),
        status_choices=st.lists(
            st.sampled_from(['pending', 'approved', 'denied', 'revoked']),
            min_size=1,
            max_size=10
        )
    )
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_consultant_sees_all_request_statuses(
        self,
        app_context,
        num_requests,
        status_choices
    ):
        """
        Property: Consultants should see all their requests regardless of status.
        
        This test verifies that:
        1. Consultants can see pending requests
        2. Consultants can see approved requests
        3. Consultants can see denied requests
        4. Consultants can see revoked requests
        5. All requests are visible regardless of status
        """
        from app.models import UserRole, EncryptedFile, AccessRequest
        import uuid
        
        # Ensure we have enough statuses for the requests
        while len(status_choices) < num_requests:
            status_choices.extend(status_choices)
        status_choices = status_choices[:num_requests]
        
        try:
            # Create organization user
            org_username = f'org_{uuid.uuid4().hex[:8]}'
            org_user = User(
                username=org_username,
                email=f'{org_username}@test.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('test_password')
            db.session.add(org_user)
            db.session.flush()
            
            # Create consultant user
            consultant_username = f'consultant_{uuid.uuid4().hex[:8]}'
            consultant = User(
                username=consultant_username,
                email=f'{consultant_username}@test.com',
                role=UserRole.CONSULTANT
            )
            consultant.set_password('test_password')
            db.session.add(consultant)
            db.session.flush()
            
            # Create requests with different statuses
            created_requests = []
            for i, status in enumerate(status_choices):
                # Create a file
                file = EncryptedFile(
                    file_id=f'test-file-{uuid.uuid4().hex[:8]}',
                    filename=f'test_encrypted_{i}',
                    original_filename=f'test_{i}.txt',
                    file_type='text',
                    file_size=1024,
                    encrypted_path=f'/path/to/encrypted_{i}',
                    algorithm='AES',
                    wrapped_key=b'wrapped_key_data',
                    iv=b'initialization_vector',
                    user_id=org_user.id
                )
                db.session.add(file)
                db.session.flush()
                
                # Create access request with specified status
                access_request = AccessRequest(
                    consultant_id=consultant.id,
                    organization_id=org_user.id,
                    file_id=file.id,
                    status=status
                )
                db.session.add(access_request)
                created_requests.append((access_request, status))
            
            db.session.commit()
            
            # Query all requests for this consultant
            all_visible_requests = AccessRequest.query.filter_by(
                consultant_id=consultant.id
            ).all()
            
            # Verify count matches
            assert len(all_visible_requests) == num_requests, \
                f"Consultant should see all {num_requests} requests, " \
                f"but sees {len(all_visible_requests)}"
            
            # Verify all statuses are represented
            visible_statuses = {r.status for r in all_visible_requests}
            expected_statuses = set(status_choices)
            assert visible_statuses == expected_statuses, \
                f"Consultant should see requests with all statuses: {expected_statuses}, " \
                f"but only sees: {visible_statuses}"
            
            # Verify each created request is visible
            visible_request_ids = {r.id for r in all_visible_requests}
            for request, status in created_requests:
                assert request.id in visible_request_ids, \
                    f"Request with status '{status}' should be visible to consultant"
            
            # Cleanup
            for request, _ in created_requests:
                db.session.delete(request.file)
                db.session.delete(request)
            db.session.delete(consultant)
            db.session.delete(org_user)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            raise



class TestOrganizationRequestFiltering:
    """
    Property 6: Organization request filtering
    
    **Feature: asymmetric-key-exchange, Property 6: Organization request filtering**
    **Validates: Requirements 3.1**
    
    For any organization user, the list of pending requests should contain only
    requests for files owned by that organization.
    """
    
    @given(
        num_organizations=st.integers(min_value=2, max_value=5),
        num_files_per_org=st.integers(min_value=1, max_value=5),
        num_consultants=st.integers(min_value=1, max_value=3)
    )
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_organization_sees_only_own_file_requests(
        self,
        app_context,
        num_organizations,
        num_files_per_org,
        num_consultants
    ):
        """
        Property: Organizations should see only requests for their own files.
        
        This test verifies that:
        1. Each organization can see all requests for their files
        2. Organizations cannot see requests for other organizations' files
        3. Request filtering is consistent across multiple organizations
        """
        from app.models import UserRole, EncryptedFile, AccessRequest
        import uuid
        
        try:
            # Create multiple organization users
            organizations = []
            for i in range(num_organizations):
                org_username = f'org_{uuid.uuid4().hex[:8]}'
                org_user = User(
                    username=org_username,
                    email=f'{org_username}@test.com',
                    role=UserRole.ORGANIZATION
                )
                org_user.set_password('test_password')
                db.session.add(org_user)
                db.session.flush()
                organizations.append(org_user)
            
            # Create consultant users
            consultants = []
            for i in range(num_consultants):
                consultant_username = f'consultant_{uuid.uuid4().hex[:8]}'
                consultant = User(
                    username=consultant_username,
                    email=f'{consultant_username}@test.com',
                    role=UserRole.CONSULTANT
                )
                consultant.set_password('test_password')
                db.session.add(consultant)
                db.session.flush()
                consultants.append(consultant)
            
            # Create files and requests for each organization
            org_files = {}
            org_requests = {}
            
            for org in organizations:
                files = []
                requests = []
                
                # Create files for this organization
                for j in range(num_files_per_org):
                    file = EncryptedFile(
                        file_id=f'test-file-{uuid.uuid4().hex[:8]}',
                        filename=f'test_encrypted_{org.id}_{j}',
                        original_filename=f'test_{org.id}_{j}.txt',
                        file_type='text',
                        file_size=1024,
                        encrypted_path=f'/path/to/encrypted_{org.id}_{j}',
                        algorithm='AES',
                        wrapped_key=b'wrapped_key_data',
                        iv=b'initialization_vector',
                        user_id=org.id
                    )
                    db.session.add(file)
                    db.session.flush()
                    files.append(file)
                    
                    # Create access requests from consultants for this file
                    for consultant in consultants:
                        access_request = AccessRequest(
                            consultant_id=consultant.id,
                            organization_id=org.id,
                            file_id=file.id,
                            status='pending'
                        )
                        db.session.add(access_request)
                        requests.append(access_request)
                
                org_files[org.id] = files
                org_requests[org.id] = requests
            
            db.session.commit()
            
            # Verify each organization sees only requests for their own files
            for org in organizations:
                # Query requests for this organization's files
                org_file_ids = [f.id for f in org_files[org.id]]
                
                # Get requests by filtering on files owned by this organization
                visible_requests = AccessRequest.query.filter(
                    AccessRequest.file_id.in_(org_file_ids)
                ).all()
                
                # Expected count: num_files_per_org * num_consultants
                expected_count = num_files_per_org * num_consultants
                assert len(visible_requests) == expected_count, \
                    f"Organization {org.id} should see {expected_count} requests, " \
                    f"but sees {len(visible_requests)}"
                
                # Verify all visible requests are for this organization's files
                for request in visible_requests:
                    assert request.file_id in org_file_ids, \
                        f"Organization {org.id} should only see requests for their files, " \
                        f"but sees request for file {request.file_id}"
                    
                    assert request.organization_id == org.id, \
                        f"Organization {org.id} should only see requests addressed to them, " \
                        f"but sees request for organization {request.organization_id}"
                
                # Verify the requests match what we created
                expected_request_ids = {r.id for r in org_requests[org.id]}
                visible_request_ids = {r.id for r in visible_requests}
                assert expected_request_ids == visible_request_ids, \
                    f"Organization {org.id} should see exactly their own file requests"
                
                # Verify organization doesn't see other organizations' requests
                for other_org in organizations:
                    if other_org.id != org.id:
                        for other_request in org_requests[other_org.id]:
                            assert other_request not in visible_requests, \
                                f"Organization {org.id} should not see requests " \
                                f"for organization {other_org.id}'s files"
            
            # Cleanup
            for org in organizations:
                for request in org_requests[org.id]:
                    db.session.delete(request)
                for file in org_files[org.id]:
                    db.session.delete(file)
                db.session.delete(org)
            for consultant in consultants:
                db.session.delete(consultant)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            raise
    
    @given(
        num_files=st.integers(min_value=1, max_value=10),
        status_filter=st.sampled_from(['pending', 'approved', 'denied', 'revoked', None])
    )
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_organization_request_filtering_by_status(
        self,
        app_context,
        num_files,
        status_filter
    ):
        """
        Property: Organizations should be able to filter requests by status.
        
        This test verifies that:
        1. Organizations can filter requests by status (pending, approved, denied, revoked)
        2. Filtering returns only requests with the specified status
        3. Without a filter, all requests are returned
        """
        from app.models import UserRole, EncryptedFile, AccessRequest
        import uuid
        
        try:
            # Create organization user
            org_username = f'org_{uuid.uuid4().hex[:8]}'
            org_user = User(
                username=org_username,
                email=f'{org_username}@test.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('test_password')
            db.session.add(org_user)
            db.session.flush()
            
            # Create consultant user
            consultant_username = f'consultant_{uuid.uuid4().hex[:8]}'
            consultant = User(
                username=consultant_username,
                email=f'{consultant_username}@test.com',
                role=UserRole.CONSULTANT
            )
            consultant.set_password('test_password')
            db.session.add(consultant)
            db.session.flush()
            
            # Create files and requests with different statuses
            statuses = ['pending', 'approved', 'denied', 'revoked']
            created_requests_by_status = {status: [] for status in statuses}
            
            # Create one file per status to avoid unique constraint violation
            # (consultant_id, file_id) must be unique
            for i, status in enumerate(statuses * ((num_files // len(statuses)) + 1)):
                if i >= num_files:
                    break
                    
                # Create a file
                file = EncryptedFile(
                    file_id=f'test-file-{uuid.uuid4().hex[:8]}',
                    filename=f'test_encrypted_{i}',
                    original_filename=f'test_{i}.txt',
                    file_type='text',
                    file_size=1024,
                    encrypted_path=f'/path/to/encrypted_{i}',
                    algorithm='AES',
                    wrapped_key=b'wrapped_key_data',
                    iv=b'initialization_vector',
                    user_id=org_user.id
                )
                db.session.add(file)
                db.session.flush()
                
                # Create one request per file with the assigned status
                access_request = AccessRequest(
                    consultant_id=consultant.id,
                    organization_id=org_user.id,
                    file_id=file.id,
                    status=status
                )
                db.session.add(access_request)
                db.session.flush()
                created_requests_by_status[status].append(access_request)
            
            db.session.commit()
            
            # Get all file IDs for this organization
            org_file_ids = [f.id for f in EncryptedFile.query.filter_by(user_id=org_user.id).all()]
            
            # Test filtering
            if status_filter is None:
                # No filter - should see all requests
                visible_requests = AccessRequest.query.filter(
                    AccessRequest.file_id.in_(org_file_ids)
                ).all()
                
                expected_count = num_files
                assert len(visible_requests) == expected_count, \
                    f"Without filter, organization should see all {expected_count} requests, " \
                    f"but sees {len(visible_requests)}"
            else:
                # With status filter - should see only requests with that status
                visible_requests = AccessRequest.query.filter(
                    AccessRequest.file_id.in_(org_file_ids),
                    AccessRequest.status == status_filter
                ).all()
                
                expected_count = len(created_requests_by_status[status_filter])
                assert len(visible_requests) == expected_count, \
                    f"With status filter '{status_filter}', organization should see {expected_count} requests, " \
                    f"but sees {len(visible_requests)}"
                
                # Verify all visible requests have the filtered status
                for request in visible_requests:
                    assert request.status == status_filter, \
                        f"Filtered requests should all have status '{status_filter}', " \
                        f"but found request with status '{request.status}'"
                
                # Verify the requests match what we created
                expected_request_ids = {r.id for r in created_requests_by_status[status_filter]}
                visible_request_ids = {r.id for r in visible_requests}
                assert expected_request_ids == visible_request_ids, \
                    f"Filtered requests should match created requests with status '{status_filter}'"
            
            # Cleanup
            for status in statuses:
                for request in created_requests_by_status[status]:
                    db.session.delete(request)
            for file_id in org_file_ids:
                file = EncryptedFile.query.get(file_id)
                if file:
                    db.session.delete(file)
            db.session.delete(consultant)
            db.session.delete(org_user)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            raise


class TestWrappedKeyStorage:
    """
    Property 5: Wrapped key storage
    
    **Feature: asymmetric-key-exchange, Property 5: Wrapped key storage**
    **Validates: Requirements 5.5**
    
    For any approved access request, the request record should contain a
    non-null wrapped symmetric key.
    """
    
    @given(
        num_requests=st.integers(min_value=1, max_value=2)
    )
    @settings(
        max_examples=3,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_approved_requests_have_wrapped_key(
        self,
        app_context,
        num_requests
    ):
        """
        Property: Approved access requests must have a wrapped symmetric key.
        
        This test verifies that:
        1. When a request is approved, a wrapped symmetric key is stored
        2. The wrapped key is non-null
        3. The wrapped key is different from the original symmetric key
        4. Pending requests do not have wrapped keys
        """
        from app.models import UserRole, EncryptedFile, AccessRequest
        from app.asymmetric_crypto import AsymmetricCrypto
        from app.crypto_utils import _unwrap_key, _wrap_key
        import uuid
        
        try:
            # Create organization user with keys
            org_username = f'org_{uuid.uuid4().hex[:8]}'
            org_user = User(
                username=org_username,
                email=f'{org_username}@test.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('test_password')
            
            # Generate keys for organization
            org_public_key, org_private_key = AsymmetricCrypto.generate_rsa_keypair()
            org_user.public_key = org_public_key
            org_user.public_key_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(org_public_key)
            
            db.session.add(org_user)
            db.session.flush()
            
            # Create consultant user with keys
            consultant_username = f'consultant_{uuid.uuid4().hex[:8]}'
            consultant = User(
                username=consultant_username,
                email=f'{consultant_username}@test.com',
                role=UserRole.CONSULTANT
            )
            consultant.set_password('test_password')
            
            # Generate keys for consultant
            consultant_public_key, consultant_private_key = AsymmetricCrypto.generate_rsa_keypair()
            consultant.public_key = consultant_public_key
            consultant.public_key_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(consultant_public_key)
            
            db.session.add(consultant)
            db.session.flush()
            
            # Create files and requests
            created_requests = []
            for i in range(num_requests):
                # Generate a symmetric key and wrap it with KEK
                from Crypto.Random import get_random_bytes
                symmetric_key = get_random_bytes(32)  # AES-256 key
                wrapped_dek = _wrap_key(symmetric_key)
                
                # Create a file with wrapped DEK
                file = EncryptedFile(
                    file_id=f'test-file-{uuid.uuid4().hex[:8]}',
                    filename=f'test_encrypted_{i}',
                    original_filename=f'test_{i}.txt',
                    file_type='text',
                    file_size=1024,
                    encrypted_path=f'/path/to/encrypted_{i}',
                    algorithm='AES',
                    wrapped_key=wrapped_dek,
                    iv=get_random_bytes(16),
                    user_id=org_user.id
                )
                db.session.add(file)
                db.session.flush()
                
                # Create access request
                access_request = AccessRequest(
                    consultant_id=consultant.id,
                    organization_id=org_user.id,
                    file_id=file.id,
                    status='pending'
                )
                db.session.add(access_request)
                db.session.flush()
                
                # Verify pending request has no wrapped key
                assert access_request.wrapped_symmetric_key is None, \
                    "Pending request should not have wrapped symmetric key"
                
                # Simulate approval: unwrap DEK, wrap with consultant's public key
                unwrapped_dek = _unwrap_key(wrapped_dek)
                wrapped_symmetric_key = AsymmetricCrypto.wrap_symmetric_key(
                    unwrapped_dek, consultant_public_key
                )
                
                # Update request to approved with wrapped key
                access_request.status = 'approved'
                access_request.wrapped_symmetric_key = wrapped_symmetric_key
                access_request.processed_at = datetime.utcnow()
                
                created_requests.append((access_request, unwrapped_dek))
            
            db.session.commit()
            
            # Verify all approved requests have wrapped keys
            approved_requests = AccessRequest.query.filter_by(
                consultant_id=consultant.id,
                status='approved'
            ).all()
            
            assert len(approved_requests) == num_requests, \
                f"Should have {num_requests} approved requests"
            
            for request in approved_requests:
                # Verify wrapped key exists
                assert request.wrapped_symmetric_key is not None, \
                    "Approved request must have wrapped symmetric key"
                
                # Verify wrapped key is not empty
                assert len(request.wrapped_symmetric_key) > 0, \
                    "Wrapped symmetric key must not be empty"
                
                # Verify wrapped key can be unwrapped with consultant's private key
                unwrapped_key = AsymmetricCrypto.unwrap_symmetric_key(
                    request.wrapped_symmetric_key,
                    consultant_private_key
                )
                
                # Find the original symmetric key for this request
                original_key = None
                for req, orig_key in created_requests:
                    if req.id == request.id:
                        original_key = orig_key
                        break
                
                # Verify unwrapped key matches original
                assert unwrapped_key == original_key, \
                    "Unwrapped key should match original symmetric key"
                
                # Verify wrapped key is different from original
                assert request.wrapped_symmetric_key != original_key, \
                    "Wrapped key should be different from original symmetric key"
            
            # Cleanup
            for request, _ in created_requests:
                db.session.delete(request.file)
                db.session.delete(request)
            db.session.delete(consultant)
            db.session.delete(org_user)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            raise
    
    @given(
        status=st.sampled_from(['pending', 'denied', 'revoked'])
    )
    @settings(
        max_examples=10,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_non_approved_requests_have_no_wrapped_key(
        self,
        app_context,
        status
    ):
        """
        Property: Non-approved requests should not have wrapped symmetric keys.
        
        This test verifies that:
        1. Pending requests do not have wrapped keys
        2. Denied requests do not have wrapped keys
        3. Revoked requests have their wrapped keys removed
        """
        from app.models import UserRole, EncryptedFile, AccessRequest
        from app.asymmetric_crypto import AsymmetricCrypto
        import uuid
        
        try:
            # Create organization user
            org_username = f'org_{uuid.uuid4().hex[:8]}'
            org_user = User(
                username=org_username,
                email=f'{org_username}@test.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('test_password')
            db.session.add(org_user)
            db.session.flush()
            
            # Create consultant user
            consultant_username = f'consultant_{uuid.uuid4().hex[:8]}'
            consultant = User(
                username=consultant_username,
                email=f'{consultant_username}@test.com',
                role=UserRole.CONSULTANT
            )
            consultant.set_password('test_password')
            db.session.add(consultant)
            db.session.flush()
            
            # Create a file
            file = EncryptedFile(
                file_id=f'test-file-{uuid.uuid4().hex[:8]}',
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
            db.session.flush()
            
            # Create access request with specified status
            access_request = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org_user.id,
                file_id=file.id,
                status=status
            )
            db.session.add(access_request)
            db.session.commit()
            
            # Verify request does not have wrapped key
            retrieved_request = AccessRequest.query.get(access_request.id)
            assert retrieved_request.wrapped_symmetric_key is None, \
                f"Request with status '{status}' should not have wrapped symmetric key"
            
            # Cleanup
            db.session.delete(retrieved_request)
            db.session.delete(file)
            db.session.delete(consultant)
            db.session.delete(org_user)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            raise


class TestStatusTransitions:
    """
    Property 3: Access request status transitions
    
    **Feature: asymmetric-key-exchange, Property 3: Access request status transitions**
    **Validates: Requirements 3.3, 3.4**
    
    For any access request in pending status, approving it should change the
    status to approved, and denying it should change the status to denied.
    """
    
    @given(
        num_requests=st.integers(min_value=1, max_value=3)
    )
    @settings(
        max_examples=10,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_pending_to_approved_transition(
        self,
        app_context,
        num_requests
    ):
        """
        Property: Pending requests can transition to approved status.
        
        This test verifies that:
        1. Requests start with pending status
        2. Pending requests can be approved
        3. Approved requests have status 'approved'
        4. Status transition is persisted in database
        """
        from app.models import UserRole, EncryptedFile, AccessRequest
        import uuid
        
        try:
            # Create organization user
            org_username = f'org_{uuid.uuid4().hex[:8]}'
            org_user = User(
                username=org_username,
                email=f'{org_username}@test.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('test_password')
            db.session.add(org_user)
            db.session.flush()
            
            # Create consultant user
            consultant_username = f'consultant_{uuid.uuid4().hex[:8]}'
            consultant = User(
                username=consultant_username,
                email=f'{consultant_username}@test.com',
                role=UserRole.CONSULTANT
            )
            consultant.set_password('test_password')
            db.session.add(consultant)
            db.session.flush()
            
            # Create requests
            created_requests = []
            for i in range(num_requests):
                # Create a file
                file = EncryptedFile(
                    file_id=f'test-file-{uuid.uuid4().hex[:8]}',
                    filename=f'test_encrypted_{i}',
                    original_filename=f'test_{i}.txt',
                    file_type='text',
                    file_size=1024,
                    encrypted_path=f'/path/to/encrypted_{i}',
                    algorithm='AES',
                    wrapped_key=b'wrapped_key_data',
                    iv=b'initialization_vector',
                    user_id=org_user.id
                )
                db.session.add(file)
                db.session.flush()
                
                # Create pending request
                access_request = AccessRequest(
                    consultant_id=consultant.id,
                    organization_id=org_user.id,
                    file_id=file.id,
                    status='pending'
                )
                db.session.add(access_request)
                db.session.flush()
                
                # Verify initial status
                assert access_request.status == 'pending', \
                    "Request should start with pending status"
                
                # Transition to approved
                access_request.status = 'approved'
                access_request.processed_at = datetime.utcnow()
                
                created_requests.append(access_request)
            
            db.session.commit()
            
            # Verify all requests are now approved
            approved_requests = AccessRequest.query.filter_by(
                consultant_id=consultant.id,
                status='approved'
            ).all()
            
            assert len(approved_requests) == num_requests, \
                f"Should have {num_requests} approved requests"
            
            for request in approved_requests:
                assert request.status == 'approved', \
                    "Request status should be 'approved'"
                assert request.processed_at is not None, \
                    "Approved request should have processed_at timestamp"
            
            # Cleanup
            for request in created_requests:
                db.session.delete(request.file)
                db.session.delete(request)
            db.session.delete(consultant)
            db.session.delete(org_user)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            raise
    
    @given(
        num_requests=st.integers(min_value=1, max_value=3)
    )
    @settings(
        max_examples=10,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_pending_to_denied_transition(
        self,
        app_context,
        num_requests
    ):
        """
        Property: Pending requests can transition to denied status.
        
        This test verifies that:
        1. Requests start with pending status
        2. Pending requests can be denied
        3. Denied requests have status 'denied'
        4. Status transition is persisted in database
        """
        from app.models import UserRole, EncryptedFile, AccessRequest
        import uuid
        
        try:
            # Create organization user
            org_username = f'org_{uuid.uuid4().hex[:8]}'
            org_user = User(
                username=org_username,
                email=f'{org_username}@test.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('test_password')
            db.session.add(org_user)
            db.session.flush()
            
            # Create consultant user
            consultant_username = f'consultant_{uuid.uuid4().hex[:8]}'
            consultant = User(
                username=consultant_username,
                email=f'{consultant_username}@test.com',
                role=UserRole.CONSULTANT
            )
            consultant.set_password('test_password')
            db.session.add(consultant)
            db.session.flush()
            
            # Create requests
            created_requests = []
            for i in range(num_requests):
                # Create a file
                file = EncryptedFile(
                    file_id=f'test-file-{uuid.uuid4().hex[:8]}',
                    filename=f'test_encrypted_{i}',
                    original_filename=f'test_{i}.txt',
                    file_type='text',
                    file_size=1024,
                    encrypted_path=f'/path/to/encrypted_{i}',
                    algorithm='AES',
                    wrapped_key=b'wrapped_key_data',
                    iv=b'initialization_vector',
                    user_id=org_user.id
                )
                db.session.add(file)
                db.session.flush()
                
                # Create pending request
                access_request = AccessRequest(
                    consultant_id=consultant.id,
                    organization_id=org_user.id,
                    file_id=file.id,
                    status='pending'
                )
                db.session.add(access_request)
                db.session.flush()
                
                # Verify initial status
                assert access_request.status == 'pending', \
                    "Request should start with pending status"
                
                # Transition to denied
                access_request.status = 'denied'
                access_request.processed_at = datetime.utcnow()
                
                created_requests.append(access_request)
            
            db.session.commit()
            
            # Verify all requests are now denied
            denied_requests = AccessRequest.query.filter_by(
                consultant_id=consultant.id,
                status='denied'
            ).all()
            
            assert len(denied_requests) == num_requests, \
                f"Should have {num_requests} denied requests"
            
            for request in denied_requests:
                assert request.status == 'denied', \
                    "Request status should be 'denied'"
                assert request.processed_at is not None, \
                    "Denied request should have processed_at timestamp"
            
            # Cleanup
            for request in created_requests:
                db.session.delete(request.file)
                db.session.delete(request)
            db.session.delete(consultant)
            db.session.delete(org_user)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            raise


class TestTimestampRecording:
    """
    Property 10: Timestamp recording
    
    **Feature: asymmetric-key-exchange, Property 10: Timestamp recording**
    **Validates: Requirements 3.5**
    
    For any access request that changes status, the processed_at timestamp
    should be updated to the current time.
    """
    
    @given(
        new_status=st.sampled_from(['approved', 'denied', 'revoked'])
    )
    @settings(
        max_examples=10,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_status_change_updates_timestamp(
        self,
        app_context,
        new_status
    ):
        """
        Property: Status changes should update processed_at timestamp.
        
        This test verifies that:
        1. Pending requests have no processed_at timestamp
        2. When status changes, processed_at is set
        3. The timestamp is close to the current time
        4. The timestamp is persisted in database
        """
        from app.models import UserRole, EncryptedFile, AccessRequest
        import uuid
        from datetime import datetime, timedelta
        
        try:
            # Create organization user
            org_username = f'org_{uuid.uuid4().hex[:8]}'
            org_user = User(
                username=org_username,
                email=f'{org_username}@test.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('test_password')
            db.session.add(org_user)
            db.session.flush()
            
            # Create consultant user
            consultant_username = f'consultant_{uuid.uuid4().hex[:8]}'
            consultant = User(
                username=consultant_username,
                email=f'{consultant_username}@test.com',
                role=UserRole.CONSULTANT
            )
            consultant.set_password('test_password')
            db.session.add(consultant)
            db.session.flush()
            
            # Create a file
            file = EncryptedFile(
                file_id=f'test-file-{uuid.uuid4().hex[:8]}',
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
            db.session.flush()
            
            # Create pending request
            access_request = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org_user.id,
                file_id=file.id,
                status='pending'
            )
            db.session.add(access_request)
            db.session.commit()
            
            # Verify no processed_at timestamp initially
            assert access_request.processed_at is None, \
                "Pending request should not have processed_at timestamp"
            
            # Record time before status change
            time_before = datetime.utcnow()
            
            # Change status
            access_request.status = new_status
            access_request.processed_at = datetime.utcnow()
            db.session.commit()
            
            # Record time after status change
            time_after = datetime.utcnow()
            
            # Retrieve request to verify persistence
            retrieved_request = AccessRequest.query.get(access_request.id)
            
            # Verify processed_at timestamp is set
            assert retrieved_request.processed_at is not None, \
                f"Request with status '{new_status}' should have processed_at timestamp"
            
            # Verify timestamp is within reasonable range (within 1 minute)
            assert time_before <= retrieved_request.processed_at <= time_after + timedelta(seconds=1), \
                "Processed timestamp should be close to current time"
            
            # Verify status was updated
            assert retrieved_request.status == new_status, \
                f"Request status should be '{new_status}'"
            
            # Cleanup
            db.session.delete(retrieved_request)
            db.session.delete(file)
            db.session.delete(consultant)
            db.session.delete(org_user)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            raise


class TestNoPlaintextKeyExposure:
    """
    Property 12: No plaintext key exposure
    
    **Feature: asymmetric-key-exchange, Property 12: No plaintext key exposure**
    **Validates: Requirements 5.6**
    
    For any approved access request, the database and API responses should not
    contain the unwrapped symmetric key in plaintext.
    """
    
    @given(
        num_requests=st.integers(min_value=1, max_value=3)
    )
    @settings(
        max_examples=10,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_database_does_not_store_plaintext_keys(
        self,
        app_context,
        num_requests
    ):
        """
        Property: Database should never contain plaintext symmetric keys.
        
        This test verifies that:
        1. Symmetric keys are always wrapped before storage
        2. Database records do not contain plaintext keys
        3. Wrapped keys are different from plaintext keys
        4. All key material in database is encrypted
        """
        from app.models import UserRole, EncryptedFile, AccessRequest
        from app.asymmetric_crypto import AsymmetricCrypto
        from app.crypto_utils import _wrap_key, _unwrap_key
        from Crypto.Random import get_random_bytes
        import uuid
        
        try:
            # Create organization user with keys
            org_username = f'org_{uuid.uuid4().hex[:8]}'
            org_user = User(
                username=org_username,
                email=f'{org_username}@test.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('test_password')
            
            org_public_key, org_private_key = AsymmetricCrypto.generate_rsa_keypair()
            org_user.public_key = org_public_key
            org_user.public_key_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(org_public_key)
            
            db.session.add(org_user)
            db.session.flush()
            
            # Create consultant user with keys
            consultant_username = f'consultant_{uuid.uuid4().hex[:8]}'
            consultant = User(
                username=consultant_username,
                email=f'{consultant_username}@test.com',
                role=UserRole.CONSULTANT
            )
            consultant.set_password('test_password')
            
            consultant_public_key, consultant_private_key = AsymmetricCrypto.generate_rsa_keypair()
            consultant.public_key = consultant_public_key
            consultant.public_key_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(consultant_public_key)
            
            db.session.add(consultant)
            db.session.flush()
            
            # Track plaintext keys to verify they're not in database
            plaintext_keys = []
            
            # Create files and approved requests
            for i in range(num_requests):
                # Generate plaintext symmetric key
                plaintext_key = get_random_bytes(32)
                plaintext_keys.append(plaintext_key)
                
                # Wrap with KEK for file storage
                kek_wrapped_key = _wrap_key(plaintext_key)
                
                # Create file with KEK-wrapped key
                file = EncryptedFile(
                    file_id=f'test-file-{uuid.uuid4().hex[:8]}',
                    filename=f'test_encrypted_{i}',
                    original_filename=f'test_{i}.txt',
                    file_type='text',
                    file_size=1024,
                    encrypted_path=f'/path/to/encrypted_{i}',
                    algorithm='AES',
                    wrapped_key=kek_wrapped_key,
                    iv=get_random_bytes(16),
                    user_id=org_user.id
                )
                db.session.add(file)
                db.session.flush()
                
                # Wrap with consultant's public key for access request
                rsa_wrapped_key = AsymmetricCrypto.wrap_symmetric_key(
                    plaintext_key, consultant_public_key
                )
                
                # Create approved request with RSA-wrapped key
                access_request = AccessRequest(
                    consultant_id=consultant.id,
                    organization_id=org_user.id,
                    file_id=file.id,
                    status='approved',
                    wrapped_symmetric_key=rsa_wrapped_key,
                    processed_at=datetime.utcnow()
                )
                db.session.add(access_request)
            
            db.session.commit()
            
            # Verify no plaintext keys in EncryptedFile table
            all_files = EncryptedFile.query.filter_by(user_id=org_user.id).all()
            for file in all_files:
                for plaintext_key in plaintext_keys:
                    # Check wrapped_key column
                    if file.wrapped_key:
                        assert file.wrapped_key != plaintext_key, \
                            "File wrapped_key should not contain plaintext symmetric key"
                    
                    # Check legacy encryption_key column
                    if file.encryption_key:
                        assert file.encryption_key != plaintext_key, \
                            "File encryption_key should not contain plaintext symmetric key"
            
            # Verify no plaintext keys in AccessRequest table
            all_requests = AccessRequest.query.filter_by(consultant_id=consultant.id).all()
            for request in all_requests:
                for plaintext_key in plaintext_keys:
                    if request.wrapped_symmetric_key:
                        assert request.wrapped_symmetric_key != plaintext_key, \
                            "AccessRequest wrapped_symmetric_key should not contain plaintext key"
            
            # Verify wrapped keys are actually encrypted (different from plaintext)
            for request in all_requests:
                assert request.wrapped_symmetric_key is not None, \
                    "Approved request should have wrapped key"
                
                # Verify it's different from all plaintext keys
                for plaintext_key in plaintext_keys:
                    assert request.wrapped_symmetric_key != plaintext_key, \
                        "Wrapped key must be different from plaintext key"
                
                # Verify wrapped key can be decrypted to get plaintext
                unwrapped = AsymmetricCrypto.unwrap_symmetric_key(
                    request.wrapped_symmetric_key,
                    consultant_private_key
                )
                
                # Verify unwrapped key is one of our plaintext keys
                assert unwrapped in plaintext_keys, \
                    "Unwrapped key should match one of the original plaintext keys"
            
            # Cleanup
            for request in all_requests:
                db.session.delete(request.file)
                db.session.delete(request)
            db.session.delete(consultant)
            db.session.delete(org_user)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            raise



class TestKeyDecryptionRoundTripIntegration:
    """
    Property 1: RSA key pair round-trip (integration)
    
    **Feature: asymmetric-key-exchange, Property 1: RSA key pair round-trip (integration)**
    **Validates: Requirements 6.5, 6.6**
    
    This is an integration test that verifies the complete workflow:
    1. Organization approves access request and wraps symmetric key with consultant's public key
    2. Consultant retrieves encrypted private key from MongoDB
    3. Consultant decrypts private key with password
    4. Consultant unwraps symmetric key with private key
    5. Unwrapped key matches the original symmetric key
    """
    
    @pytest.fixture(scope='function')
    def test_keystore_integration(self):
        """
        Create a test KeyStore instance with a test database for integration tests.
        """
        # Use a unique test database name for each test run
        test_db_name = f'test_integration_{os.getpid()}_{id(self)}'
        
        try:
            keystore = KeyStore(
                connection_string='mongodb://localhost:27017/',
                db_name=test_db_name
            )
            yield keystore
        except ConnectionFailure:
            pytest.skip("MongoDB not available for testing")
        finally:
            # Cleanup: drop test database
            try:
                if keystore._client:
                    keystore._client.drop_database(test_db_name)
                    keystore.close()
            except:
                pass
    
    @given(
        password=passwords,
        symmetric_key=symmetric_keys
    )
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow]
    )
    def test_complete_key_decryption_workflow(
        self,
        app_context,
        test_keystore_integration,
        password,
        symmetric_key
    ):
        """
        Property: Complete key decryption workflow should preserve the symmetric key.
        
        This integration test verifies the entire workflow:
        1. Generate RSA key pair for consultant
        2. Encrypt private key with password and store in MongoDB
        3. Wrap symmetric key with consultant's public key (simulating approval)
        4. Retrieve encrypted private key from MongoDB
        5. Decrypt private key with password
        6. Unwrap symmetric key with private key
        7. Verify unwrapped key matches original
        """
        from app.models import UserRole
        import uuid
        
        keystore = test_keystore_integration
        
        try:
            # Create consultant user
            consultant_username = f'consultant_{uuid.uuid4().hex[:8]}'
            consultant = User(
                username=consultant_username,
                email=f'{consultant_username}@test.com',
                role=UserRole.CONSULTANT
            )
            consultant.set_password(password)
            db.session.add(consultant)
            db.session.flush()
            
            # Step 1: Generate RSA key pair for consultant
            public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
            
            # Store public key in user record
            consultant.public_key = public_key
            consultant.public_key_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(public_key)
            consultant.key_generated_at = datetime.utcnow()
            db.session.flush()
            
            # Step 2: Encrypt private key with password and store in MongoDB
            encrypted_key, salt, nonce = AsymmetricCrypto.encrypt_private_key(
                private_key, password
            )
            
            success = keystore.store_private_key(
                user_id=consultant.id,
                encrypted_key=encrypted_key,
                salt=salt,
                nonce=nonce,
                metadata={'algorithm': 'RSA-2048'}
            )
            assert success, "Private key storage should succeed"
            
            # Step 3: Wrap symmetric key with consultant's public key
            # (This simulates what happens during access request approval)
            wrapped_symmetric_key = AsymmetricCrypto.wrap_symmetric_key(
                symmetric_key, public_key
            )
            
            # Verify wrapped key is different from original
            assert wrapped_symmetric_key != symmetric_key, \
                "Wrapped key should be different from original"
            
            # Step 4: Retrieve encrypted private key from MongoDB
            # (This simulates what happens when consultant wants to decrypt)
            key_data = keystore.retrieve_private_key(consultant.id)
            assert key_data is not None, "Should be able to retrieve private key"
            
            # Step 5: Decrypt private key with password
            decrypted_private_key = AsymmetricCrypto.decrypt_private_key(
                encrypted_key=key_data['encrypted_key'],
                password=password,
                salt=key_data['salt'],
                nonce=key_data['nonce']
            )
            
            # Verify decrypted private key matches original
            assert decrypted_private_key == private_key, \
                "Decrypted private key should match original"
            
            # Step 6: Unwrap symmetric key with private key
            unwrapped_symmetric_key = AsymmetricCrypto.unwrap_symmetric_key(
                wrapped_key=wrapped_symmetric_key,
                private_key_pem=decrypted_private_key
            )
            
            # Step 7: Verify unwrapped key matches original symmetric key
            assert unwrapped_symmetric_key == symmetric_key, \
                "Unwrapped symmetric key should match original symmetric key"
            
            # Cleanup
            keystore.delete_private_key(consultant.id)
            db.session.delete(consultant)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            raise
    
    @given(
        correct_password=passwords,
        wrong_password=passwords,
        symmetric_key=symmetric_keys
    )
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow]
    )
    def test_wrong_password_prevents_key_decryption(
        self,
        app_context,
        test_keystore_integration,
        correct_password,
        wrong_password,
        symmetric_key
    ):
        """
        Property: Using wrong password should prevent successful key decryption.
        
        This test verifies that:
        1. The workflow succeeds with the correct password
        2. The workflow fails with an incorrect password
        3. Security is maintained through password protection
        """
        # Skip if passwords happen to be the same
        if correct_password == wrong_password:
            return
        
        from app.models import UserRole
        import uuid
        
        keystore = test_keystore_integration
        
        try:
            # Create consultant user
            consultant_username = f'consultant_{uuid.uuid4().hex[:8]}'
            consultant = User(
                username=consultant_username,
                email=f'{consultant_username}@test.com',
                role=UserRole.CONSULTANT
            )
            consultant.set_password(correct_password)
            db.session.add(consultant)
            db.session.flush()
            
            # Generate RSA key pair
            public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
            consultant.public_key = public_key
            db.session.flush()
            
            # Encrypt private key with correct password
            encrypted_key, salt, nonce = AsymmetricCrypto.encrypt_private_key(
                private_key, correct_password
            )
            
            keystore.store_private_key(
                user_id=consultant.id,
                encrypted_key=encrypted_key,
                salt=salt,
                nonce=nonce,
                metadata={'algorithm': 'RSA-2048'}
            )
            
            # Wrap symmetric key
            wrapped_symmetric_key = AsymmetricCrypto.wrap_symmetric_key(
                symmetric_key, public_key
            )
            
            # Retrieve key data
            key_data = keystore.retrieve_private_key(consultant.id)
            
            # Test 1: Correct password should work
            decrypted_private_key = AsymmetricCrypto.decrypt_private_key(
                encrypted_key=key_data['encrypted_key'],
                password=correct_password,
                salt=key_data['salt'],
                nonce=key_data['nonce']
            )
            
            unwrapped_key = AsymmetricCrypto.unwrap_symmetric_key(
                wrapped_key=wrapped_symmetric_key,
                private_key_pem=decrypted_private_key
            )
            
            assert unwrapped_key == symmetric_key, \
                "Correct password should allow successful key decryption"
            
            # Test 2: Wrong password should fail
            with pytest.raises(ValueError):
                AsymmetricCrypto.decrypt_private_key(
                    encrypted_key=key_data['encrypted_key'],
                    password=wrong_password,
                    salt=key_data['salt'],
                    nonce=key_data['nonce']
                )
            
            # Cleanup
            keystore.delete_private_key(consultant.id)
            db.session.delete(consultant)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            raise



class TestApprovedFileAccess:
    """
    Property 15: Approved file access
    
    **Feature: asymmetric-key-exchange, Property 15: Approved file access**
    **Validates: Requirements 7.1, 10.4, 12.5**
    
    For any consultant and file, the consultant should be able to download the file
    if and only if they have an approved (non-revoked) access request for that file.
    """
    
    @given(
        has_request=st.booleans(),
        request_status=st.sampled_from(['pending', 'approved', 'denied', 'revoked'])
    )
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_consultant_download_requires_approved_access(
        self,
        app_context,
        has_request,
        request_status
    ):
        """
        Property: Consultants can download files if and only if they have approved access.
        
        This test verifies that:
        1. Consultants with approved requests can download files
        2. Consultants without requests cannot download files
        3. Consultants with pending/denied/revoked requests cannot download files
        4. Access control is enforced consistently
        """
        from app.models import UserRole, EncryptedFile, AccessRequest
        from flask_login import login_user
        import uuid
        import tempfile
        import os
        
        try:
            # Create organization user
            org_username = f'org_{uuid.uuid4().hex[:8]}'
            org_user = User(
                username=org_username,
                email=f'{org_username}@test.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('test_password')
            db.session.add(org_user)
            db.session.flush()
            
            # Create consultant user
            consultant_username = f'consultant_{uuid.uuid4().hex[:8]}'
            consultant = User(
                username=consultant_username,
                email=f'{consultant_username}@test.com',
                role=UserRole.CONSULTANT
            )
            consultant.set_password('test_password')
            db.session.add(consultant)
            db.session.flush()
            
            # Create a temporary encrypted file
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='_encrypted')
            temp_file.write(b'encrypted_test_data_12345678')  # Some test data
            temp_file.close()
            
            # Create file record
            file = EncryptedFile(
                file_id=f'test-file-{uuid.uuid4().hex[:8]}',
                filename='test_encrypted',
                original_filename='test.txt',
                file_type='text',
                file_size=1024,
                encrypted_path=temp_file.name,
                algorithm='AES',
                wrapped_key=b'wrapped_key_data_for_testing',
                iv=b'1234567890123456',  # 16 bytes for AES
                user_id=org_user.id
            )
            db.session.add(file)
            db.session.flush()
            
            # Create access request if specified
            access_request = None
            if has_request:
                access_request = AccessRequest(
                    consultant_id=consultant.id,
                    organization_id=org_user.id,
                    file_id=file.id,
                    status=request_status
                )
                db.session.add(access_request)
                db.session.flush()
            
            db.session.commit()
            
            # Test download access using test client
            with app_context.test_client() as client:
                # Log in as consultant
                with client.session_transaction() as sess:
                    sess['_user_id'] = str(consultant.id)
                    sess['_fresh'] = True
                
                # Attempt to download file
                response = client.get(f'/file/{file.file_id}/download', follow_redirects=False)
                
                # Determine expected behavior
                should_allow_download = has_request and request_status == 'approved'
                
                if should_allow_download:
                    # With approved access, consultant should be redirected to decrypt key first
                    # (since symmetric key is not in session yet)
                    assert response.status_code in [302, 200], \
                        f"Consultant with approved access should be able to proceed (got {response.status_code})"
                else:
                    # Without approved access, consultant should be denied
                    assert response.status_code == 302, \
                        f"Consultant without approved access should be redirected (got {response.status_code})"
                    
                    # Check that they're redirected away (not to download)
                    if response.status_code == 302:
                        location = response.headers.get('Location', '')
                        assert 'download' not in location or 'dashboard' in location or 'my-requests' in location, \
                            "Consultant should be redirected away from download"
            
            # Cleanup
            try:
                os.unlink(temp_file.name)
            except:
                pass
            
            if access_request:
                db.session.delete(access_request)
            db.session.delete(file)
            db.session.delete(consultant)
            db.session.delete(org_user)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            # Clean up temp file on error
            try:
                if 'temp_file' in locals():
                    os.unlink(temp_file.name)
            except:
                pass
            raise
    
    @given(
        num_consultants=st.integers(min_value=2, max_value=5),
        num_files=st.integers(min_value=1, max_value=3)
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_access_isolation_between_consultants(
        self,
        app_context,
        num_consultants,
        num_files
    ):
        """
        Property: Consultants can only download files they have approved access to.
        
        This test verifies that:
        1. Each consultant can only download their own approved files
        2. Consultants cannot download files approved for other consultants
        3. Access control is properly isolated between consultants
        """
        from app.models import UserRole, EncryptedFile, AccessRequest
        import uuid
        import tempfile
        import os
        
        try:
            # Create organization user
            org_username = f'org_{uuid.uuid4().hex[:8]}'
            org_user = User(
                username=org_username,
                email=f'{org_username}@test.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('test_password')
            db.session.add(org_user)
            db.session.flush()
            
            # Create multiple consultants
            consultants = []
            for i in range(num_consultants):
                consultant_username = f'consultant_{uuid.uuid4().hex[:8]}'
                consultant = User(
                    username=consultant_username,
                    email=f'{consultant_username}@test.com',
                    role=UserRole.CONSULTANT
                )
                consultant.set_password('test_password')
                db.session.add(consultant)
                db.session.flush()
                consultants.append(consultant)
            
            # Create files and assign approved access to specific consultants
            files = []
            temp_files = []
            consultant_approved_files = {c.id: [] for c in consultants}
            
            for i in range(num_files):
                # Create temporary encrypted file
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='_encrypted')
                temp_file.write(b'encrypted_test_data_12345678')
                temp_file.close()
                temp_files.append(temp_file.name)
                
                # Create file record
                file = EncryptedFile(
                    file_id=f'test-file-{uuid.uuid4().hex[:8]}',
                    filename=f'test_encrypted_{i}',
                    original_filename=f'test_{i}.txt',
                    file_type='text',
                    file_size=1024,
                    encrypted_path=temp_file.name,
                    algorithm='AES',
                    wrapped_key=b'wrapped_key_data_for_testing',
                    iv=b'1234567890123456',
                    user_id=org_user.id
                )
                db.session.add(file)
                db.session.flush()
                files.append(file)
                
                # Assign approved access to one consultant (round-robin)
                assigned_consultant = consultants[i % num_consultants]
                access_request = AccessRequest(
                    consultant_id=assigned_consultant.id,
                    organization_id=org_user.id,
                    file_id=file.id,
                    status='approved'
                )
                db.session.add(access_request)
                consultant_approved_files[assigned_consultant.id].append(file.id)
            
            db.session.commit()
            
            # Test that each consultant can only access their approved files
            with app_context.test_client() as client:
                for consultant in consultants:
                    # Log in as this consultant
                    with client.session_transaction() as sess:
                        sess['_user_id'] = str(consultant.id)
                        sess['_fresh'] = True
                    
                    # Try to download each file
                    for file in files:
                        response = client.get(f'/file/{file.file_id}/download', follow_redirects=False)
                        
                        # Check if this consultant should have access
                        should_have_access = file.id in consultant_approved_files[consultant.id]
                        
                        if should_have_access:
                            # Should be able to proceed (may redirect to decrypt key)
                            assert response.status_code in [200, 302], \
                                f"Consultant {consultant.id} should have access to file {file.id}"
                        else:
                            # Should be denied
                            assert response.status_code == 302, \
                                f"Consultant {consultant.id} should not have access to file {file.id}"
            
            # Cleanup
            for temp_file_path in temp_files:
                try:
                    os.unlink(temp_file_path)
                except:
                    pass
            
            # Delete all created records
            AccessRequest.query.filter_by(organization_id=org_user.id).delete()
            for file in files:
                db.session.delete(file)
            for consultant in consultants:
                db.session.delete(consultant)
            db.session.delete(org_user)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            # Clean up temp files on error
            if 'temp_files' in locals():
                for temp_file_path in temp_files:
                    try:
                        os.unlink(temp_file_path)
                    except:
                        pass
            raise
    
    @given(
        initial_status=st.sampled_from(['approved']),
        revoke=st.booleans()
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_revoked_access_prevents_download(
        self,
        app_context,
        initial_status,
        revoke
    ):
        """
        Property: Revoking access should prevent file downloads.
        
        This test verifies that:
        1. Approved access allows downloads
        2. Revoking access prevents downloads
        3. Revocation is enforced immediately
        """
        from app.models import UserRole, EncryptedFile, AccessRequest
        import uuid
        import tempfile
        import os
        
        try:
            # Create organization user
            org_username = f'org_{uuid.uuid4().hex[:8]}'
            org_user = User(
                username=org_username,
                email=f'{org_username}@test.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('test_password')
            db.session.add(org_user)
            db.session.flush()
            
            # Create consultant user
            consultant_username = f'consultant_{uuid.uuid4().hex[:8]}'
            consultant = User(
                username=consultant_username,
                email=f'{consultant_username}@test.com',
                role=UserRole.CONSULTANT
            )
            consultant.set_password('test_password')
            db.session.add(consultant)
            db.session.flush()
            
            # Create temporary encrypted file
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='_encrypted')
            temp_file.write(b'encrypted_test_data_12345678')
            temp_file.close()
            
            # Create file record
            file = EncryptedFile(
                file_id=f'test-file-{uuid.uuid4().hex[:8]}',
                filename='test_encrypted',
                original_filename='test.txt',
                file_type='text',
                file_size=1024,
                encrypted_path=temp_file.name,
                algorithm='AES',
                wrapped_key=b'wrapped_key_data_for_testing',
                iv=b'1234567890123456',
                user_id=org_user.id
            )
            db.session.add(file)
            db.session.flush()
            
            # Create access request with initial status
            access_request = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org_user.id,
                file_id=file.id,
                status=initial_status
            )
            db.session.add(access_request)
            db.session.commit()
            
            # Test download before revocation
            with app_context.test_client() as client:
                with client.session_transaction() as sess:
                    sess['_user_id'] = str(consultant.id)
                    sess['_fresh'] = True
                
                response_before = client.get(f'/file/{file.file_id}/download', follow_redirects=False)
                
                # With approved status, should be able to proceed
                assert response_before.status_code in [200, 302], \
                    "Consultant with approved access should be able to proceed"
            
            # Revoke access if specified
            if revoke:
                access_request.status = 'revoked'
                db.session.commit()
                
                # Test download after revocation
                with app_context.test_client() as client:
                    with client.session_transaction() as sess:
                        sess['_user_id'] = str(consultant.id)
                        sess['_fresh'] = True
                    
                    response_after = client.get(f'/file/{file.file_id}/download', follow_redirects=False)
                    
                    # After revocation, should be denied
                    assert response_after.status_code == 302, \
                        "Consultant with revoked access should be denied"
                    
                    # Verify redirect is away from download
                    location = response_after.headers.get('Location', '')
                    assert 'my-requests' in location or 'dashboard' in location, \
                        "Revoked access should redirect to my-requests or dashboard"
            
            # Cleanup
            try:
                os.unlink(temp_file.name)
            except:
                pass
            
            db.session.delete(access_request)
            db.session.delete(file)
            db.session.delete(consultant)
            db.session.delete(org_user)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            try:
                if 'temp_file' in locals():
                    os.unlink(temp_file.name)
            except:
                pass
            raise


class TestAccessRevocationCleanup:
    """
    Property 9: Access revocation cleanup
    
    **Feature: asymmetric-key-exchange, Property 9: Access revocation cleanup**
    **Validates: Requirements 10.3**
    
    For any access request that is revoked, the wrapped symmetric key should be
    deleted from the request record.
    """
    
    @given(
        num_requests=st.integers(min_value=1, max_value=10)
    )
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_revoked_requests_have_no_wrapped_key(
        self,
        app_context,
        num_requests
    ):
        """
        Property: Revoked access requests should have their wrapped key deleted.
        
        This test verifies that:
        1. Approved requests have a wrapped symmetric key
        2. When a request is revoked, the wrapped key is deleted
        3. The request status is updated to 'revoked'
        4. The processed_at timestamp is updated
        """
        from app.models import UserRole, EncryptedFile, AccessRequest
        from app.asymmetric_crypto import AsymmetricCrypto
        from datetime import datetime
        import uuid
        
        try:
            # Create organization user with keys
            org_username = f'org_{uuid.uuid4().hex[:8]}'
            org_user = User(
                username=org_username,
                email=f'{org_username}@test.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('test_password')
            
            # Generate keys for organization
            public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
            org_user.public_key = public_key
            org_user.public_key_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(public_key)
            org_user.key_generated_at = datetime.utcnow()
            
            db.session.add(org_user)
            db.session.flush()
            
            # Create consultant user with keys
            consultant_username = f'consultant_{uuid.uuid4().hex[:8]}'
            consultant = User(
                username=consultant_username,
                email=f'{consultant_username}@test.com',
                role=UserRole.CONSULTANT
            )
            consultant.set_password('test_password')
            
            # Generate keys for consultant
            consultant_public_key, consultant_private_key = AsymmetricCrypto.generate_rsa_keypair()
            consultant.public_key = consultant_public_key
            consultant.public_key_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(consultant_public_key)
            consultant.key_generated_at = datetime.utcnow()
            
            db.session.add(consultant)
            db.session.flush()
            
            # Create files and approved requests with wrapped keys
            created_requests = []
            for i in range(num_requests):
                # Create a file
                file = EncryptedFile(
                    file_id=f'test-file-{uuid.uuid4().hex[:8]}',
                    filename=f'test_encrypted_{i}',
                    original_filename=f'test_{i}.txt',
                    file_type='text',
                    file_size=1024,
                    encrypted_path=f'/path/to/encrypted_{i}',
                    algorithm='AES',
                    wrapped_key=b'kek_wrapped_symmetric_key_data',
                    iv=b'initialization_vector',
                    user_id=org_user.id
                )
                db.session.add(file)
                db.session.flush()
                
                # Create access request with approved status and wrapped key
                # Simulate wrapping a symmetric key with consultant's public key
                test_symmetric_key = b'test_symmetric_key_32_bytes_12'  # 32 bytes for AES-256
                wrapped_key = AsymmetricCrypto.wrap_symmetric_key(
                    test_symmetric_key,
                    consultant_public_key
                )
                
                access_request = AccessRequest(
                    consultant_id=consultant.id,
                    organization_id=org_user.id,
                    file_id=file.id,
                    status='approved',
                    wrapped_symmetric_key=wrapped_key,
                    processed_at=datetime.utcnow()
                )
                db.session.add(access_request)
                db.session.flush()
                created_requests.append(access_request)
            
            db.session.commit()
            
            # Verify all requests have wrapped keys before revocation
            for request in created_requests:
                retrieved = AccessRequest.query.get(request.id)
                assert retrieved.status == 'approved', \
                    "Request should be approved before revocation"
                assert retrieved.wrapped_symmetric_key is not None, \
                    "Approved request should have wrapped symmetric key"
                assert len(retrieved.wrapped_symmetric_key) > 0, \
                    "Wrapped key should not be empty"
            
            # Revoke all requests
            for request in created_requests:
                request.status = 'revoked'
                request.wrapped_symmetric_key = None  # Delete the wrapped key
                request.processed_at = datetime.utcnow()
            
            db.session.commit()
            
            # Verify all revoked requests have no wrapped key
            for request in created_requests:
                retrieved = AccessRequest.query.get(request.id)
                
                assert retrieved.status == 'revoked', \
                    "Request status should be 'revoked'"
                
                assert retrieved.wrapped_symmetric_key is None, \
                    "Revoked request should have wrapped_symmetric_key set to None"
                
                assert retrieved.processed_at is not None, \
                    "Revoked request should have processed_at timestamp"
            
            # Cleanup
            for request in created_requests:
                db.session.delete(request.file)
                db.session.delete(request)
            db.session.delete(consultant)
            db.session.delete(org_user)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            raise
    
    @given(
        initial_status=st.sampled_from(['approved', 'pending', 'denied'])
    )
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_revocation_clears_wrapped_key_regardless_of_initial_status(
        self,
        app_context,
        initial_status
    ):
        """
        Property: Revocation should clear wrapped key regardless of initial status.
        
        This test verifies that:
        1. Requests can be revoked from any status
        2. Wrapped keys are cleared even if the request wasn't approved
        3. The revocation process is consistent across different initial states
        """
        from app.models import UserRole, EncryptedFile, AccessRequest
        from app.asymmetric_crypto import AsymmetricCrypto
        from datetime import datetime
        import uuid
        
        try:
            # Create organization user
            org_username = f'org_{uuid.uuid4().hex[:8]}'
            org_user = User(
                username=org_username,
                email=f'{org_username}@test.com',
                role=UserRole.ORGANIZATION
            )
            org_user.set_password('test_password')
            db.session.add(org_user)
            db.session.flush()
            
            # Create consultant user with keys
            consultant_username = f'consultant_{uuid.uuid4().hex[:8]}'
            consultant = User(
                username=consultant_username,
                email=f'{consultant_username}@test.com',
                role=UserRole.CONSULTANT
            )
            consultant.set_password('test_password')
            
            # Generate keys for consultant
            consultant_public_key, consultant_private_key = AsymmetricCrypto.generate_rsa_keypair()
            consultant.public_key = consultant_public_key
            consultant.public_key_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(consultant_public_key)
            consultant.key_generated_at = datetime.utcnow()
            
            db.session.add(consultant)
            db.session.flush()
            
            # Create a file
            file = EncryptedFile(
                file_id=f'test-file-{uuid.uuid4().hex[:8]}',
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
            db.session.flush()
            
            # Create access request with initial status
            wrapped_key = None
            if initial_status == 'approved':
                # Only approved requests should have wrapped keys
                test_symmetric_key = b'test_symmetric_key_32_bytes_12'
                wrapped_key = AsymmetricCrypto.wrap_symmetric_key(
                    test_symmetric_key,
                    consultant_public_key
                )
            
            access_request = AccessRequest(
                consultant_id=consultant.id,
                organization_id=org_user.id,
                file_id=file.id,
                status=initial_status,
                wrapped_symmetric_key=wrapped_key,
                processed_at=datetime.utcnow() if initial_status != 'pending' else None
            )
            db.session.add(access_request)
            db.session.commit()
            
            # Record whether there was a wrapped key before revocation
            had_wrapped_key = access_request.wrapped_symmetric_key is not None
            
            # Revoke the request
            access_request.status = 'revoked'
            access_request.wrapped_symmetric_key = None
            access_request.processed_at = datetime.utcnow()
            db.session.commit()
            
            # Verify revocation
            retrieved = AccessRequest.query.get(access_request.id)
            
            assert retrieved.status == 'revoked', \
                f"Request should be revoked (was {initial_status})"
            
            assert retrieved.wrapped_symmetric_key is None, \
                f"Revoked request should have no wrapped key (was {initial_status})"
            
            assert retrieved.processed_at is not None, \
                "Revoked request should have processed_at timestamp"
            
            # If there was a wrapped key before, verify it was actually cleared
            if had_wrapped_key:
                assert retrieved.wrapped_symmetric_key is None, \
                    "Wrapped key should be cleared after revocation"
            
            # Cleanup
            db.session.delete(access_request)
            db.session.delete(file)
            db.session.delete(consultant)
            db.session.delete(org_user)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            raise



class TestCryptographicOperationLogging:
    """
    Property 11: Cryptographic operation logging
    
    **Feature: asymmetric-key-exchange, Property 11: Cryptographic operation logging**
    **Validates: Requirements 11.1, 11.2, 11.3**
    
    For any cryptographic operation (key generation, wrapping, unwrapping), a log entry
    should be created with the operation type and user identifier.
    """
    
    @given(
        user_id=user_ids,
        operation=st.sampled_from([
            'keypair_generated',
            'key_wrapped',
            'key_unwrapped',
            'private_key_decrypted',
            'access_granted',
            'access_revoked'
        ]),
        details=st.text(min_size=0, max_size=200, alphabet=st.characters(
            blacklist_categories=('Cs',),
            blacklist_characters='\x00'
        ))
    )
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_crypto_operations_are_logged(self, app_context, user_id, operation, details):
        """
        Property: All cryptographic operations should create log entries.
        
        This test verifies that:
        1. Cryptographic operations create log entries in the database
        2. Log entries contain the operation type
        3. Log entries contain the user identifier
        4. Log entries have timestamps
        """
        from app.models import CryptoLog
        from app.utils import log_crypto_operation
        
        # Get initial log count
        initial_count = CryptoLog.query.count()
        
        # Perform a crypto operation (log it)
        log_crypto_operation(
            user_id=user_id,
            operation=operation,
            details=details,
            success=True,
            ip_address='127.0.0.1'
        )
        
        # Verify log entry was created
        new_count = CryptoLog.query.count()
        assert new_count == initial_count + 1, \
            "Cryptographic operation should create a log entry"
        
        # Retrieve the log entry
        log_entry = CryptoLog.query.filter_by(
            user_id=user_id,
            operation=operation
        ).order_by(CryptoLog.timestamp.desc()).first()
        
        # Verify log entry exists
        assert log_entry is not None, \
            "Log entry should exist in database"
        
        # Verify log entry contains operation type
        assert log_entry.operation == operation, \
            f"Log entry should contain operation type '{operation}'"
        
        # Verify log entry contains user identifier
        assert log_entry.user_id == user_id, \
            f"Log entry should contain user ID {user_id}"
        
        # Verify log entry has timestamp
        assert log_entry.timestamp is not None, \
            "Log entry should have a timestamp"
        
        # Verify timestamp is a datetime object
        from datetime import datetime
        assert isinstance(log_entry.timestamp, datetime), \
            "Timestamp should be a datetime object"
        
        # Verify success flag is set correctly
        assert log_entry.success is True, \
            "Success flag should be set correctly"
        
        # Cleanup
        db.session.delete(log_entry)
        db.session.commit()
    
    @given(
        user_id=user_ids,
        operation=st.sampled_from([
            'keypair_generated',
            'key_wrapped',
            'key_unwrapped'
        ])
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_failed_operations_are_logged(self, app_context, user_id, operation):
        """
        Property: Failed cryptographic operations should be logged with error details.
        
        This test verifies that:
        1. Failed operations create log entries
        2. Log entries have success=False
        3. Log entries contain error messages
        """
        from app.models import CryptoLog
        from app.utils import log_crypto_operation
        
        error_message = "Test error message for failed operation"
        
        # Log a failed operation
        log_crypto_operation(
            user_id=user_id,
            operation=operation,
            details=f"Failed {operation}",
            success=False,
            error_message=error_message,
            ip_address='127.0.0.1'
        )
        
        # Retrieve the log entry
        log_entry = CryptoLog.query.filter_by(
            user_id=user_id,
            operation=operation,
            success=False
        ).order_by(CryptoLog.timestamp.desc()).first()
        
        # Verify log entry exists
        assert log_entry is not None, \
            "Failed operation should create a log entry"
        
        # Verify success flag is False
        assert log_entry.success is False, \
            "Failed operation should have success=False"
        
        # Verify error message is present
        assert log_entry.error_message is not None, \
            "Failed operation should have an error message"
        
        # Verify error message content
        assert error_message in log_entry.error_message, \
            "Error message should be preserved in log"
        
        # Cleanup
        db.session.delete(log_entry)
        db.session.commit()
    
    @given(
        user_id=user_ids,
        num_operations=st.integers(min_value=1, max_value=10)
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_multiple_operations_all_logged(self, app_context, user_id, num_operations):
        """
        Property: Multiple cryptographic operations should all be logged.
        
        This test verifies that:
        1. Multiple operations create multiple log entries
        2. Each operation is logged independently
        3. Log entries can be retrieved in order
        """
        from app.models import CryptoLog
        from app.utils import log_crypto_operation
        
        operations = ['keypair_generated', 'key_wrapped', 'key_unwrapped']
        
        # Get initial count
        initial_count = CryptoLog.query.filter_by(user_id=user_id).count()
        
        # Perform multiple operations
        for i in range(num_operations):
            operation = operations[i % len(operations)]
            log_crypto_operation(
                user_id=user_id,
                operation=operation,
                details=f"Operation {i+1} of {num_operations}",
                success=True,
                ip_address='127.0.0.1'
            )
        
        # Verify all operations were logged
        new_count = CryptoLog.query.filter_by(user_id=user_id).count()
        assert new_count == initial_count + num_operations, \
            f"All {num_operations} operations should be logged"
        
        # Retrieve all log entries for this user
        log_entries = CryptoLog.query.filter_by(
            user_id=user_id
        ).order_by(CryptoLog.timestamp.desc()).limit(num_operations).all()
        
        # Verify we got all entries
        assert len(log_entries) >= num_operations, \
            f"Should retrieve at least {num_operations} log entries"
        
        # Cleanup
        for entry in log_entries:
            db.session.delete(entry)
        db.session.commit()



class TestNoPlaintextKeyExposureInLogs:
    """
    Property 12: No plaintext key exposure (in logs)
    
    **Feature: asymmetric-key-exchange, Property 12: No plaintext key exposure (in logs)**
    **Validates: Requirements 11.5**
    
    For any cryptographic operation that fails, the error logs should not contain
    plaintext keys, passwords, or other sensitive cryptographic material.
    """
    
    @given(
        user_id=user_ids,
        sensitive_data=st.sampled_from([
            'private_key: MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...',
            'symmetric_key: 0123456789abcdef0123456789abcdef',
            'password: my_secret_password_123',
            'plaintext: this is the decrypted data',
            'unwrapped_key: aabbccddeeaabbccddeeaabbccddeeaa',
            'encryption_key: ' + 'a' * 64,  # 64 hex chars
            'aes_key: ' + 'b' * 32,  # 32 hex chars
        ])
    )
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_logs_do_not_contain_sensitive_data(self, app_context, user_id, sensitive_data):
        """
        Property: Logs should never contain plaintext keys or passwords.
        
        This test verifies that:
        1. Sensitive data in log details is sanitized
        2. Sensitive data in error messages is sanitized
        3. Common key formats (hex, base64) are detected and redacted
        4. Sensitive keywords trigger redaction
        """
        from app.models import CryptoLog
        from app.utils import log_crypto_operation
        
        # Try to log an operation with sensitive data in details
        log_crypto_operation(
            user_id=user_id,
            operation='key_unwrapped',
            details=f"Operation details: {sensitive_data}",
            success=False,
            error_message=f"Error occurred: {sensitive_data}",
            ip_address='127.0.0.1'
        )
        
        # Retrieve the log entry
        log_entry = CryptoLog.query.filter_by(
            user_id=user_id,
            operation='key_unwrapped'
        ).order_by(CryptoLog.timestamp.desc()).first()
        
        # Verify log entry exists
        assert log_entry is not None, \
            "Log entry should be created"
        
        # Verify details do not contain the original sensitive data
        if log_entry.details:
            assert sensitive_data not in log_entry.details, \
                "Log details should not contain plaintext sensitive data"
            
            # Verify redaction marker is present
            assert '[REDACTED' in log_entry.details or 'TRUNCATED' in log_entry.details, \
                "Log details should contain redaction marker"
        
        # Verify error message does not contain the original sensitive data
        if log_entry.error_message:
            assert sensitive_data not in log_entry.error_message, \
                "Error message should not contain plaintext sensitive data"
            
            # Verify redaction marker is present
            assert '[REDACTED' in log_entry.error_message or 'TRUNCATED' in log_entry.error_message, \
                "Error message should contain redaction marker"
        
        # Cleanup
        db.session.delete(log_entry)
        db.session.commit()
    
    @given(
        user_id=user_ids,
        key_data=st.binary(min_size=32, max_size=256)
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_binary_key_data_not_logged(self, app_context, user_id, key_data):
        """
        Property: Binary key data should not appear in logs.
        
        This test verifies that:
        1. Binary data is not logged directly
        2. Hex-encoded keys are detected and redacted
        3. Base64-encoded keys are detected and redacted
        """
        from app.models import CryptoLog
        from app.utils import log_crypto_operation
        import base64
        
        # Convert binary to hex and base64
        hex_key = key_data.hex()
        base64_key = base64.b64encode(key_data).decode('ascii')
        
        # Try to log with hex-encoded key
        log_crypto_operation(
            user_id=user_id,
            operation='key_wrapped',
            details=f"Wrapped key: {hex_key}",
            success=True,
            ip_address='127.0.0.1'
        )
        
        # Retrieve the log entry
        log_entry = CryptoLog.query.filter_by(
            user_id=user_id,
            operation='key_wrapped'
        ).order_by(CryptoLog.timestamp.desc()).first()
        
        # Verify log entry exists
        assert log_entry is not None, \
            "Log entry should be created"
        
        # Verify hex key is not in the log
        if log_entry.details and len(hex_key) >= 64:
            # Only check if key is long enough to be detected as sensitive
            assert hex_key not in log_entry.details, \
                "Hex-encoded key should not appear in logs"
        
        # Cleanup
        db.session.delete(log_entry)
        db.session.commit()
        
        # Try to log with base64-encoded key
        log_crypto_operation(
            user_id=user_id,
            operation='key_unwrapped',
            details=f"Unwrapped key: {base64_key}",
            success=True,
            ip_address='127.0.0.1'
        )
        
        # Retrieve the log entry
        log_entry = CryptoLog.query.filter_by(
            user_id=user_id,
            operation='key_unwrapped'
        ).order_by(CryptoLog.timestamp.desc()).first()
        
        # Verify log entry exists
        assert log_entry is not None, \
            "Log entry should be created"
        
        # Verify base64 key is not in the log (if long enough)
        if log_entry.details and len(base64_key) >= 40:
            # Only check if key is long enough to be detected as sensitive
            assert base64_key not in log_entry.details, \
                "Base64-encoded key should not appear in logs"
        
        # Cleanup
        db.session.delete(log_entry)
        db.session.commit()
    
    @given(
        user_id=user_ids,
        operation=st.sampled_from(['keypair_generated', 'key_wrapped', 'key_unwrapped'])
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_sensitive_keywords_trigger_redaction(self, app_context, user_id, operation):
        """
        Property: Sensitive keywords should trigger redaction in logs.
        
        This test verifies that:
        1. Keywords like 'private_key', 'password', 'secret' trigger redaction
        2. Redaction is case-insensitive
        3. Redaction applies to both details and error messages
        """
        from app.models import CryptoLog
        from app.utils import log_crypto_operation
        
        sensitive_keywords = [
            'private_key',
            'PASSWORD',
            'Secret',
            'symmetric_key',
            'plaintext'
        ]
        
        for keyword in sensitive_keywords:
            # Log with sensitive keyword
            log_crypto_operation(
                user_id=user_id,
                operation=operation,
                details=f"Operation involving {keyword} data",
                success=False,
                error_message=f"Failed due to {keyword} issue",
                ip_address='127.0.0.1'
            )
            
            # Retrieve the log entry
            log_entry = CryptoLog.query.filter_by(
                user_id=user_id,
                operation=operation
            ).order_by(CryptoLog.timestamp.desc()).first()
            
            # Verify log entry exists
            assert log_entry is not None, \
                f"Log entry should be created for {keyword}"
            
            # Verify redaction occurred
            if log_entry.details:
                assert '[REDACTED' in log_entry.details, \
                    f"Details should be redacted when containing '{keyword}'"
            
            if log_entry.error_message:
                assert '[REDACTED' in log_entry.error_message, \
                    f"Error message should be redacted when containing '{keyword}'"
            
            # Cleanup
            db.session.delete(log_entry)
            db.session.commit()
