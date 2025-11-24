"""
Unit Tests for Asymmetric Cryptography Module

This module contains unit tests for the AsymmetricCrypto class,
testing specific examples and edge cases.
"""

import pytest
from Crypto.PublicKey import RSA
from app.asymmetric_crypto import AsymmetricCrypto


class TestRSAKeyGeneration:
    """Unit tests for RSA key pair generation."""
    
    def test_generate_keypair_produces_valid_keys(self):
        """Test that RSA key generation produces valid keys."""
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        
        # Verify both keys are bytes
        assert isinstance(public_key, bytes)
        assert isinstance(private_key, bytes)
        
        # Verify keys can be imported
        public_rsa = RSA.import_key(public_key)
        private_rsa = RSA.import_key(private_key)
        
        # Verify private key has private components
        assert private_rsa.has_private()
        
        # Verify public key doesn't have private components
        assert not public_rsa.has_private()
        
        # Verify keys are in PEM format
        assert public_key.startswith(b'-----BEGIN PUBLIC KEY-----')
        assert private_key.startswith(b'-----BEGIN RSA PRIVATE KEY-----')
    
    def test_generate_keypair_default_size(self):
        """Test that default key size is 2048 bits."""
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        
        private_rsa = RSA.import_key(private_key)
        assert private_rsa.size_in_bits() == 2048
    
    def test_generate_keypair_custom_size(self):
        """Test that custom key sizes work correctly."""
        for key_size in [2048, 3072, 4096]:
            public_key, private_key = AsymmetricCrypto.generate_rsa_keypair(key_size)
            
            private_rsa = RSA.import_key(private_key)
            assert private_rsa.size_in_bits() == key_size
    
    def test_generate_keypair_rejects_small_keys(self):
        """Test that key generation rejects keys smaller than 2048 bits."""
        with pytest.raises(ValueError, match="at least 2048 bits"):
            AsymmetricCrypto.generate_rsa_keypair(1024)
        
        with pytest.raises(ValueError, match="at least 2048 bits"):
            AsymmetricCrypto.generate_rsa_keypair(512)


class TestSymmetricKeyWrapping:
    """Unit tests for symmetric key wrapping and unwrapping."""
    
    def test_wrap_unwrap_aes_key(self):
        """Test wrapping and unwrapping an AES-256 key."""
        # Generate RSA key pair
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        
        # Create a 256-bit AES key
        aes_key = b'0' * 32
        
        # Wrap the key
        wrapped = AsymmetricCrypto.wrap_symmetric_key(aes_key, public_key)
        
        # Verify wrapped key is different
        assert wrapped != aes_key
        
        # Unwrap the key
        unwrapped = AsymmetricCrypto.unwrap_symmetric_key(wrapped, private_key)
        
        # Verify unwrapped matches original
        assert unwrapped == aes_key
    
    def test_wrap_with_invalid_public_key_fails(self):
        """Test that wrapping with invalid public key fails gracefully."""
        aes_key = b'0' * 32
        invalid_key = b'not a valid key'
        
        with pytest.raises(ValueError, match="Invalid public key"):
            AsymmetricCrypto.wrap_symmetric_key(aes_key, invalid_key)
    
    def test_unwrap_with_invalid_private_key_fails(self):
        """Test that unwrapping with invalid private key fails gracefully."""
        # Generate valid key pair and wrap a key
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        aes_key = b'0' * 32
        wrapped = AsymmetricCrypto.wrap_symmetric_key(aes_key, public_key)
        
        # Try to unwrap with invalid private key
        invalid_key = b'not a valid key'
        with pytest.raises(ValueError, match="Invalid private key"):
            AsymmetricCrypto.unwrap_symmetric_key(wrapped, invalid_key)
    
    def test_unwrap_with_wrong_private_key_fails(self):
        """Test that unwrapping with wrong private key fails."""
        # Generate two different key pairs
        public_key1, private_key1 = AsymmetricCrypto.generate_rsa_keypair()
        public_key2, private_key2 = AsymmetricCrypto.generate_rsa_keypair()
        
        # Wrap with first public key
        aes_key = b'0' * 32
        wrapped = AsymmetricCrypto.wrap_symmetric_key(aes_key, public_key1)
        
        # Try to unwrap with second private key - should fail
        with pytest.raises(ValueError):
            AsymmetricCrypto.unwrap_symmetric_key(wrapped, private_key2)
    
    def test_wrap_different_key_sizes(self):
        """Test wrapping keys of different sizes."""
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        
        # Test different symmetric key sizes
        for key_size in [16, 24, 32]:  # 128, 192, 256 bits
            symmetric_key = b'X' * key_size
            
            wrapped = AsymmetricCrypto.wrap_symmetric_key(symmetric_key, public_key)
            unwrapped = AsymmetricCrypto.unwrap_symmetric_key(wrapped, private_key)
            
            assert unwrapped == symmetric_key


class TestPrivateKeyEncryption:
    """Unit tests for private key encryption and decryption."""
    
    def test_encrypt_decrypt_private_key(self):
        """Test encrypting and decrypting a private key."""
        # Generate RSA key pair
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        
        # Encrypt private key with password
        password = "strong_password_123"
        encrypted, salt, nonce = AsymmetricCrypto.encrypt_private_key(
            private_key, password
        )
        
        # Verify encrypted is different
        assert encrypted != private_key
        
        # Verify salt and nonce are correct sizes
        assert len(salt) == AsymmetricCrypto.SALT_SIZE
        assert len(nonce) == AsymmetricCrypto.NONCE_SIZE
        
        # Decrypt private key
        decrypted = AsymmetricCrypto.decrypt_private_key(
            encrypted, password, salt, nonce
        )
        
        # Verify decrypted matches original
        assert decrypted == private_key
        
        # Verify decrypted key is still valid
        rsa_key = RSA.import_key(decrypted)
        assert rsa_key.has_private()
    
    def test_encrypt_with_various_password_strengths(self):
        """Test private key encryption with various password strengths."""
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        
        passwords = [
            "short",
            "medium_length_password",
            "very_long_password_with_many_characters_123456789",
            "p@ssw0rd!#$%",
            "unicode_密码_пароль"
        ]
        
        for password in passwords:
            encrypted, salt, nonce = AsymmetricCrypto.encrypt_private_key(
                private_key, password
            )
            
            decrypted = AsymmetricCrypto.decrypt_private_key(
                encrypted, password, salt, nonce
            )
            
            assert decrypted == private_key
    
    def test_decrypt_with_wrong_password_fails(self):
        """Test that decryption with wrong password fails."""
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        
        correct_password = "correct_password"
        wrong_password = "wrong_password"
        
        encrypted, salt, nonce = AsymmetricCrypto.encrypt_private_key(
            private_key, correct_password
        )
        
        # Try to decrypt with wrong password
        with pytest.raises(ValueError, match="Decryption failed"):
            AsymmetricCrypto.decrypt_private_key(
                encrypted, wrong_password, salt, nonce
            )
    
    def test_encrypt_with_empty_password_fails(self):
        """Test that encryption with empty password fails."""
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        
        with pytest.raises(ValueError, match="Password cannot be empty"):
            AsymmetricCrypto.encrypt_private_key(private_key, "")
    
    def test_decrypt_with_empty_password_fails(self):
        """Test that decryption with empty password fails."""
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        
        password = "valid_password"
        encrypted, salt, nonce = AsymmetricCrypto.encrypt_private_key(
            private_key, password
        )
        
        with pytest.raises(ValueError, match="Password cannot be empty"):
            AsymmetricCrypto.decrypt_private_key(encrypted, "", salt, nonce)
    
    def test_decrypt_with_corrupted_data_fails(self):
        """Test that decryption with corrupted data fails."""
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        
        password = "valid_password"
        encrypted, salt, nonce = AsymmetricCrypto.encrypt_private_key(
            private_key, password
        )
        
        # Corrupt the encrypted data
        corrupted = encrypted[:-10] + b'corrupted!'
        
        with pytest.raises(ValueError, match="Decryption failed"):
            AsymmetricCrypto.decrypt_private_key(corrupted, password, salt, nonce)


class TestPublicKeyFingerprint:
    """Unit tests for public key fingerprint generation."""
    
    def test_fingerprint_generation(self):
        """Test that fingerprint generation produces consistent results."""
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        
        # Generate fingerprint
        fingerprint = AsymmetricCrypto.get_public_key_fingerprint(public_key)
        
        # Verify fingerprint is a hex string
        assert isinstance(fingerprint, str)
        assert len(fingerprint) == 64  # SHA-256 produces 64 hex characters
        
        # Verify all characters are hex
        assert all(c in '0123456789abcdef' for c in fingerprint)
    
    def test_fingerprint_consistency(self):
        """Test that same key produces same fingerprint."""
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        
        fingerprint1 = AsymmetricCrypto.get_public_key_fingerprint(public_key)
        fingerprint2 = AsymmetricCrypto.get_public_key_fingerprint(public_key)
        
        assert fingerprint1 == fingerprint2
    
    def test_different_keys_produce_different_fingerprints(self):
        """Test that different keys produce different fingerprints."""
        public_key1, _ = AsymmetricCrypto.generate_rsa_keypair()
        public_key2, _ = AsymmetricCrypto.generate_rsa_keypair()
        
        fingerprint1 = AsymmetricCrypto.get_public_key_fingerprint(public_key1)
        fingerprint2 = AsymmetricCrypto.get_public_key_fingerprint(public_key2)
        
        assert fingerprint1 != fingerprint2
    
    def test_fingerprint_with_invalid_key_fails(self):
        """Test that fingerprint generation with invalid key fails."""
        invalid_key = b'not a valid key'
        
        with pytest.raises(ValueError, match="Invalid public key"):
            AsymmetricCrypto.get_public_key_fingerprint(invalid_key)


class TestIntegrationScenarios:
    """Integration tests for complete workflows."""
    
    def test_complete_key_exchange_workflow(self):
        """Test a complete key exchange workflow."""
        # Organization generates key pair
        org_public, org_private = AsymmetricCrypto.generate_rsa_keypair()
        
        # Consultant generates key pair
        consultant_public, consultant_private = AsymmetricCrypto.generate_rsa_keypair()
        
        # Organization encrypts their private key with password
        org_password = "org_secure_password"
        org_encrypted, org_salt, org_nonce = AsymmetricCrypto.encrypt_private_key(
            org_private, org_password
        )
        
        # Consultant encrypts their private key with password
        consultant_password = "consultant_secure_password"
        consultant_encrypted, consultant_salt, consultant_nonce = AsymmetricCrypto.encrypt_private_key(
            consultant_private, consultant_password
        )
        
        # Organization has a symmetric key (DEK) for file encryption
        file_dek = b'file_encryption_key_32_bytes!'
        
        # Organization wraps DEK with consultant's public key
        wrapped_dek = AsymmetricCrypto.wrap_symmetric_key(file_dek, consultant_public)
        
        # Consultant decrypts their private key
        consultant_private_decrypted = AsymmetricCrypto.decrypt_private_key(
            consultant_encrypted, consultant_password, consultant_salt, consultant_nonce
        )
        
        # Consultant unwraps DEK with their private key
        unwrapped_dek = AsymmetricCrypto.unwrap_symmetric_key(
            wrapped_dek, consultant_private_decrypted
        )
        
        # Verify consultant got the correct DEK
        assert unwrapped_dek == file_dek
    
    def test_key_fingerprint_for_verification(self):
        """Test using fingerprints for key verification."""
        # Generate key pair
        public_key, private_key = AsymmetricCrypto.generate_rsa_keypair()
        
        # Get fingerprint
        fingerprint = AsymmetricCrypto.get_public_key_fingerprint(public_key)
        
        # Simulate storing public key and fingerprint separately
        stored_public_key = public_key
        stored_fingerprint = fingerprint
        
        # Later, verify the stored key matches the fingerprint
        verification_fingerprint = AsymmetricCrypto.get_public_key_fingerprint(
            stored_public_key
        )
        
        assert verification_fingerprint == stored_fingerprint
