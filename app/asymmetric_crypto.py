"""
Asymmetric Cryptography Module

This module provides RSA-based asymmetric encryption operations for secure
key exchange in the Secure File Exchange System.

Key Features:
- RSA key pair generation (2048-bit minimum)
- Symmetric key wrapping with RSA-OAEP SHA-256
- Symmetric key unwrapping with RSA private key
- Private key encryption with AES-256-GCM
- Private key decryption with password verification
- Public key fingerprint generation
"""

import hashlib
import secrets
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2


class AsymmetricCrypto:
    """Handles RSA key generation, encryption, and decryption operations."""
    
    # Constants
    DEFAULT_KEY_SIZE = 2048
    MIN_KEY_SIZE = 2048
    AES_KEY_SIZE = 32  # 256-bit
    PBKDF2_ITERATIONS = 100000
    SALT_SIZE = 16
    NONCE_SIZE = 12
    
    @staticmethod
    def generate_rsa_keypair(key_size: int = DEFAULT_KEY_SIZE) -> tuple[bytes, bytes]:
        """
        Generate RSA key pair.
        
        Args:
            key_size: Size of RSA key in bits (minimum 2048)
            
        Returns:
            Tuple of (public_key_pem, private_key_pem) as bytes
            
        Raises:
            ValueError: If key_size is less than minimum required
        """
        if key_size < AsymmetricCrypto.MIN_KEY_SIZE:
            raise ValueError(
                f'Key size must be at least {AsymmetricCrypto.MIN_KEY_SIZE} bits'
            )
        
        # Generate RSA key pair
        key = RSA.generate(key_size)
        
        # Export keys in PEM format
        private_key_pem = key.export_key(format='PEM')
        public_key_pem = key.publickey().export_key(format='PEM')
        
        return public_key_pem, private_key_pem
    
    @staticmethod
    def wrap_symmetric_key(symmetric_key: bytes, public_key_pem: bytes) -> bytes:
        """
        Encrypt symmetric key with RSA public key using OAEP padding.
        
        Args:
            symmetric_key: The symmetric key to wrap (e.g., AES key)
            public_key_pem: RSA public key in PEM format
            
        Returns:
            Wrapped (encrypted) symmetric key as bytes
            
        Raises:
            ValueError: If public key is invalid
        """
        try:
            # Import public key
            public_key = RSA.import_key(public_key_pem)
            
            # Create cipher with OAEP padding and SHA-256
            cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
            
            # Encrypt the symmetric key
            wrapped_key = cipher.encrypt(symmetric_key)
            
            return wrapped_key
        except (ValueError, TypeError) as e:
            raise ValueError(f'Invalid public key: {e}')
    
    @staticmethod
    def unwrap_symmetric_key(wrapped_key: bytes, private_key_pem: bytes) -> bytes:
        """
        Decrypt wrapped symmetric key with RSA private key.
        
        Args:
            wrapped_key: The wrapped symmetric key to decrypt
            private_key_pem: RSA private key in PEM format
            
        Returns:
            Unwrapped (decrypted) symmetric key as bytes
            
        Raises:
            ValueError: If private key is invalid or decryption fails
        """
        try:
            # Import private key
            private_key = RSA.import_key(private_key_pem)
            
            # Create cipher with OAEP padding and SHA-256
            cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
            
            # Decrypt the wrapped key
            symmetric_key = cipher.decrypt(wrapped_key)
            
            return symmetric_key
        except (ValueError, TypeError) as e:
            raise ValueError(f'Invalid private key or wrapped key: {e}')
    
    @staticmethod
    def encrypt_private_key(
        private_key_pem: bytes,
        password: str
    ) -> tuple[bytes, bytes, bytes]:
        """
        Encrypt private key with password-derived key using AES-256-GCM.
        
        Args:
            private_key_pem: RSA private key in PEM format
            password: User password for key derivation
            
        Returns:
            Tuple of (encrypted_key, salt, nonce)
            
        Raises:
            ValueError: If password is empty
        """
        if not password:
            raise ValueError('Password cannot be empty')
        
        # Generate random salt and nonce
        salt = secrets.token_bytes(AsymmetricCrypto.SALT_SIZE)
        nonce = secrets.token_bytes(AsymmetricCrypto.NONCE_SIZE)
        
        # Derive encryption key from password using PBKDF2
        # Encode password to bytes if it's a string
        password_bytes = password.encode('utf-8') if isinstance(password, str) else password
        derived_key = PBKDF2(
            password_bytes,
            salt,
            dkLen=AsymmetricCrypto.AES_KEY_SIZE,
            count=AsymmetricCrypto.PBKDF2_ITERATIONS,
            hmac_hash_module=SHA256
        )
        
        # Encrypt private key with AES-256-GCM
        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
        encrypted_key, tag = cipher.encrypt_and_digest(private_key_pem)
        
        # Prepend tag to encrypted key for storage
        encrypted_key_with_tag = tag + encrypted_key
        
        return encrypted_key_with_tag, salt, nonce
    
    @staticmethod
    def decrypt_private_key(
        encrypted_key: bytes,
        password: str,
        salt: bytes,
        nonce: bytes
    ) -> bytes:
        """
        Decrypt private key using password.
        
        Args:
            encrypted_key: Encrypted private key (with tag prepended)
            password: User password for key derivation
            salt: Salt used in key derivation
            nonce: Nonce used in AES-GCM encryption
            
        Returns:
            Decrypted private key in PEM format
            
        Raises:
            ValueError: If password is incorrect or data is corrupted
        """
        if not password:
            raise ValueError('Password cannot be empty')
        
        try:
            # Derive decryption key from password using PBKDF2
            # Encode password to bytes if it's a string
            password_bytes = password.encode('utf-8') if isinstance(password, str) else password
            derived_key = PBKDF2(
                password_bytes,
                salt,
                dkLen=AsymmetricCrypto.AES_KEY_SIZE,
                count=AsymmetricCrypto.PBKDF2_ITERATIONS,
                hmac_hash_module=SHA256
            )
            
            # Extract tag and ciphertext
            # AES-GCM tag is 16 bytes
            tag = encrypted_key[:16]
            ciphertext = encrypted_key[16:]
            
            # Decrypt private key with AES-256-GCM
            cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
            private_key_pem = cipher.decrypt_and_verify(ciphertext, tag)
            
            return private_key_pem
        except (ValueError, KeyError) as e:
            raise ValueError(f'Decryption failed - incorrect password or corrupted data: {e}')
    
    @staticmethod
    def get_public_key_fingerprint(public_key_pem: bytes) -> str:
        """
        Generate SHA-256 fingerprint of public key.
        
        Args:
            public_key_pem: RSA public key in PEM format
            
        Returns:
            Hex-encoded fingerprint string
            
        Raises:
            ValueError: If public key is invalid
        """
        try:
            # Import public key to validate it
            public_key = RSA.import_key(public_key_pem)
            
            # Generate SHA-256 hash of the public key bytes
            fingerprint = hashlib.sha256(public_key_pem).hexdigest()
            
            return fingerprint
        except (ValueError, TypeError) as e:
            raise ValueError(f'Invalid public key: {e}')
