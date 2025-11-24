"""
MongoDB Key Store Module

This module provides secure storage for encrypted private keys in MongoDB,
isolated from the main SQLite database.
"""

import os
from datetime import datetime
from typing import Optional, Dict, Any
import logging
from pymongo import MongoClient, ASCENDING
from pymongo.errors import (
    ConnectionFailure,
    ServerSelectionTimeoutError,
    DuplicateKeyError,
    PyMongoError
)
from app.error_handlers import retry_on_transient_failure

logger = logging.getLogger(__name__)


class KeyStore:
    """
    MongoDB interface for private key storage.
    
    This class manages the storage and retrieval of encrypted private keys
    in a MongoDB database, separate from the main application database.
    """
    
    def __init__(self, connection_string: str = None, db_name: str = None):
        """
        Initialize MongoDB connection.
        
        Args:
            connection_string: MongoDB connection URI (defaults to env var MONGODB_URI)
            db_name: Database name (defaults to env var MONGODB_DB_NAME)
        
        Raises:
            ConnectionFailure: If unable to connect to MongoDB
        """
        self.connection_string = connection_string or os.getenv(
            'MONGODB_URI', 
            'mongodb://localhost:27017/'
        )
        self.db_name = db_name or os.getenv(
            'MONGODB_DB_NAME', 
            'secure_file_exchange_keys'
        )
        
        self._client = None
        self._db = None
        self._collection = None
        self._connect()
    
    def _connect(self):
        """
        Establish connection to MongoDB and create indexes.
        
        Raises:
            ConnectionFailure: If unable to connect to MongoDB
        """
        try:
            # Prepare connection options
            connection_options = {
                'serverSelectionTimeoutMS': 5000,
                'connectTimeoutMS': 5000,
                'socketTimeoutMS': 5000
            }
            
            # Add SSL/TLS options for MongoDB Atlas or secure connections
            # This helps resolve SSL handshake errors on Windows
            if 'mongodb+srv://' in self.connection_string or 'ssl=true' in self.connection_string.lower():
                connection_options.update({
                    'tls': True,
                    'tlsAllowInvalidCertificates': False,  # Set to True only for development
                    'retryWrites': True,
                    'w': 'majority'
                })
            
            # Create client with timeout and SSL settings
            self._client = MongoClient(
                self.connection_string,
                **connection_options
            )
            
            # Test connection
            self._client.admin.command('ping')
            
            # Get database and collection
            self._db = self._client[self.db_name]
            self._collection = self._db['private_keys']
            
            # Create unique index on user_id
            self._collection.create_index(
                [('user_id', ASCENDING)],
                unique=True,
                name='user_id_unique_idx'
            )
            
            logger.info(f"Successfully connected to MongoDB: {self.db_name}")
            
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            logger.error(f"Failed to connect to MongoDB: {str(e)}")
            raise ConnectionFailure(f"MongoDB connection failed: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error connecting to MongoDB: {str(e)}")
            raise
    
    @retry_on_transient_failure(max_attempts=3, delay=0.5, backoff=2.0)
    def store_private_key(
        self,
        user_id: int,
        encrypted_key: bytes,
        salt: bytes,
        nonce: bytes,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Store encrypted private key in MongoDB.
        
        Args:
            user_id: User identifier (references SQLite User.id)
            encrypted_key: AES-256-GCM encrypted RSA private key
            salt: PBKDF2 salt used for key derivation
            nonce: AES-GCM nonce
            metadata: Optional additional metadata (e.g., algorithm, key_size)
        
        Returns:
            True if storage successful, False otherwise
        
        Raises:
            ConnectionFailure: If MongoDB connection is unavailable
            DuplicateKeyError: If key already exists for user_id
        """
        try:
            if not self._client:
                raise ConnectionFailure("MongoDB client not initialized")
            
            # Prepare document
            document = {
                'user_id': user_id,
                'encrypted_private_key': encrypted_key,
                'salt': salt,
                'nonce': nonce,
                'algorithm': metadata.get('algorithm', 'RSA-2048') if metadata else 'RSA-2048',
                'created_at': datetime.utcnow(),
                'last_accessed': datetime.utcnow(),
                'access_count': 0
            }
            
            # Add any additional metadata
            if metadata:
                for key, value in metadata.items():
                    if key not in document:
                        document[key] = value
            
            # Insert document
            result = self._collection.insert_one(document)
            
            if result.inserted_id:
                logger.info(f"Successfully stored private key for user_id: {user_id}")
                return True
            else:
                logger.error(f"Failed to store private key for user_id: {user_id}")
                return False
                
        except DuplicateKeyError:
            logger.error(f"Private key already exists for user_id: {user_id}")
            raise
        except (ConnectionFailure, PyMongoError) as e:
            logger.error(f"MongoDB error storing private key: {str(e)}")
            raise ConnectionFailure(f"Failed to store private key: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error storing private key: {str(e)}")
            return False
    
    def retrieve_private_key(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve encrypted private key and metadata from MongoDB.
        
        Args:
            user_id: User identifier
        
        Returns:
            Dictionary containing:
                - encrypted_key: bytes
                - salt: bytes
                - nonce: bytes
                - created_at: datetime
                - algorithm: str
            Returns None if key not found
        
        Raises:
            ConnectionFailure: If MongoDB connection is unavailable
        """
        try:
            if not self._client:
                raise ConnectionFailure("MongoDB client not initialized")
            
            # Find document
            document = self._collection.find_one({'user_id': user_id})
            
            if not document:
                logger.warning(f"No private key found for user_id: {user_id}")
                return None
            
            # Update access tracking
            self._collection.update_one(
                {'user_id': user_id},
                {
                    '$set': {'last_accessed': datetime.utcnow()},
                    '$inc': {'access_count': 1}
                }
            )
            
            # Return key data
            result = {
                'encrypted_key': document['encrypted_private_key'],
                'salt': document['salt'],
                'nonce': document['nonce'],
                'created_at': document['created_at'],
                'algorithm': document.get('algorithm', 'RSA-2048')
            }
            
            logger.info(f"Successfully retrieved private key for user_id: {user_id}")
            return result
            
        except (ConnectionFailure, PyMongoError) as e:
            logger.error(f"MongoDB error retrieving private key: {str(e)}")
            raise ConnectionFailure(f"Failed to retrieve private key: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error retrieving private key: {str(e)}")
            return None
    
    def delete_private_key(self, user_id: int) -> bool:
        """
        Delete private key from MongoDB (for account deletion).
        
        Args:
            user_id: User identifier
        
        Returns:
            True if deletion successful, False otherwise
        
        Raises:
            ConnectionFailure: If MongoDB connection is unavailable
        """
        try:
            if not self._client:
                raise ConnectionFailure("MongoDB client not initialized")
            
            result = self._collection.delete_one({'user_id': user_id})
            
            if result.deleted_count > 0:
                logger.info(f"Successfully deleted private key for user_id: {user_id}")
                return True
            else:
                logger.warning(f"No private key found to delete for user_id: {user_id}")
                return False
                
        except (ConnectionFailure, PyMongoError) as e:
            logger.error(f"MongoDB error deleting private key: {str(e)}")
            raise ConnectionFailure(f"Failed to delete private key: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error deleting private key: {str(e)}")
            return False
    
    def key_exists(self, user_id: int) -> bool:
        """
        Check if private key exists for user.
        
        Args:
            user_id: User identifier
        
        Returns:
            True if key exists, False otherwise
        
        Raises:
            ConnectionFailure: If MongoDB connection is unavailable
        """
        try:
            if not self._client:
                raise ConnectionFailure("MongoDB client not initialized")
            
            count = self._collection.count_documents({'user_id': user_id}, limit=1)
            return count > 0
            
        except (ConnectionFailure, PyMongoError) as e:
            logger.error(f"MongoDB error checking key existence: {str(e)}")
            raise ConnectionFailure(f"Failed to check key existence: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error checking key existence: {str(e)}")
            return False
    
    def close(self):
        """Close MongoDB connection."""
        if self._client:
            self._client.close()
            logger.info("MongoDB connection closed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
