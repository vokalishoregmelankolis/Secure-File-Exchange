"""
Error handling utilities for the Secure File Exchange System

Provides centralized error handling, user-friendly error messages,
and retry logic for transient failures.
"""

import time
import logging
from functools import wraps
from flask import flash, current_app
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, PyMongoError

logger = logging.getLogger(__name__)


class ErrorMessages:
    """User-friendly error messages for various failure scenarios"""
    
    # MongoDB errors
    MONGODB_CONNECTION_FAILED = (
        "Unable to connect to the key storage service. "
        "Please try again in a few moments. If the problem persists, contact support."
    )
    MONGODB_TIMEOUT = (
        "The key storage service is taking too long to respond. "
        "Please try again later."
    )
    MONGODB_OPERATION_FAILED = (
        "An error occurred while accessing the key storage service. "
        "Please try again."
    )
    
    # Key generation errors
    KEY_GENERATION_FAILED = (
        "Failed to generate encryption keys. "
        "This may be due to insufficient system resources. Please try again."
    )
    KEY_SIZE_INVALID = (
        "Invalid key size specified. Keys must be at least 2048 bits for security."
    )
    
    # Cryptographic operation errors
    ENCRYPTION_FAILED = (
        "Failed to encrypt data. Please verify your input and try again."
    )
    DECRYPTION_FAILED = (
        "Failed to decrypt data. The encryption key may be incorrect or corrupted."
    )
    KEY_WRAPPING_FAILED = (
        "Failed to securely wrap the encryption key. "
        "The recipient's public key may be invalid."
    )
    KEY_UNWRAPPING_FAILED = (
        "Failed to unwrap the encryption key. "
        "Your private key or password may be incorrect."
    )
    
    # Password errors
    PASSWORD_INCORRECT = (
        "Incorrect password. Please try again. "
        "Make sure you're using the password you set during registration."
    )
    PASSWORD_EMPTY = (
        "Password cannot be empty. Please provide your password."
    )
    
    # Data corruption errors
    KEY_CORRUPTED = (
        "The encryption key appears to be corrupted. "
        "Please contact support for assistance."
    )
    DATA_CORRUPTED = (
        "The encrypted data appears to be corrupted and cannot be decrypted."
    )
    
    # Access control errors
    ACCESS_DENIED = (
        "You do not have permission to perform this action."
    )
    ACCESS_REVOKED = (
        "Your access to this file has been revoked by the owner."
    )
    
    # General errors
    UNEXPECTED_ERROR = (
        "An unexpected error occurred. Please try again. "
        "If the problem persists, contact support."
    )
    OPERATION_FAILED = (
        "The operation could not be completed. Please try again."
    )


def retry_on_transient_failure(max_attempts=3, delay=1.0, backoff=2.0):
    """
    Decorator to retry operations on transient failures.
    
    Args:
        max_attempts: Maximum number of retry attempts
        delay: Initial delay between retries in seconds
        backoff: Multiplier for delay after each retry
    
    Returns:
        Decorated function that retries on transient failures
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            current_delay = delay
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except (ConnectionFailure, ServerSelectionTimeoutError) as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        logger.warning(
                            f"Transient failure in {func.__name__} (attempt {attempt + 1}/{max_attempts}): {e}"
                        )
                        time.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        logger.error(
                            f"All retry attempts failed for {func.__name__}: {e}"
                        )
                except Exception as e:
                    # Non-transient errors should not be retried
                    logger.error(f"Non-transient error in {func.__name__}: {e}")
                    raise
            
            # If we get here, all retries failed
            raise last_exception
        
        return wrapper
    return decorator


def handle_mongodb_error(error, operation="operation"):
    """
    Handle MongoDB errors and provide user-friendly messages.
    
    Args:
        error: The exception that occurred
        operation: Description of the operation that failed
    
    Returns:
        Tuple of (user_message, log_message)
    """
    if isinstance(error, ConnectionFailure):
        user_msg = ErrorMessages.MONGODB_CONNECTION_FAILED
        log_msg = f"MongoDB connection failed during {operation}: {error}"
    elif isinstance(error, ServerSelectionTimeoutError):
        user_msg = ErrorMessages.MONGODB_TIMEOUT
        log_msg = f"MongoDB timeout during {operation}: {error}"
    elif isinstance(error, PyMongoError):
        user_msg = ErrorMessages.MONGODB_OPERATION_FAILED
        log_msg = f"MongoDB operation failed during {operation}: {error}"
    else:
        user_msg = ErrorMessages.UNEXPECTED_ERROR
        log_msg = f"Unexpected error during {operation}: {error}"
    
    logger.error(log_msg)
    return user_msg, log_msg


def handle_crypto_error(error, operation="cryptographic operation"):
    """
    Handle cryptographic errors and provide user-friendly messages.
    
    Args:
        error: The exception that occurred
        operation: Description of the operation that failed
    
    Returns:
        Tuple of (user_message, log_message)
    """
    error_str = str(error).lower()
    
    # Determine the type of error based on the error message
    if "password" in error_str and ("incorrect" in error_str or "wrong" in error_str or "failed" in error_str):
        user_msg = ErrorMessages.PASSWORD_INCORRECT
    elif "password cannot be empty" in error_str:
        user_msg = ErrorMessages.PASSWORD_EMPTY
    elif "corrupted" in error_str or "invalid" in error_str:
        if "key" in error_str:
            user_msg = ErrorMessages.KEY_CORRUPTED
        else:
            user_msg = ErrorMessages.DATA_CORRUPTED
    elif "key size" in error_str or "2048 bits" in error_str:
        user_msg = ErrorMessages.KEY_SIZE_INVALID
    elif "wrap" in error_str:
        user_msg = ErrorMessages.KEY_WRAPPING_FAILED
    elif "unwrap" in error_str or "decrypt" in error_str:
        user_msg = ErrorMessages.KEY_UNWRAPPING_FAILED
    elif "encrypt" in error_str:
        user_msg = ErrorMessages.ENCRYPTION_FAILED
    else:
        user_msg = ErrorMessages.OPERATION_FAILED
    
    log_msg = f"Cryptographic error during {operation}: {error}"
    logger.error(log_msg)
    
    return user_msg, log_msg


def flash_error(message, category='danger'):
    """
    Flash an error message to the user.
    
    Args:
        message: The message to display
        category: Flash message category (default: 'danger')
    """
    flash(message, category)


def flash_success(message):
    """
    Flash a success message to the user.
    
    Args:
        message: The message to display
    """
    flash(message, 'success')


def flash_warning(message):
    """
    Flash a warning message to the user.
    
    Args:
        message: The message to display
    """
    flash(message, 'warning')


def flash_info(message):
    """
    Flash an info message to the user.
    
    Args:
        message: The message to display
    """
    flash(message, 'info')


def safe_operation(operation_name, flash_on_error=True):
    """
    Decorator to safely execute operations with error handling.
    
    Args:
        operation_name: Name of the operation for logging
        flash_on_error: Whether to flash error messages to user
    
    Returns:
        Decorated function with error handling
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except (ConnectionFailure, ServerSelectionTimeoutError, PyMongoError) as e:
                user_msg, log_msg = handle_mongodb_error(e, operation_name)
                if flash_on_error:
                    flash_error(user_msg)
                return None
            except ValueError as e:
                user_msg, log_msg = handle_crypto_error(e, operation_name)
                if flash_on_error:
                    flash_error(user_msg)
                return None
            except Exception as e:
                logger.error(f"Unexpected error in {operation_name}: {e}")
                if flash_on_error:
                    flash_error(ErrorMessages.UNEXPECTED_ERROR)
                return None
        
        return wrapper
    return decorator
