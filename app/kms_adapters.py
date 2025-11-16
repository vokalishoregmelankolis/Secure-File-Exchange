"""KMS adapter examples.

This file provides example adapters implementing the same minimal
KMSInterface used by `app/crypto_utils`. It's intended as a starting point
for integrating a real KMS such as AWS KMS. Do NOT store credentials in code.

Usage:
  from app.kms_adapters import AWSKMS
  kms = AWSKMS(key_id='alias/your-key')
  wrapped = kms.wrap(dek_bytes)
  dek = kms.unwrap(wrapped)

This adapter expects `boto3` to be available and AWS credentials configured
in the environment or via standard AWS config locations.
"""
from typing import Optional

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except Exception:  # pragma: no cover - optional dependency
    boto3 = None

from app.crypto_utils import KMSInterface


class AWSKMS(KMSInterface):
    """Simple AWS KMS adapter.

    This adapter implements wrap/unwrap by calling KMS Encrypt/Decrypt APIs.
    It is intentionally minimal — for production consider using GenerateDataKey
    for the common envelope pattern (GenerateDataKey returns plaintext DEK and
    encrypted DEK blob). Here we provide wrap/unwrap for an existing DEK.
    """
    def __init__(self, key_id: Optional[str] = None, region_name: Optional[str] = None):
        if boto3 is None:
            raise RuntimeError('boto3 is required for AWSKMS adapter')
        self.client = boto3.client('kms', region_name=region_name)
        self.key_id = key_id

    def wrap(self, plaintext: bytes) -> bytes:
        """Wrap (encrypt) a DEK using AWS KMS Encrypt API.

        Returns the raw CiphertextBlob bytes as returned by AWS KMS.
        """
        try:
            params = {'Plaintext': plaintext}
            if self.key_id:
                params['KeyId'] = self.key_id
            resp = self.client.encrypt(**params)
            return resp['CiphertextBlob']
        except (BotoCoreError, ClientError) as e:
            raise RuntimeError(f'AWS KMS encrypt error: {e}')

    def unwrap(self, wrapped: bytes) -> bytes:
        """Unwrap (decrypt) a KMS CiphertextBlob using AWS KMS Decrypt API."""
        try:
            resp = self.client.decrypt(CiphertextBlob=wrapped)
            return resp['Plaintext']
        except (BotoCoreError, ClientError) as e:
            raise RuntimeError(f'AWS KMS decrypt error: {e}')


class DummyKMS(KMSInterface):
    """Local in-memory KMS for quick testing or dev — NOT secure."""
    def __init__(self):
        self._store = {}
        self._counter = 0

    def wrap(self, plaintext: bytes) -> bytes:
        key = f'dummy_{self._counter}'.encode('utf-8')
        self._store[key] = plaintext
        self._counter += 1
        return key + b':'

    def unwrap(self, wrapped: bytes) -> bytes:
        key = wrapped.split(b':', 1)[0]
        return self._store.get(key, b'')
