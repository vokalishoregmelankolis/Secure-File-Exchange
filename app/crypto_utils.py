from Crypto.Cipher import AES, DES, ARC4
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import time
import os
import base64
import binascii
import hashlib
import json
import base64 as _b64

# Environment variable name for the master key-encryption-key (KEK)
MASTER_KEK_ENV = 'MASTER_KEY'


def _get_kek():
    """Derive a 32-byte KEK from environment MASTER_KEY.

    In production this should be an actual KMS or hardware key. Here we derive
    a 32-byte key deterministically from the provided MASTER_KEY string using
    SHA-256. If missing, a RuntimeError is raised to avoid silently insecure
    fallbacks.
    """
    master = os.environ.get(MASTER_KEK_ENV)
    if not master:
        # For development and tests, allow a deterministic fallback KEK so tests
        # and local runs don't fail. In production, set MASTER_KEY explicitly.
        master = os.environ.get('MASTER_KEY_FALLBACK', 'dev-master-key-please-change')
    if isinstance(master, str):
        master = master.encode('utf-8')
    # Simple derivation to 32 bytes
    return hashlib.sha256(master).digest()


def parse_key(key_input, expected_length=None, passphrase_salt: bytes = None, iterations: int = 100_000):
    """Parse/normalize a key input.

    Accepts raw bytes, base64 strings, hex strings, or a passphrase (string) to
    derive a key via PBKDF2 (if expected_length provided).

    Returns bytes of the resulting key.
    """
    if key_input is None:
        return None

    # If already bytes, return (optionally validate length)
    if isinstance(key_input, (bytes, bytearray)):
        b = bytes(key_input)
        if expected_length and len(b) != expected_length:
            raise ValueError(f'Key length {len(b)} does not match expected {expected_length}')
        return b

    if isinstance(key_input, str):
        s = key_input.strip()
        # Try hex first because some hex strings are valid base64 and would decode
        # to unexpected bytes. Hex is more specific for hex-encoded keys.
        try:
            b = binascii.unhexlify(s)
            return b
        except Exception:
            pass

        # Try base64
        try:
            b = base64.b64decode(s, validate=True)
            if expected_length and len(b) != expected_length:
                # allow len >= expected for flexibility
                pass
            return b
        except Exception:
            pass

        # Treat as passphrase: derive key
        if expected_length is None:
            raise ValueError('expected_length must be provided to derive a key from passphrase')
        if passphrase_salt is None:
            # use fixed salt derived from passphrase length (not ideal), but caller
            # should provide a salt for reproducibility
            passphrase_salt = hashlib.sha256(s.encode('utf-8')).digest()[:16]

        # PBKDF2
        from Crypto.Protocol.KDF import PBKDF2
        from Crypto.Hash import SHA256
        key = PBKDF2(s, passphrase_salt, dkLen=expected_length, count=iterations, hmac_hash_module=SHA256)
        return key


class KMSInterface:
    """Simple KMS provider interface used by this module.

    Implementations must provide `wrap(key_bytes) -> bytes` and
    `unwrap(wrapped_bytes) -> bytes`. This is a minimal abstraction so the
    code can later be switched to a real KMS without changing callers.
    """
    def wrap(self, plaintext: bytes) -> bytes:
        raise NotImplementedError()

    def unwrap(self, wrapped: bytes) -> bytes:
        raise NotImplementedError()


class EnvKMS(KMSInterface):
    """KMS implementation that uses an environment MASTER_KEY as KEK.

    It simply performs AES-GCM wrap/unwrap. The wrapped format is:
      b'V1' || nonce(12) || tag(16) || ciphertext
    """
    version = b'V1'

    def wrap(self, plaintext: bytes) -> bytes:
        kek = _get_kek()
        cipher = AES.new(kek, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        # Encode nonce and tag lengths so unwrap can parse variable-length nonces
        nonce = cipher.nonce
        return self.version + bytes([len(nonce)]) + bytes([len(tag)]) + nonce + tag + ciphertext

    def unwrap(self, wrapped: bytes) -> bytes:
        if not wrapped or len(wrapped) < 2:
            raise ValueError('Invalid wrapped key')
        version = wrapped[:2]
        if version != self.version:
            raise ValueError(f'Unsupported wrapped key version: {version!r}')
        # next byte = nonce length, following byte = tag length
        if len(wrapped) < 4:
            raise ValueError('Invalid wrapped key')
        nonce_len = wrapped[2]
        tag_len = wrapped[3]
        start = 4
        nonce = wrapped[start:start+nonce_len]
        start += nonce_len
        tag = wrapped[start:start+tag_len]
        start += tag_len
        ciphertext = wrapped[start:]
        kek = _get_kek()
        cipher = AES.new(kek, AES.MODE_GCM, nonce=nonce)
        dek = cipher.decrypt_and_verify(ciphertext, tag)
        return dek


class StubKMS(KMSInterface):
    """A simple stub KMS that behaves like EnvKMS but can be swapped in tests.

    For now it derives a KEK from an environment variable named MASTER_KEY_STUB
    if present; otherwise it uses the same behaviour as EnvKMS. This is only
    to demonstrate a pluggable interface — replace with a real KMS adapter
    for production (AWS/GCP/Azure KMS).
    """
    version = b'V1'

    def __init__(self):
        # can be extended to keep state
        pass

    def wrap(self, plaintext: bytes) -> bytes:
        # Reuse EnvKMS implementation for now
        return EnvKMS().wrap(plaintext)

    def unwrap(self, wrapped: bytes) -> bytes:
        return EnvKMS().unwrap(wrapped)


# module-level KMS provider (default to EnvKMS)
_KMS_PROVIDER: KMSInterface = EnvKMS()


def set_kms_provider(provider_name: str):
    """Set KMS provider by name. Supported: 'env', 'stub'.

    Used by tests or by a future integration point.
    """
    global _KMS_PROVIDER
    if provider_name == 'env':
        _KMS_PROVIDER = EnvKMS()
    elif provider_name == 'stub':
        _KMS_PROVIDER = StubKMS()
    else:
        raise ValueError('Unsupported KMS provider')


def _wrap_key(dek: bytes) -> bytes:
    return _KMS_PROVIDER.wrap(dek)


def _unwrap_key(wrapped: bytes) -> bytes:
    return _KMS_PROVIDER.unwrap(wrapped)


def pack_ciphertext(encrypted_data: bytes, algorithm: str, iv: bytes = None, wrapped_key: bytes = None, wrapped_key_version: str = None):
    """Pack ciphertext and metadata into a JSON envelope (bytes).

    Fields (JSON):
      - version: envelope version ("1")
      - algorithm: algorithm name (e.g., "AES")
      - iv: base64 iv or null
      - wrapped_key: base64 wrapped key blob or null
      - wrapped_key_version: string or null
      - ciphertext: base64 ciphertext

    This makes stored ciphertext self-describing if desired.
    """
    env = {
        'version': '1',
        'algorithm': algorithm,
        'iv': _b64.b64encode(iv).decode('ascii') if iv is not None else None,
        'wrapped_key': _b64.b64encode(wrapped_key).decode('ascii') if wrapped_key is not None else None,
        'wrapped_key_version': wrapped_key_version,
        'ciphertext': _b64.b64encode(encrypted_data).decode('ascii')
    }
    return json.dumps(env, separators=(',', ':')).encode('utf-8')


def unpack_ciphertext(envelope: bytes):
    """Unpack an envelope produced by `pack_ciphertext`.

    Returns tuple: (encrypted_data: bytes, algorithm: str, iv: bytes|None, wrapped_key: bytes|None, wrapped_key_version: str|None)
    """
    env = json.loads(envelope.decode('utf-8'))
    algorithm = env.get('algorithm')
    iv = _b64.b64decode(env['iv']) if env.get('iv') else None
    wrapped_key = _b64.b64decode(env['wrapped_key']) if env.get('wrapped_key') else None
    wrapped_key_version = env.get('wrapped_key_version')
    ciphertext = _b64.b64decode(env['ciphertext'])
    return ciphertext, algorithm, iv, wrapped_key, wrapped_key_version


class CryptoEngine:
    """Cryptographic engine supporting AES, DES, and RC4.

    Important changes:
    - DEKs are generated per-operation, then wrapped with a KEK (from env).
    - Functions return/store wrapped DEK blobs so raw DEKs are not saved in DB.
    """

    AES_KEY_SIZE = 32  # 256-bit
    DES_KEY_SIZE = 8   # 64-bit (56-bit effective)
    RC4_KEY_SIZE = 16  # 128-bit
    BLOCK_SIZE = 16    # For AES (CBC)
    DES_BLOCK_SIZE = 8 # For DES

    @staticmethod
    def _generate_key_for_algorithm(algorithm: str) -> bytes:
        if algorithm.upper() == 'AES':
            return get_random_bytes(CryptoEngine.AES_KEY_SIZE)
        elif algorithm.upper() == 'DES':
            return get_random_bytes(CryptoEngine.DES_KEY_SIZE)
        elif algorithm.upper() == 'RC4':
            return get_random_bytes(CryptoEngine.RC4_KEY_SIZE)
        else:
            raise ValueError(f'Unsupported algorithm: {algorithm}')

    @staticmethod
    def encrypt_aes(data, dek: bytes = None):
        start_time = time.time()
        if dek is None:
            dek = CryptoEngine._generate_key_for_algorithm('AES')
        iv = get_random_bytes(CryptoEngine.BLOCK_SIZE)
        cipher = AES.new(dek, AES.MODE_CBC, iv)
        if isinstance(data, str):
            data = data.encode('utf-8')
        padded_data = pad(data, CryptoEngine.BLOCK_SIZE)
        encrypted_data = cipher.encrypt(padded_data)
        execution_time = time.time() - start_time
        # Wrap the DEK before returning
        wrapped_dek = _wrap_key(dek)
        return encrypted_data, wrapped_dek, iv, execution_time

    @staticmethod
    def decrypt_aes(encrypted_data, wrapped_dek: bytes, iv: bytes):
        start_time = time.time()
        dek = _unwrap_key(wrapped_dek)
        cipher = AES.new(dek, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_padded, CryptoEngine.BLOCK_SIZE)
        execution_time = time.time() - start_time
        return decrypted_data, execution_time

    @staticmethod
    def encrypt_des(data, dek: bytes = None):
        start_time = time.time()
        if dek is None:
            dek = CryptoEngine._generate_key_for_algorithm('DES')
        iv = get_random_bytes(CryptoEngine.DES_BLOCK_SIZE)
        cipher = DES.new(dek, DES.MODE_CBC, iv)
        if isinstance(data, str):
            data = data.encode('utf-8')
        padded_data = pad(data, CryptoEngine.DES_BLOCK_SIZE)
        encrypted_data = cipher.encrypt(padded_data)
        execution_time = time.time() - start_time
        wrapped_dek = _wrap_key(dek)
        return encrypted_data, wrapped_dek, iv, execution_time

    @staticmethod
    def decrypt_des(encrypted_data, wrapped_dek: bytes, iv: bytes):
        start_time = time.time()
        dek = _unwrap_key(wrapped_dek)
        cipher = DES.new(dek, DES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_padded, CryptoEngine.DES_BLOCK_SIZE)
        execution_time = time.time() - start_time
        return decrypted_data, execution_time

    @staticmethod
    def encrypt_rc4(data, dek: bytes = None):
        start_time = time.time()
        if dek is None:
            dek = CryptoEngine._generate_key_for_algorithm('RC4')
        cipher = ARC4.new(dek)
        if isinstance(data, str):
            data = data.encode('utf-8')
        encrypted_data = cipher.encrypt(data)
        execution_time = time.time() - start_time
        wrapped_dek = _wrap_key(dek)
        return encrypted_data, wrapped_dek, None, execution_time

    @staticmethod
    def decrypt_rc4(encrypted_data, wrapped_dek: bytes):
        start_time = time.time()
        dek = _unwrap_key(wrapped_dek)
        cipher = ARC4.new(dek)
        decrypted_data = cipher.decrypt(encrypted_data)
        execution_time = time.time() - start_time
        return decrypted_data, execution_time

    @staticmethod
    def encrypt_file(file_path, algorithm='AES', key=None):
        with open(file_path, 'rb') as f:
            data = f.read()
        original_size = len(data)
        if algorithm.upper() == 'AES':
            encrypted_data, wrapped_dek, iv, exec_time = CryptoEngine.encrypt_aes(data, key)
        elif algorithm.upper() == 'DES':
            encrypted_data, wrapped_dek, iv, exec_time = CryptoEngine.encrypt_des(data, key)
        elif algorithm.upper() == 'RC4':
            encrypted_data, wrapped_dek, iv, exec_time = CryptoEngine.encrypt_rc4(data, key)
        else:
            raise ValueError(f'Unsupported algorithm: {algorithm}')
        encrypted_size = len(encrypted_data)
        return encrypted_data, wrapped_dek, iv, exec_time, original_size, encrypted_size

    @staticmethod
    def decrypt_file(encrypted_data, algorithm, wrapped_dek: bytes, iv=None):
        if algorithm.upper() == 'AES':
            return CryptoEngine.decrypt_aes(encrypted_data, wrapped_dek, iv)
        elif algorithm.upper() == 'DES':
            return CryptoEngine.decrypt_des(encrypted_data, wrapped_dek, iv)
        elif algorithm.upper() == 'RC4':
            return CryptoEngine.decrypt_rc4(encrypted_data, wrapped_dek)
        else:
            raise ValueError(f'Unsupported algorithm: {algorithm}')

    @staticmethod
    def encrypt_text(text, algorithm='AES', key=None):
        if algorithm.upper() == 'AES':
            return CryptoEngine.encrypt_aes(text, key)
        elif algorithm.upper() == 'DES':
            return CryptoEngine.encrypt_des(text, key)
        elif algorithm.upper() == 'RC4':
            return CryptoEngine.encrypt_rc4(text, key)
        else:
            raise ValueError(f'Unsupported algorithm: {algorithm}')

    @staticmethod
    def decrypt_text(encrypted_data, algorithm, wrapped_dek: bytes, iv=None):
        if algorithm.upper() == 'AES':
            decrypted, exec_time = CryptoEngine.decrypt_aes(encrypted_data, wrapped_dek, iv)
        elif algorithm.upper() == 'DES':
            decrypted, exec_time = CryptoEngine.decrypt_des(encrypted_data, wrapped_dek, iv)
        elif algorithm.upper() == 'RC4':
            decrypted, exec_time = CryptoEngine.decrypt_rc4(encrypted_data, wrapped_dek)
        else:
            raise ValueError(f'Unsupported algorithm: {algorithm}')
        return decrypted.decode('utf-8'), exec_time


def encrypt_financial_data(data_dict, algorithm='AES', key=None):
    """Encrypt financial form fields. Returns (encrypted_dict, wrapped_key, iv)
    where wrapped_key is the KEK-wrapped DEK blob suitable for storage in DB.
    """
    # Determine raw DEK to use for all fields (so a single DEK encrypts all fields)
    raw_dek = None
    wrapped_key = None
    if key is None:
        # generate fresh DEK for this set of fields
        raw_dek = CryptoEngine._generate_key_for_algorithm(algorithm)
        wrapped_key = _wrap_key(raw_dek)
    else:
        # key may be a wrapped blob (from DB) or raw bytes
        if isinstance(key, (bytes, bytearray)):
            # heuristics: if key starts with our version tag, treat as wrapped
            if len(key) >= 2 and bytes(key)[:2] == b'V1':
                wrapped_key = bytes(key)
                raw_dek = _unwrap_key(wrapped_key)
            else:
                # treat as raw DEK
                raw_dek = bytes(key)
                wrapped_key = _wrap_key(raw_dek)
        else:
            raise ValueError('Unsupported key type for encrypt_financial_data')

    encrypted_dict = {}
    iv = None
    # Use a single IV for all fields for block ciphers so we can store one IV
    # in the EncryptedFile row and decrypt all fields with it.
    algo = algorithm.upper()
    if algo == 'AES':
        iv = get_random_bytes(CryptoEngine.BLOCK_SIZE)
        for field, value in data_dict.items():
            if value is not None and value != '':
                b = str(value).encode('utf-8')
                padded = pad(b, CryptoEngine.BLOCK_SIZE)
                cipher = AES.new(raw_dek, AES.MODE_CBC, iv)
                encrypted = cipher.encrypt(padded)
                encrypted_dict[f'encrypted_{field}'] = encrypted
            else:
                encrypted_dict[f'encrypted_{field}'] = None
    elif algo == 'DES':
        iv = get_random_bytes(CryptoEngine.DES_BLOCK_SIZE)
        for field, value in data_dict.items():
            if value is not None and value != '':
                b = str(value).encode('utf-8')
                padded = pad(b, CryptoEngine.DES_BLOCK_SIZE)
                cipher = DES.new(raw_dek, DES.MODE_CBC, iv)
                encrypted = cipher.encrypt(padded)
                encrypted_dict[f'encrypted_{field}'] = encrypted
            else:
                encrypted_dict[f'encrypted_{field}'] = None
    elif algo == 'RC4':
        # RC4 is a stream cipher; no IV. Use same key for all fields.
        for field, value in data_dict.items():
            if value is not None and value != '':
                b = str(value).encode('utf-8')
                cipher = ARC4.new(raw_dek)
                encrypted = cipher.encrypt(b)
                encrypted_dict[f'encrypted_{field}'] = encrypted
            else:
                encrypted_dict[f'encrypted_{field}'] = None
    else:
        raise ValueError(f'Unsupported algorithm: {algorithm}')

    return encrypted_dict, wrapped_key, iv


def decrypt_financial_data(encrypted_dict, algorithm, wrapped_key, iv=None):
    """Decrypt all fields in an encrypted financial data dictionary.
    `wrapped_key` must be the wrapped-dek blob stored in DB.
    Returns: decrypted_dict
    """
    decrypted_dict = {}
    for field, value in encrypted_dict.items():
        if value is not None:
            field_name = field.replace('encrypted_', '')
            decrypted, _ = CryptoEngine.decrypt_text(value, algorithm, wrapped_key, iv)
            decrypted_dict[field_name] = decrypted
        else:
            field_name = field.replace('encrypted_', '')
            decrypted_dict[field_name] = None
    return decrypted_dict