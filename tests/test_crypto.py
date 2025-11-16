import os
import tempfile
from app.crypto_utils import (
    parse_key,
    set_kms_provider,
    encrypt_financial_data,
    decrypt_financial_data,
)


def test_parse_key_base64_and_hex_and_passphrase():
    b = b'0123456789abcdef0123456789abcdef'
    import base64, binascii
    b64 = base64.b64encode(b).decode('utf-8')
    h = binascii.hexlify(b).decode('utf-8')

    assert parse_key(b) == b
    assert parse_key(b64) == b
    assert parse_key(h) == b

    # derive from passphrase
    derived = parse_key('my secret passphrase', expected_length=32)
    assert isinstance(derived, bytes) and len(derived) == 32


def test_wrap_unwrap_and_encrypt_decrypt_roundtrip(tmp_path):
    # ensure using stub provider for deterministic behaviour
    set_kms_provider('stub')

    data = {'company_name': 'ACME', 'notes': 'ok'}
    enc_dict, wrapped_key, iv = encrypt_financial_data(data, 'AES')
    assert wrapped_key is not None

    dec = decrypt_financial_data(enc_dict, 'AES', wrapped_key, iv)
    assert dec['company_name'] == 'ACME'
    assert dec['notes'] == 'ok'


def test_pack_unpack_envelope():
    from app.crypto_utils import pack_ciphertext, unpack_ciphertext
    data = b'hello-cipher'
    algo = 'AES'
    iv = b'0' * 16
    wrapped = b'V1' + b'xx'
    env = pack_ciphertext(data, algo, iv, wrapped, 'V1')
    ct, a, iv2, w2, ver = unpack_ciphertext(env)
    assert ct == data
    assert a == algo
    assert iv2 == iv
    assert w2 == wrapped
    assert ver == 'V1'
