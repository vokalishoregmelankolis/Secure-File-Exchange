"""Example script demonstrating encryption+wrapping flow.

Run after exporting MASTER_KEY or set it in the environment.
"""
import os
from app.crypto_utils import encrypt_financial_data, decrypt_financial_data


def main():
    os.environ.setdefault('MASTER_KEY', 'example-master-key')
    data = {
        'company_name': 'Example Co',
        'report_period': '2025',
        'notes': 'Demo'
    }
    enc, wrapped, iv = encrypt_financial_data(data, 'AES')
    print('Wrapped key len:', len(wrapped))
    dec = decrypt_financial_data(enc, 'AES', wrapped, iv)
    print('Decrypted:', dec)


if __name__ == '__main__':
    main()
