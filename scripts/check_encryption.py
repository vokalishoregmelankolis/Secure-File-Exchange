#!/usr/bin/env python3
"""
Inspect encrypted files in the app database and verify encryption/decryption.

Usage:
  python scripts/check_encryption.py            # list encrypted files
  python scripts/check_encryption.py <file_id> # inspect and attempt decrypt the specified file

The script uses the app's SQLALCHEMY config and CryptoEngine to attempt decryption
using the stored key and iv. If decryption succeeds, a decrypted copy is written to
the app UPLOAD_FOLDER for manual inspection.
"""
import os
import sys
import argparse

# Ensure project root is on sys.path so we can import the 'app' package when this script
# is executed from the scripts/ folder.
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import create_app
from app.models import EncryptedFile
from app.crypto_utils import CryptoEngine


def human_bytes(b):
    for unit in ['B','KB','MB','GB']:
        if b < 1024.0:
            return f"{b:.1f}{unit}"
        b /= 1024.0
    return f"{b:.1f}TB"


def inspect_file(file_obj, app):
    print(f"\nFile record: id={file_obj.id} file_id={file_obj.file_id}")
    print(f" original_filename: {file_obj.original_filename}")
    print(f" algorithm: {file_obj.algorithm}")
    print(f" file_type: {file_obj.file_type}")
    print(f" encrypted_path: {file_obj.encrypted_path}")
    print(f" stored_encrypted_size (db): {human_bytes(file_obj.file_size)} (original size)")

    if not os.path.exists(file_obj.encrypted_path):
        print(' ERROR: encrypted file not found on disk')
        return

    with open(file_obj.encrypted_path, 'rb') as f:
        enc = f.read()

    print(f" on-disk encrypted file size: {human_bytes(len(enc))}")

    # Heuristic: printable ASCII ratio
    printable = sum(32 <= b <= 126 for b in enc) / max(1, len(enc))
    print(f" printable ASCII ratio in encrypted file: {printable:.2%}")
    if printable > 0.7:
        print(" WARNING: high printable ratio — file might not be encrypted or is plaintext-like")

    # Attempt decryption using stored key/iv
    try:
        if file_obj.iv is None:
            decrypted, exec_time = CryptoEngine.decrypt_file(enc, file_obj.algorithm, file_obj.encryption_key, None)
        else:
            decrypted, exec_time = CryptoEngine.decrypt_file(enc, file_obj.algorithm, file_obj.encryption_key, file_obj.iv)

        print(f" decryption: SUCCESS (took {exec_time:.4f}s). Writing decrypted copy for inspection.")

        # write decrypted file for inspection
        uploads = app.config.get('UPLOAD_FOLDER', os.getcwd())
        out_path = os.path.join(uploads, f"{file_obj.file_id}_decrypted_{file_obj.original_filename}")
        with open(out_path, 'wb') as out:
            out.write(decrypted)

        print(f" decrypted file written to: {out_path}")

        # If spreadsheet, attempt to load with openpyxl to validate
        if file_obj.file_type == 'spreadsheet':
            try:
                import openpyxl
                wb = openpyxl.load_workbook(out_path)
                print(' openpyxl: loaded decrypted spreadsheet OK')
            except Exception as e:
                print(f' openpyxl: failed to load decrypted spreadsheet: {e}')

    except Exception as e:
        print(f" decryption: FAILED with error: {e}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file_id', nargs='?', help='file_id (UUID) of encrypted file to inspect')
    args = parser.parse_args()

    app = create_app()

    with app.app_context():
        if not args.file_id:
            files = EncryptedFile.query.order_by(EncryptedFile.uploaded_at.desc()).all()
            if not files:
                print('No encrypted files found in the database.')
                return
            print('Encrypted files in DB:')
            for f in files:
                print(f" - file_id={f.file_id} original={f.original_filename} alg={f.algorithm} uploaded_at={f.uploaded_at} encrypted_path={f.encrypted_path}")
            print('\nRun this script with a file_id to inspect/decrypt, e.g.:')
            print('  python scripts/check_encryption.py 25e63871-94ad-428a-a16f-13d107cc0d0b')
            return

        file_obj = EncryptedFile.query.filter_by(file_id=args.file_id).first()
        if not file_obj:
            print(f'No file with file_id {args.file_id} found.')
            return

        inspect_file(file_obj, app)


if __name__ == '__main__':
    main()
