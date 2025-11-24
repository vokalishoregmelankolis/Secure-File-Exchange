#!/usr/bin/env python3
"""Seed script: create two sample uploads and corresponding EncryptedFile rows.

This script uses the application's factory (`create_app`) so it runs with the
same configuration and paths. It encrypts two small text files using the
project's `CryptoEngine` and stores the encrypted blobs in the configured
`ENCRYPTED_FOLDER` and metadata in the `encrypted_files` table.

Usage:
  python3 scripts/seed_sample_uploads.py

Note: For deterministic KEK behaviour set environment variable `MASTER_KEY`.
"""
import os
import uuid
from pathlib import Path

from app import create_app, db
from app.models import EncryptedFile, User
from app.crypto_utils import CryptoEngine


def ensure_master_key():
    # Ensure a MASTER_KEY exists for deterministic wrapping in dev
    if not os.environ.get('MASTER_KEY'):
        os.environ['MASTER_KEY'] = 'test-master-key-2025-seed'


def create_sample_user():
    user = User.query.filter_by(username='seeduser').first()
    if not user:
        user = User(username='seeduser', email='seed@example.com')
        user.set_password('password')
        db.session.add(user)
        db.session.commit()
    return user


def seed_file(app, user, original_name: str, content: bytes):
    upload_folder = Path(app.config['UPLOAD_FOLDER'])
    encrypted_folder = Path(app.config['ENCRYPTED_FOLDER'])
    upload_folder.mkdir(parents=True, exist_ok=True)
    encrypted_folder.mkdir(parents=True, exist_ok=True)

    # write the plaintext to uploads
    local_name = upload_folder / original_name
    local_name.write_bytes(content)

    # Encrypt file using AES
    encrypted_data, wrapped_dek, iv, exec_time, orig_size, enc_size = CryptoEngine.encrypt_file(str(local_name), algorithm='AES')

    file_id = str(uuid.uuid4())
    encrypted_filename = f"{file_id}_encrypted"
    encrypted_path = encrypted_folder / encrypted_filename
    encrypted_path.write_bytes(encrypted_data)

    ef = EncryptedFile(
        file_id=file_id,
        filename=encrypted_filename,
        original_filename=original_name,
        file_type='text/plain',
        file_size=orig_size,
        encrypted_path=str(encrypted_path),
        algorithm='AES',
        encryption_key=None,
        iv=iv,
        wrapped_key=wrapped_dek,
        wrapped_key_version='V1',
        user_id=user.id,
    )
    db.session.add(ef)
    db.session.commit()
    print(f'Created EncryptedFile id={ef.id} file_id={ef.file_id} path={ef.encrypted_path}')
    return ef


def main():
    ensure_master_key()
    app = create_app()
    with app.app_context():
        user = create_sample_user()
        seed_file(app, user, 'sample1.txt', b'Hello from sample 1\nThis is a seeded upload.')
        seed_file(app, user, 'sample2.txt', b'Second sample file. Another seeded upload.')


if __name__ == '__main__':
    main()
