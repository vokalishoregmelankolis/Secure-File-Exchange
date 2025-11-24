from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import enum


class UserRole(enum.Enum):
    """User role enumeration"""
    ORGANIZATION = "organization"
    CONSULTANT = "consultant"


class User(UserMixin, db.Model):
    """User model for authentication and user management"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Asymmetric key exchange fields
    role = db.Column(db.Enum(UserRole), nullable=False, default=UserRole.ORGANIZATION)
    public_key = db.Column(db.LargeBinary, nullable=True)
    public_key_fingerprint = db.Column(db.String(64), nullable=True)
    key_generated_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    files = db.relationship('EncryptedFile', backref='owner', lazy=True, foreign_keys='EncryptedFile.user_id')
    shared_files = db.relationship('SharedFile', backref='recipient', lazy=True, foreign_keys='SharedFile.recipient_id')
    
    def set_password(self, password):
        """Hash and set the user's password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify the user's password"""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'


class EncryptedFile(db.Model):
    """Model for storing encrypted file metadata and encrypted data"""
    __tablename__ = 'encrypted_files'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    encrypted_path = db.Column(db.String(500), nullable=False)
    algorithm = db.Column(db.String(20), nullable=False)
    
    # Store encryption key (legacy). In production, use proper key management.
    # This column is kept for backward compatibility; new code prefers `wrapped_key`.
    encryption_key = db.Column(db.LargeBinary, nullable=True)
    iv = db.Column(db.LargeBinary, nullable=True)  # Initialization Vector for AES/DES
    # Wrapped DEK (preferred) — KEK-wrapped data-encryption-key blob
    wrapped_key = db.Column(db.LargeBinary, nullable=True)
    wrapped_key_version = db.Column(db.String(10), nullable=True)
    
    # User relationship
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Timestamps
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    shared_with = db.relationship('SharedFile', backref='file', lazy=True, cascade='all, delete-orphan')
    report_data = db.relationship('FinancialReport', backref='file', uselist=False, cascade='all, delete-orphan')
    performance_metrics = db.relationship('PerformanceMetric', backref='file', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<EncryptedFile {self.filename}>'


class SharedFile(db.Model):
    """Model for tracking file sharing permissions"""
    __tablename__ = 'shared_files'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('encrypted_files.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    shared_at = db.Column(db.DateTime, default=datetime.utcnow)
    can_download = db.Column(db.Boolean, default=True)
    
    # Unique constraint to prevent duplicate shares
    __table_args__ = (db.UniqueConstraint('file_id', 'recipient_id', name='unique_file_share'),)
    
    def __repr__(self):
        return f'<SharedFile file_id={self.file_id} recipient_id={self.recipient_id}>'


class FinancialReport(db.Model):
    """Model for storing encrypted financial report data"""
    __tablename__ = 'financial_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('encrypted_files.id'), nullable=False, unique=True)
    
    # Encrypted financial data (stored as binary)
    encrypted_company_name = db.Column(db.LargeBinary, nullable=True)
    encrypted_report_period = db.Column(db.LargeBinary, nullable=True)
    encrypted_department = db.Column(db.LargeBinary, nullable=True)
    encrypted_total_revenue = db.Column(db.LargeBinary, nullable=True)
    encrypted_total_expenses = db.Column(db.LargeBinary, nullable=True)
    encrypted_net_profit = db.Column(db.LargeBinary, nullable=True)
    encrypted_budget_allocated = db.Column(db.LargeBinary, nullable=True)
    encrypted_budget_spent = db.Column(db.LargeBinary, nullable=True)
    encrypted_variance = db.Column(db.LargeBinary, nullable=True)
    encrypted_notes = db.Column(db.LargeBinary, nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<FinancialReport file_id={self.file_id}>'


class PerformanceMetric(db.Model):
    """Model for storing encryption/decryption performance metrics"""
    __tablename__ = 'performance_metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('encrypted_files.id'), nullable=False)
    
    algorithm = db.Column(db.String(20), nullable=False)  # AES, DES, RC4
    operation = db.Column(db.String(20), nullable=False)  # encryption, decryption
    data_type = db.Column(db.String(50), nullable=False)  # numerical, spreadsheet, image
    
    execution_time = db.Column(db.Float, nullable=False)  # Time in seconds
    input_size = db.Column(db.Integer, nullable=False)  # Size in bytes
    output_size = db.Column(db.Integer, nullable=False)  # Size in bytes
    
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<PerformanceMetric {self.algorithm} {self.operation}>'


class EncryptionLog(db.Model):
    """Model for logging encryption/decryption operations"""
    __tablename__ = 'encryption_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    file_id = db.Column(db.String(36), nullable=False)
    operation = db.Column(db.String(20), nullable=False)  # upload, download, share, decrypt
    algorithm = db.Column(db.String(20), nullable=True)
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
    
    user = db.relationship('User', backref='encryption_logs')
    
    def __repr__(self):
        return f'<EncryptionLog {self.operation} by user {self.user_id}>'


class AccessRequest(db.Model):
    """Model for tracking data access requests"""
    __tablename__ = 'access_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    consultant_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('encrypted_files.id', ondelete='CASCADE'), nullable=False)
    
    status = db.Column(db.String(20), nullable=False, default='pending')
    # Status values: pending, approved, denied, revoked
    
    wrapped_symmetric_key = db.Column(db.LargeBinary, nullable=True)
    # Stores the RSA-wrapped DEK after approval
    
    requested_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    consultant = db.relationship('User', foreign_keys=[consultant_id], backref='sent_requests')
    organization = db.relationship('User', foreign_keys=[organization_id], backref='received_requests')
    file = db.relationship('EncryptedFile', backref='access_requests')
    
    # Unique constraint to prevent duplicate requests
    __table_args__ = (db.UniqueConstraint('consultant_id', 'file_id', name='unique_access_request'),)
    
    def __repr__(self):
        return f'<AccessRequest consultant_id={self.consultant_id} file_id={self.file_id} status={self.status}>'


class CryptoLog(db.Model):
    """Model for logging cryptographic operations"""
    __tablename__ = 'crypto_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    operation = db.Column(db.String(50), nullable=False)
    # Operations: keypair_generated, key_wrapped, key_unwrapped, 
    #             private_key_decrypted, access_granted, access_revoked
    
    details = db.Column(db.Text, nullable=True)
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
    
    user = db.relationship('User', backref='crypto_logs')
    
    def __repr__(self):
        return f'<CryptoLog {self.operation} by user {self.user_id}>'