"""Add asymmetric key exchange feature

Revision ID: 001
Revises: 
Create Date: 2024-11-25 10:00:00.000000

This migration adds support for asymmetric key exchange between organizations and consultants.

Changes:
1. Add role, public_key, public_key_fingerprint, and key_generated_at columns to users table
2. Create access_requests table for tracking access requests
3. Create crypto_logs table for logging cryptographic operations

Requirements: 1.1, 2.4, 11.1
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Apply the migration"""
    
    # For SQLite, we need to add columns one at a time
    # Add role column with default value
    op.add_column('users', sa.Column('role', sa.String(length=20), nullable=False, server_default='organization'))
    
    # Add public key columns
    op.add_column('users', sa.Column('public_key', sa.LargeBinary(), nullable=True))
    op.add_column('users', sa.Column('public_key_fingerprint', sa.String(length=64), nullable=True))
    op.add_column('users', sa.Column('key_generated_at', sa.DateTime(), nullable=True))
    
    # Create access_requests table
    op.create_table(
        'access_requests',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('consultant_id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('file_id', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='pending'),
        sa.Column('wrapped_symmetric_key', sa.LargeBinary(), nullable=True),
        sa.Column('requested_at', sa.DateTime(), nullable=False),
        sa.Column('processed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['consultant_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['file_id'], ['encrypted_files.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('consultant_id', 'file_id', name='unique_access_request')
    )
    
    # Create indexes for access_requests
    op.create_index('ix_access_requests_consultant_id', 'access_requests', ['consultant_id'], unique=False)
    op.create_index('ix_access_requests_organization_id', 'access_requests', ['organization_id'], unique=False)
    op.create_index('ix_access_requests_file_id', 'access_requests', ['file_id'], unique=False)
    op.create_index('ix_access_requests_status', 'access_requests', ['status'], unique=False)
    
    # Create crypto_logs table
    op.create_table(
        'crypto_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('operation', sa.String(length=50), nullable=False),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=True, server_default='1'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for crypto_logs
    op.create_index('ix_crypto_logs_user_id', 'crypto_logs', ['user_id'], unique=False)
    op.create_index('ix_crypto_logs_operation', 'crypto_logs', ['operation'], unique=False)
    op.create_index('ix_crypto_logs_timestamp', 'crypto_logs', ['timestamp'], unique=False)


def downgrade() -> None:
    """Rollback the migration"""
    
    # Drop crypto_logs table and its indexes
    op.drop_index('ix_crypto_logs_timestamp', table_name='crypto_logs')
    op.drop_index('ix_crypto_logs_operation', table_name='crypto_logs')
    op.drop_index('ix_crypto_logs_user_id', table_name='crypto_logs')
    op.drop_table('crypto_logs')
    
    # Drop access_requests table and its indexes
    op.drop_index('ix_access_requests_status', table_name='access_requests')
    op.drop_index('ix_access_requests_file_id', table_name='access_requests')
    op.drop_index('ix_access_requests_organization_id', table_name='access_requests')
    op.drop_index('ix_access_requests_consultant_id', table_name='access_requests')
    op.drop_table('access_requests')
    
    # Note: SQLite doesn't support DROP COLUMN in older versions
    # The columns will remain but be unused after downgrade
    # For complete cleanup, use batch mode with table recreation
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('key_generated_at')
        batch_op.drop_column('public_key_fingerprint')
        batch_op.drop_column('public_key')
        batch_op.drop_column('role')
