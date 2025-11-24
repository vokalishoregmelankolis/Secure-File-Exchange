"""
Role-based access control decorators for the Secure File Exchange System.

This module provides decorators to enforce role-based authorization
for organization and consultant users.
"""

from functools import wraps
from flask import flash, redirect, url_for, abort
from flask_login import current_user
from app.models import UserRole


def organization_required(f):
    """
    Decorator to require organization role for a route.
    
    This decorator verifies that the current user has the ORGANIZATION role.
    If the user is not authenticated or does not have the required role,
    they are redirected to the login page with an appropriate error message.
    
    Usage:
        @main.route('/organization-only')
        @login_required
        @organization_required
        def organization_view():
            return "Organization content"
    
    Requirements: 1.3, 1.4
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is authenticated
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('main.login'))
        
        # Check if user has organization role
        if current_user.role != UserRole.ORGANIZATION:
            flash('Access denied. This page is only available to organization users.', 'danger')
            return redirect(url_for('main.dashboard'))
        
        return f(*args, **kwargs)
    
    return decorated_function


def consultant_required(f):
    """
    Decorator to require consultant role for a route.
    
    This decorator verifies that the current user has the CONSULTANT role.
    If the user is not authenticated or does not have the required role,
    they are redirected to the login page with an appropriate error message.
    
    Usage:
        @main.route('/consultant-only')
        @login_required
        @consultant_required
        def consultant_view():
            return "Consultant content"
    
    Requirements: 1.3, 1.5
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is authenticated
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('main.login'))
        
        # Check if user has consultant role
        if current_user.role != UserRole.CONSULTANT:
            flash('Access denied. This page is only available to consultant users.', 'danger')
            return redirect(url_for('main.dashboard'))
        
        return f(*args, **kwargs)
    
    return decorated_function


def role_required(required_role):
    """
    Generic decorator factory to require a specific role for a route.
    
    This is a more flexible decorator that can be used to require any role.
    
    Args:
        required_role: The UserRole enum value required for access
    
    Usage:
        @main.route('/custom-role')
        @login_required
        @role_required(UserRole.ORGANIZATION)
        def custom_view():
            return "Custom content"
    
    Requirements: 1.3
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if user is authenticated
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('main.login'))
            
            # Check if user has required role
            if current_user.role != required_role:
                flash(f'Access denied. This page requires {required_role.value} role.', 'danger')
                return redirect(url_for('main.dashboard'))
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    return decorator
