"""
Unit Tests for Role-Based Access Control Decorators

This module contains unit tests for the @organization_required and
@consultant_required decorators.
"""

import pytest
from tests import create_test_app
from app.models import User, UserRole
from app.decorators import organization_required, consultant_required
from flask import Flask
from flask_login import login_user


class TestAccessControlDecorators:
    """Unit tests for access control decorators"""
    
    @pytest.fixture
    def app_and_db(self):
        """Create test app with database"""
        app, db = create_test_app()
        
        with app.app_context():
            db.create_all()
            yield app, db
            db.drop_all()
    
    @pytest.fixture
    def client(self, app_and_db):
        """Create test client"""
        app, db = app_and_db
        return app.test_client()
    
    @pytest.fixture
    def organization_user(self, app_and_db):
        """Create an organization user"""
        app, db = app_and_db
        
        with app.app_context():
            user = User(
                username='org_user',
                email='org@example.com',
                role=UserRole.ORGANIZATION
            )
            user.set_password('password123')
            db.session.add(user)
            db.session.commit()
            
            # Return user ID to avoid detached instance issues
            user_id = user.id
            
        # Fetch fresh instance in new context
        with app.app_context():
            return User.query.get(user_id)
    
    @pytest.fixture
    def consultant_user(self, app_and_db):
        """Create a consultant user"""
        app, db = app_and_db
        
        with app.app_context():
            user = User(
                username='consultant_user',
                email='consultant@example.com',
                role=UserRole.CONSULTANT
            )
            user.set_password('password123')
            db.session.add(user)
            db.session.commit()
            
            # Return user ID to avoid detached instance issues
            user_id = user.id
            
        # Fetch fresh instance in new context
        with app.app_context():
            return User.query.get(user_id)
    
    def test_organization_decorator_allows_organization_users(self, app_and_db, organization_user):
        """Test organization decorator allows organization users"""
        app, db = app_and_db
        
        with app.app_context():
            # Refresh user in current session
            user = User.query.get(organization_user.id)
            
            with app.test_request_context():
                login_user(user)
                
                @organization_required
                def test_function():
                    return 'success'
                
                result = test_function()
                assert result == 'success', \
                    "Organization user should be allowed to access organization-required function"
    
    def test_organization_decorator_blocks_consultant_users(self, app_and_db, consultant_user):
        """Test organization decorator blocks consultant users"""
        app, db = app_and_db
        
        with app.app_context():
            # Refresh user in current session
            user = User.query.get(consultant_user.id)
            
            with app.test_request_context():
                login_user(user)
                
                @organization_required
                def test_function():
                    return 'success'
                
                result = test_function()
                # Should return a redirect response
                assert hasattr(result, 'status_code'), \
                    "Decorator should return a response object"
                assert result.status_code == 302, \
                    "Consultant user should be redirected (302) when accessing organization-required function"
    
    def test_consultant_decorator_allows_consultant_users(self, app_and_db, consultant_user):
        """Test consultant decorator allows consultant users"""
        app, db = app_and_db
        
        with app.app_context():
            # Refresh user in current session
            user = User.query.get(consultant_user.id)
            
            with app.test_request_context():
                login_user(user)
                
                @consultant_required
                def test_function():
                    return 'success'
                
                result = test_function()
                assert result == 'success', \
                    "Consultant user should be allowed to access consultant-required function"
    
    def test_consultant_decorator_blocks_organization_users(self, app_and_db, organization_user):
        """Test consultant decorator blocks organization users"""
        app, db = app_and_db
        
        with app.app_context():
            # Refresh user in current session
            user = User.query.get(organization_user.id)
            
            with app.test_request_context():
                login_user(user)
                
                @consultant_required
                def test_function():
                    return 'success'
                
                result = test_function()
                # Should return a redirect response
                assert hasattr(result, 'status_code'), \
                    "Decorator should return a response object"
                assert result.status_code == 302, \
                    "Organization user should be redirected (302) when accessing consultant-required function"
    
    def test_organization_decorator_redirects_unauthenticated_users(self, app_and_db):
        """Test organization decorator redirects unauthenticated users"""
        app, db = app_and_db
        
        with app.app_context():
            with app.test_request_context():
                # Don't login any user
                
                @organization_required
                def test_function():
                    return 'success'
                
                result = test_function()
                # Should return a redirect response
                assert hasattr(result, 'status_code'), \
                    "Decorator should return a response object"
                assert result.status_code == 302, \
                    "Unauthenticated user should be redirected (302)"
    
    def test_consultant_decorator_redirects_unauthenticated_users(self, app_and_db):
        """Test consultant decorator redirects unauthenticated users"""
        app, db = app_and_db
        
        with app.app_context():
            with app.test_request_context():
                # Don't login any user
                
                @consultant_required
                def test_function():
                    return 'success'
                
                result = test_function()
                # Should return a redirect response
                assert hasattr(result, 'status_code'), \
                    "Decorator should return a response object"
                assert result.status_code == 302, \
                    "Unauthenticated user should be redirected (302)"
    
    def test_decorators_preserve_function_metadata(self, app_and_db):
        """Test that decorators preserve function metadata using functools.wraps"""
        app, db = app_and_db
        
        with app.app_context():
            @organization_required
            def org_function():
                """Organization function docstring"""
                return 'org'
            
            @consultant_required
            def consultant_function():
                """Consultant function docstring"""
                return 'consultant'
            
            # Verify function names are preserved
            assert org_function.__name__ == 'org_function', \
                "Decorator should preserve function name"
            assert consultant_function.__name__ == 'consultant_function', \
                "Decorator should preserve function name"
            
            # Verify docstrings are preserved
            assert org_function.__doc__ == "Organization function docstring", \
                "Decorator should preserve function docstring"
            assert consultant_function.__doc__ == "Consultant function docstring", \
                "Decorator should preserve function docstring"


def run_decorator_tests():
    """Run all decorator tests"""
    print("Running Decorator Tests...")
    print("=" * 50)
    
    # Run tests with pytest
    exit_code = pytest.main([
        __file__,
        '-v',
        '--tb=short',
        '--no-header'
    ])
    
    return exit_code == 0


if __name__ == '__main__':
    success = run_decorator_tests()
    if success:
        print("\n✅ All decorator tests passed!")
    else:
        print("\n❌ Some decorator tests failed!")
    
    exit(0 if success else 1)
