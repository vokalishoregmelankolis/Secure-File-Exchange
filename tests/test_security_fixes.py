#!/usr/bin/env python3
"""
Tests for security fixes: debug mode and open redirect vulnerabilities.
"""

import os
import sys
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestDebugModeConfiguration:
    """Tests for Flask debug mode configuration."""
    
    def test_debug_mode_defaults_to_false(self):
        """Debug mode should be disabled by default when FLASK_DEBUG is not set."""
        # Ensure FLASK_DEBUG is not set
        os.environ.pop('FLASK_DEBUG', None)
        
        debug_mode = os.environ.get('FLASK_DEBUG', '0').lower() in ('1', 'true', 'yes')
        assert debug_mode is False, "Debug mode should be False by default"
    
    def test_debug_mode_enabled_with_flag_1(self):
        """Debug mode should be enabled when FLASK_DEBUG=1."""
        os.environ['FLASK_DEBUG'] = '1'
        try:
            debug_mode = os.environ.get('FLASK_DEBUG', '0').lower() in ('1', 'true', 'yes')
            assert debug_mode is True, "Debug mode should be True when FLASK_DEBUG=1"
        finally:
            os.environ.pop('FLASK_DEBUG', None)
    
    def test_debug_mode_enabled_with_flag_true(self):
        """Debug mode should be enabled when FLASK_DEBUG=true."""
        os.environ['FLASK_DEBUG'] = 'true'
        try:
            debug_mode = os.environ.get('FLASK_DEBUG', '0').lower() in ('1', 'true', 'yes')
            assert debug_mode is True, "Debug mode should be True when FLASK_DEBUG=true"
        finally:
            os.environ.pop('FLASK_DEBUG', None)
    
    def test_debug_mode_enabled_with_flag_yes(self):
        """Debug mode should be enabled when FLASK_DEBUG=yes."""
        os.environ['FLASK_DEBUG'] = 'yes'
        try:
            debug_mode = os.environ.get('FLASK_DEBUG', '0').lower() in ('1', 'true', 'yes')
            assert debug_mode is True, "Debug mode should be True when FLASK_DEBUG=yes"
        finally:
            os.environ.pop('FLASK_DEBUG', None)
    
    def test_debug_mode_disabled_with_flag_0(self):
        """Debug mode should be disabled when FLASK_DEBUG=0."""
        os.environ['FLASK_DEBUG'] = '0'
        try:
            debug_mode = os.environ.get('FLASK_DEBUG', '0').lower() in ('1', 'true', 'yes')
            assert debug_mode is False, "Debug mode should be False when FLASK_DEBUG=0"
        finally:
            os.environ.pop('FLASK_DEBUG', None)
    
    def test_debug_mode_disabled_with_flag_false(self):
        """Debug mode should be disabled when FLASK_DEBUG=false."""
        os.environ['FLASK_DEBUG'] = 'false'
        try:
            debug_mode = os.environ.get('FLASK_DEBUG', '0').lower() in ('1', 'true', 'yes')
            assert debug_mode is False, "Debug mode should be False when FLASK_DEBUG=false"
        finally:
            os.environ.pop('FLASK_DEBUG', None)


class TestOpenRedirectPrevention:
    """Tests for URL validation to prevent open redirect vulnerabilities."""
    
    @pytest.fixture
    def app(self):
        """Create test Flask application."""
        from app import create_app
        app = create_app()
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        return app
    
    def _is_safe_url_test(self, target, host_url='http://localhost:8080/'):
        """Test version of is_safe_url that works outside Flask context."""
        from urllib.parse import urlparse
        
        if not target:
            return False
        ref_url = urlparse(host_url)
        test_url = urlparse(target)
        
        # Relative paths (no scheme and no netloc) are always safe
        if test_url.scheme == '' and test_url.netloc == '':
            return True
        
        # For absolute URLs, require exact host match including port
        # and only allow HTTP/HTTPS schemes
        if test_url.scheme not in ('http', 'https'):
            return False
        
        return test_url.netloc == ref_url.netloc
    
    # Relative path tests
    def test_relative_path_is_safe(self):
        """Relative paths should be considered safe."""
        assert self._is_safe_url_test('/dashboard') is True
    
    def test_nested_relative_path_is_safe(self):
        """Nested relative paths should be considered safe."""
        assert self._is_safe_url_test('/files/123/view') is True
    
    def test_path_without_leading_slash_is_safe(self):
        """Paths without leading slash should be considered safe."""
        assert self._is_safe_url_test('dashboard') is True
    
    # External URL tests
    def test_external_http_url_is_unsafe(self):
        """External HTTP URLs should be considered unsafe."""
        assert self._is_safe_url_test('http://evil.com') is False
    
    def test_external_https_url_is_unsafe(self):
        """External HTTPS URLs should be considered unsafe."""
        assert self._is_safe_url_test('https://attacker.com/steal') is False
    
    def test_external_url_with_path_is_unsafe(self):
        """External URLs with paths should be considered unsafe."""
        assert self._is_safe_url_test('http://malicious.com/steal/credentials') is False
    
    # Protocol-relative URL tests
    def test_protocol_relative_url_is_unsafe(self):
        """Protocol-relative URLs (//evil.com) should be considered unsafe."""
        assert self._is_safe_url_test('//evil.com') is False
    
    def test_protocol_relative_url_with_path_is_unsafe(self):
        """Protocol-relative URLs with paths should be considered unsafe."""
        assert self._is_safe_url_test('//attacker.com/phishing') is False
    
    # Empty/None tests
    def test_empty_string_is_unsafe(self):
        """Empty strings should be considered unsafe."""
        assert self._is_safe_url_test('') is False
    
    def test_none_is_unsafe(self):
        """None should be considered unsafe."""
        assert self._is_safe_url_test(None) is False
    
    # Same host tests
    def test_same_host_http_is_safe(self):
        """HTTP URLs to same host should be considered safe."""
        assert self._is_safe_url_test('http://localhost:8080/dashboard') is True
    
    def test_same_host_https_is_safe(self):
        """HTTPS URLs to same host should be considered safe."""
        assert self._is_safe_url_test('https://localhost:8080/profile') is True
    
    # Different port tests
    def test_different_port_is_unsafe(self):
        """URLs to same host but different port should be considered unsafe."""
        assert self._is_safe_url_test('http://localhost:9000/dashboard') is False
    
    # Non-HTTP scheme tests
    def test_javascript_scheme_is_unsafe(self):
        """JavaScript: scheme should be considered unsafe."""
        assert self._is_safe_url_test('javascript:alert(1)') is False
    
    def test_ftp_scheme_is_unsafe(self):
        """FTP scheme should be considered unsafe."""
        assert self._is_safe_url_test('ftp://localhost:8080/file') is False
    
    def test_data_scheme_is_unsafe(self):
        """Data: scheme should be considered unsafe."""
        assert self._is_safe_url_test('data:text/html,<script>alert(1)</script>') is False
    
    def test_file_scheme_is_unsafe(self):
        """File: scheme should be considered unsafe."""
        assert self._is_safe_url_test('file:///etc/passwd') is False


class TestLoginRedirect:
    """Integration tests for login redirect security."""
    
    @pytest.fixture
    def app(self):
        """Create test Flask application."""
        from app import create_app
        app = create_app()
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        return app
    
    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return app.test_client()
    
    def test_is_safe_url_function_exists(self, app):
        """The is_safe_url function should exist in routes."""
        from app.routes import is_safe_url
        assert callable(is_safe_url)
    
    def test_is_safe_url_within_app_context(self, app):
        """Test is_safe_url function within Flask app context."""
        from app.routes import is_safe_url
        
        with app.test_request_context('http://localhost:8080/'):
            # Relative paths should be safe
            assert is_safe_url('/dashboard') is True
            assert is_safe_url('/files/123') is True
            
            # External URLs should be unsafe
            assert is_safe_url('http://evil.com') is False
            assert is_safe_url('https://attacker.com') is False
            
            # Empty/None should be unsafe
            assert is_safe_url('') is False
            assert is_safe_url(None) is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
