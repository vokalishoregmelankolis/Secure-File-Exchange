from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    
    # Configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'secure-vault-dev-key-2025-bakso-kamil')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///secure_file_exchange.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
    app.config['ENCRYPTED_FOLDER'] = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'encrypted_files')
    app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))
    
    # MongoDB Configuration for Private Key Storage
    app.config['MONGODB_URI'] = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
    app.config['MONGODB_DB_NAME'] = os.getenv('MONGODB_DB_NAME', 'secure_file_exchange_keys')
    
    # Session Configuration - Enhanced Security
    app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_SECURE', 'False').lower() == 'true'  # HTTPS in production
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent XSS attacks
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
    app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 24 hours
    
    # Force session cookie security using Flask's session interface
    from flask.sessions import SecureCookieSessionInterface
    
    class SecureSessionInterface(SecureCookieSessionInterface):
        def get_cookie_secure(self, app):
            return app.config.get('SESSION_COOKIE_SECURE', False)
            
        def get_cookie_httponly(self, app):
            return app.config.get('SESSION_COOKIE_HTTPONLY', True)
            
        def get_cookie_samesite(self, app):
            return app.config.get('SESSION_COOKIE_SAMESITE', 'Lax')
    
    app.session_interface = SecureSessionInterface()
    
    # Additional security headers
    @app.after_request
    def set_security_headers(response):
        # Ensure session cookies have proper security flags
        if 'Set-Cookie' in response.headers:
            cookie_header = response.headers.get('Set-Cookie', '')
            if 'session=' in cookie_header:
                # Force HttpOnly if not present
                if 'HttpOnly' not in cookie_header:
                    cookie_header += '; HttpOnly'
                # Add Secure flag if configured
                if app.config.get('SESSION_COOKIE_SECURE') and 'Secure' not in cookie_header:
                    cookie_header += '; Secure'
                response.headers['Set-Cookie'] = cookie_header
                
        # Additional security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        return response
    
    # CSRF Configuration (disabled for development with Simple Browser)
    app.config['WTF_CSRF_ENABLED'] = False  # Disabled for Simple Browser compatibility
    app.config['WTF_CSRF_TIME_LIMIT'] = None
    
    # Create upload directories if they don't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['ENCRYPTED_FOLDER'], exist_ok=True)
    
    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    
    # Login manager settings
    login_manager.login_view = 'main.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    # User loader
    from app.models import User
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Register blueprints
    from app.routes import main
    app.register_blueprint(main)
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    return app