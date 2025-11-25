import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    # Debug mode should be disabled in production.
    # Set FLASK_DEBUG=1 environment variable to enable debug mode for development.
    debug_mode = os.environ.get('FLASK_DEBUG', '0').lower() in ('1', 'true', 'yes')
    app.run(debug=debug_mode, host='0.0.0.0', port=8080)