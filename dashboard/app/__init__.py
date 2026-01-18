"""Flask application initialization."""
from flask import Flask
from flask_cors import CORS
from config import Config
import sys


def validate_config(config):
    """Validate that all required configuration variables are set.
    
    Args:
        config: Flask configuration object
        
    Raises:
        SystemExit: If any required configuration is missing
    """
    required_vars = {
        'SECRET_KEY': 'Flask secret key for session encryption',
        'OAUTH2_CLIENT_ID': 'OAuth2 client ID',
        'OAUTH2_CLIENT_SECRET': 'OAuth2 client secret',
        'OAUTH2_AUTHORIZE_URL': 'OAuth2 authorization endpoint URL',
        'OAUTH2_TOKEN_URL': 'OAuth2 token endpoint URL',
        'OAUTH2_REDIRECT_URI': 'OAuth2 callback redirect URI',
        'OAUTH2_SCOPE': 'OAuth2 scope',
        'CORS_ALLOWED_ORIGINS': 'CORS allowed origins (comma-separated)',
        'CATALOG_PATH': 'Path to catalog directory'
    }
    
    missing = []
    for var, description in required_vars.items():
        value = config.get(var)
        if not value or (isinstance(value, list) and not value):
            missing.append(f"  - {var}: {description}")
    
    if missing:
        print("\n" + "="*80)
        print("ERROR: Missing required environment variables!")
        print("="*80)
        print("\nThe following environment variables must be set:\n")
        print("\n".join(missing))
        print("\nPlease configure these variables in docker-compose.yml or your environment.")
        print("="*80 + "\n")
        sys.exit(1)
    
    # Log configuration values (mask sensitive data)
    print("\n" + "="*80)
    print("Dashboard Configuration Loaded Successfully")
    print("="*80)
    for var in required_vars.keys():
        value = config.get(var)
        # Mask sensitive values
        if 'SECRET' in var or 'PASSWORD' in var:
            display_value = '***MASKED***'
        elif isinstance(value, list):
            display_value = ', '.join(value) if value else '[]'
        else:
            display_value = str(value)
        print(f"  {var}: {display_value}")
    print("="*80 + "\n")


def create_app(config_class=Config):
    """Create and configure Flask application.
    
    Args:
        config_class: Configuration class to use
        
    Returns:
        Configured Flask application
    """
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Validate configuration
    validate_config(app.config)
    
    # Enable CORS for all routes (OAuth2 requires cross-origin requests)
    # CRITICAL: When using credentials, cannot use origins="*", must specify exact origins
    print(f"[CORS Config] Allowed origins: {app.config['CORS_ALLOWED_ORIGINS']}")
    print(f"[CORS Config] Supports credentials: True")
    
    CORS(app, 
         resources={r"/*": {"origins": app.config['CORS_ALLOWED_ORIGINS']}}, 
         supports_credentials=True)
    
    # Register routes
    from app import routes
    app.register_blueprint(routes.bp)
    
    @app.after_request
    def log_response_headers(response):
        """Log Set-Cookie headers for debugging."""
        if 'Set-Cookie' in response.headers:
            print(f"[Cookie Debug] Set-Cookie: {response.headers.getlist('Set-Cookie')}")
        return response
    
    return app
