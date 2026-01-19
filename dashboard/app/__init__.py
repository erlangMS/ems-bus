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
        'CORS_ALLOWED_ORIGINS': 'CORS allowed origins (comma-separated)',
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
    
    # Display basic config
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
    
    # Display OAuth2 config (already validated in Config.__init__)
    print(f"  OAUTH2_CLIENT_ID: {config.get('OAUTH2_CLIENT_ID')}")
    print(f"  OAUTH2_CLIENT_SECRET: ***MASKED***")
    print(f"  OAUTH2_AUTHORIZE_URL: {config.get('OAUTH2_AUTHORIZE_URL')}")
    print(f"  OAUTH2_TOKEN_URL: {config.get('OAUTH2_TOKEN_URL')}")
    print(f"  OAUTH2_REDIRECT_URI: {config.get('OAUTH2_REDIRECT_URI')}")
    print(f"  OAUTH2_SCOPE: {config.get('OAUTH2_SCOPE')}")
    print(f"  VERIFY_SSL: {config.get('VERIFY_SSL', True)}")
    print(f"  SESSION_COOKIE_SECURE: {config.get('SESSION_COOKIE_SECURE')}")
    print(f"  SESSION_COOKIE_SAMESITE: {config.get('SESSION_COOKIE_SAMESITE')}")
    print(f"  SESSION_COOKIE_DOMAIN: {config.get('SESSION_COOKIE_DOMAIN')}")
    
    # Display catalog paths
    catalog_paths = config.get('CATALOG_PATHS', [])
    if len(catalog_paths) > 1:
        print(f"  CATALOG_PATHS: {', '.join(str(p) for p in catalog_paths)}")
    else:
        print(f"  CATALOG_PATH: {config.get('CATALOG_PATH')}")
    
    print("="*80 + "\n")


def create_app(config_class=Config):
    """Create and configure Flask application.
    
    Args:
        config_class: Configuration class to use
        
    Returns:
        Configured Flask application
    """
    app = Flask(__name__)
    
    # Create config instance (this validates OAuth2 and reads instance vars)
    config_instance = config_class()
    
    # Load configuration from INSTANCE to evaluate properties
    app.config.from_object(config_instance)
    
    # Copy instance variables to Flask config (redundant if using from_object(instance) but safe to keep)
    app.config['HTTP_PORT'] = config_instance.HTTP_PORT
    app.config['HTTPS_PORT'] = config_instance.HTTPS_PORT
    app.config['VERIFY_SSL'] = config_instance.VERIFY_SSL
    app.config['USE_SSL'] = config_instance.USE_SSL
    app.config['SSL_CERT_FILE'] = config_instance.SSL_CERT_FILE
    app.config['SSL_KEY_FILE'] = config_instance.SSL_KEY_FILE
    
    # Explicitly set the session cookie secure value from the evaluated property
    app.config['SESSION_COOKIE_SECURE'] = config_instance.SESSION_COOKIE_SECURE
    
    # Validate configuration
    validate_config(app.config)
    
    # Enable CORS for all routes (OAuth2 requires cross-origin requests)
    # CRITICAL: When using credentials, cannot use origins="*", must specify exact origins
    CORS(app, 
         resources={r"/*": {"origins": app.config['CORS_ALLOWED_ORIGINS']}}, 
         supports_credentials=True)
    
    # Register routes
    from app import routes
    app.register_blueprint(routes.bp)
    
    return app
