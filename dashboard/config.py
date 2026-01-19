"""Flask application configuration."""
import os
import sys
from pathlib import Path

class Config:
    """Base configuration."""
    
    def __init__(self):
        """Initialize and validate configuration."""
        # Read port configuration
        self.HTTP_PORT = os.environ.get('HTTP_PORT')
        self.HTTPS_PORT = os.environ.get('HTTPS_PORT')
        
        # SSL/TLS configuration
        self.SSL_CERT_FILE = os.environ.get('SSL_CERT_FILE')
        self.SSL_KEY_FILE = os.environ.get('SSL_KEY_FILE')
        
        # SSL verification (for OAuth2 requests to external servers)
        # Set to 'false' to disable SSL verification (useful for self-signed certificates)
        verify_ssl_str = os.environ.get('VERIFY_SSL', 'true').lower()
        self.VERIFY_SSL = verify_ssl_str not in ('false', '0', 'no', 'off')
        
        # Check if SSL is properly configured
        self.USE_SSL = bool(
            self.SSL_CERT_FILE and 
            self.SSL_KEY_FILE and 
            Path(self.SSL_CERT_FILE).exists() and 
            Path(self.SSL_KEY_FILE).exists()
        )
        
        # Validate required OAuth2 settings
        self._validate_oauth2()
    
    def _validate_oauth2(self):
        """Validate that all required configuration variables are set."""
        # OAuth2 required vars
        required_oauth2_vars = {
            'OAUTH2_CLIENT_ID': self.OAUTH2_CLIENT_ID,
            'OAUTH2_CLIENT_SECRET': self.OAUTH2_CLIENT_SECRET,
            'OAUTH2_AUTHORIZE_URL': self.OAUTH2_AUTHORIZE_URL,
            'OAUTH2_TOKEN_URL': self.OAUTH2_TOKEN_URL,
            'OAUTH2_REDIRECT_URI': self.OAUTH2_REDIRECT_URI,
            'OAUTH2_SCOPE': self.OAUTH2_SCOPE,
        }
        
        # Other required vars
        required_other_vars = {
            'FLASK_SESSION_SECRET_KEY': self.SECRET_KEY,
            'CATALOG_PATH': os.environ.get('CATALOG_PATH'),
            'CORS_ALLOWED_ORIGINS': os.environ.get('CORS_ALLOWED_ORIGINS'),
        }
        
        missing = []
        for var, value in {**required_oauth2_vars, **required_other_vars}.items():
            if not value:
                missing.append(var)
        
        if missing:
            print("\n" + "="*80)
            print("ERROR: Missing required configuration!")
            print("="*80)
            print("\nThe following environment variables must be set:\n")
            for var in missing:
                print(f"  - {var}")
            print("\nPlease configure these variables in docker-compose.yml or your environment.")
            print("="*80 + "\n")
            sys.exit(1)
    
    # Flask settings
    SECRET_KEY = os.environ.get('FLASK_SESSION_SECRET_KEY')
    
    # OAuth2 settings
    OAUTH2_CLIENT_ID = os.environ.get('OAUTH2_CLIENT_ID')
    OAUTH2_CLIENT_SECRET = os.environ.get('OAUTH2_CLIENT_SECRET')
    OAUTH2_AUTHORIZE_URL = os.environ.get('OAUTH2_AUTHORIZE_URL')
    OAUTH2_TOKEN_URL = os.environ.get('OAUTH2_TOKEN_URL')
    OAUTH2_REDIRECT_URI = os.environ.get('OAUTH2_REDIRECT_URI')
    OAUTH2_SCOPE = os.environ.get('OAUTH2_SCOPE')
    
    # Session configuration for OAuth2
    @property
    def SESSION_COOKIE_SECURE(self):
        """Enable secure cookies when using HTTPS."""
        return self.USE_SSL
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'  # Allow cookies in OAuth2 redirects
    SESSION_COOKIE_NAME = 'ems_dashboard_session'
    
    # CORS configuration
    # Comma-separated list of allowed origins for CORS
    cors_origins = os.environ.get('CORS_ALLOWED_ORIGINS', '')
    CORS_ALLOWED_ORIGINS = cors_origins.split(',') if cors_origins else []
    
    # Catalog paths - supports comma-separated list of paths
    _catalog_path_str = os.environ.get('CATALOG_PATH', '/app/priv/catalog')
    CATALOG_PATHS = [Path(p.strip()) for p in _catalog_path_str.split(',') if p.strip()]
    # Keep CATALOG_PATH for backward compatibility (first path in list)
    CATALOG_PATH = CATALOG_PATHS[0] if CATALOG_PATHS else Path('/app/priv/catalog')
    
    # Application settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    JSON_SORT_KEYS = False
    JSONIFY_PRETTYPRINT_REGULAR = True
    
    # Backup settings
    CREATE_BACKUPS = True
    BACKUP_SUFFIX = '.bak'
