"""Flask application configuration."""
import os
from pathlib import Path

class Config:
    """Base configuration."""
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY')
    
    # OAuth2 settings
    OAUTH2_CLIENT_ID = os.environ.get('OAUTH2_CLIENT_ID')
    OAUTH2_CLIENT_SECRET = os.environ.get('OAUTH2_CLIENT_SECRET')
    OAUTH2_AUTHORIZE_URL = os.environ.get('OAUTH2_AUTHORIZE_URL')
    OAUTH2_TOKEN_URL = os.environ.get('OAUTH2_TOKEN_URL')
    OAUTH2_REDIRECT_URI = os.environ.get('OAUTH2_REDIRECT_URI')
    OAUTH2_SCOPE = os.environ.get('OAUTH2_SCOPE')
    
    # Session configuration for OAuth2
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'  # Allow cookies in OAuth2 redirects
    SESSION_COOKIE_NAME = 'ems_dashboard_session'
    
    # CORS configuration
    # Comma-separated list of allowed origins for CORS
    cors_origins = os.environ.get('CORS_ALLOWED_ORIGINS', '')
    CORS_ALLOWED_ORIGINS = cors_origins.split(',') if cors_origins else []
    
    # Paths
    CATALOG_PATH = Path(os.environ.get('CATALOG_PATH', '/app/priv/catalog'))
    
    # Application settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    JSON_SORT_KEYS = False
    JSONIFY_PRETTYPRINT_REGULAR = True
    
    # Backup settings
    CREATE_BACKUPS = True
    BACKUP_SUFFIX = '.bak'
