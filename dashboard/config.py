"""Flask application configuration."""
import os
from pathlib import Path

class Config:
    """Base configuration."""
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Authentication
    BASIC_AUTH_USERNAME = os.environ.get('CATALOG_USERNAME', 'admin')
    BASIC_AUTH_PASSWORD = os.environ.get('CATALOG_PASSWORD', 'admin123')
    
    # Paths
    CATALOG_PATH = Path(os.environ.get('CATALOG_PATH', '/app/priv/catalog'))
    
    # Application settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    JSON_SORT_KEYS = False
    JSONIFY_PRETTYPRINT_REGULAR = True
    
    # Backup settings
    CREATE_BACKUPS = True
    BACKUP_SUFFIX = '.bak'
