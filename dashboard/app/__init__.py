"""Flask application initialization."""
from flask import Flask
from config import Config


def create_app(config_class=Config):
    """Create and configure Flask application.
    
    Args:
        config_class: Configuration class to use
        
    Returns:
        Configured Flask application
    """
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Register routes
    from app import routes
    app.register_blueprint(routes.bp)
    
    return app
