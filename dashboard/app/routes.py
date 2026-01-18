"""Flask routes for catalog management."""
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, session
from functools import wraps
from app.catalog_service import CatalogService
from pathlib import Path


bp = Blueprint('main', __name__)


def check_auth(username, password):
    """Check if username/password combination is valid."""
    return (username == current_app.config['BASIC_AUTH_USERNAME'] and
            password == current_app.config['BASIC_AUTH_PASSWORD'])


def authenticate():
    """Send 401 response for authentication."""
    return ('Authentication required', 401, {
        'WWW-Authenticate': 'Basic realm="Catalog Manager"'
    })


def requires_auth(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


def get_catalog_service():
    """Get CatalogService instance."""
    catalog_path = current_app.config['CATALOG_PATH']
    return CatalogService(
        catalog_path,
        current_app.config['CREATE_BACKUPS']
    )


@bp.route('/')
@requires_auth
def index():
    """Dashboard with catalog overview."""
    try:
        catalog_service = get_catalog_service()
        catalog_path = current_app.config['CATALOG_PATH']
        
        # Get main catalog file
        main_catalog = catalog_path / 'catalog.json'
        
        # Get stats for the catalog
        catalog_stats = {}
        try:
            stats = catalog_service.get_catalog_stats('catalog.json')
            catalog_stats['ems-bus'] = stats
        except Exception as e:
            catalog_stats['ems-bus'] = {
                'error': str(e),
                'total_services': 0,
                'by_type': {},
                'by_owner': {},
                'unique_files': 0
            }
        
        return render_template('index.html', 
                             catalog_paths={'ems-bus': 'catalog.json'},
                             catalog_stats=catalog_stats)
    
    except Exception as e:
        flash(f'Error loading catalog: {e}', 'error')
        return render_template('error.html', error=str(e)), 500


@bp.route('/catalogs')
@requires_auth
def list_catalogs():
    """List all available catalogs."""
    try:
        return render_template('catalogs.html', catalog_paths={'ems-bus': 'catalog.json'})
    
    except Exception as e:
        flash(f'Error loading catalogs: {e}', 'error')
        return render_template('error.html', error=str(e)), 500


@bp.route('/catalog/<catalog_name>')
@requires_auth
def view_catalog(catalog_name):
    """View specific catalog with all services."""
    try:
        catalog_service = get_catalog_service()
        
        # Load all services recursively
        services = catalog_service.list_catalogs_recursive('catalog.json')
        
        # Get statistics
        stats = catalog_service.get_catalog_stats('catalog.json')
        
        return render_template('catalog_view.html',
                             catalog_name=catalog_name,
                             catalog_path='catalog.json',
                             services=services,
                             stats=stats)
    
    except Exception as e:
        flash(f'Error loading catalog: {e}', 'error')
        return render_template('error.html', error=str(e)), 500


@bp.route('/catalog/<catalog_name>/file/<path:file_path>')
@requires_auth
def view_catalog_file(catalog_name, file_path):
    """View specific catalog file."""
    try:
        catalog_service = get_catalog_service()
        data, full_path = catalog_service.load_catalog(file_path)
        
        import json
        json_content = json.dumps(data, indent=2, ensure_ascii=False)
        
        return render_template('catalog_file.html',
                             catalog_name=catalog_name,
                             file_path=file_path,
                             full_path=str(full_path),
                             data=data,
                             json_content=json_content)
    
    except Exception as e:
        flash(f'Error loading catalog file: {e}', 'error')
        return redirect(url_for('main.view_catalog', catalog_name=catalog_name))


@bp.route('/catalog/<catalog_name>/file/<path:file_path>/edit', methods=['GET', 'POST'])
@requires_auth
def edit_catalog_file(catalog_name, file_path):
    """Edit specific catalog file."""
    catalog_service = get_catalog_service()
    
    if request.method == 'POST':
        try:
            # Get JSON content from form
            json_content = request.form.get('json_content', '')
            
            # Validate JSON
            is_valid, error_msg, parsed_data = catalog_service.validate_json(json_content)
            
            if not is_valid:
                flash(f'Invalid JSON: {error_msg}', 'error')
                return render_template('catalog_edit.html',
                                     catalog_name=catalog_name,
                                     file_path=file_path,
                                     json_content=json_content)
            
            # Save catalog
            catalog_service.save_catalog(file_path, parsed_data)
            
            flash('Catalog saved successfully! Backup created.', 'success')
            return redirect(url_for('main.view_catalog_file', 
                                  catalog_name=catalog_name, 
                                  file_path=file_path))
        
        except Exception as e:
            flash(f'Error saving catalog: {e}', 'error')
            return render_template('catalog_edit.html',
                                 catalog_name=catalog_name,
                                 file_path=file_path,
                                 json_content=request.form.get('json_content', ''))
    
    # GET request - load catalog for editing
    try:
        data, full_path = catalog_service.load_catalog(file_path)
        
        import json
        json_content = json.dumps(data, indent=2, ensure_ascii=False)
        
        return render_template('catalog_edit.html',
                             catalog_name=catalog_name,
                             file_path=file_path,
                             full_path=str(full_path),
                             json_content=json_content)
    
    except Exception as e:
        flash(f'Error loading catalog: {e}', 'error')
        return redirect(url_for('main.view_catalog', catalog_name=catalog_name))


@bp.route('/search')
@requires_auth
def search():
    """Search across all catalogs."""
    query = request.args.get('q', '')
    
    if not query:
        return render_template('search.html', query='', results=[])
    
    try:
        catalog_service = get_catalog_service()
        
        # Search in catalog
        all_results = []
        try:
            results = catalog_service.search_catalogs('catalog.json', query)
            for result in results:
                result['_catalog_name'] = 'ems-bus'
            all_results.extend(results)
        except Exception as e:
            flash(f'Error searching catalog: {e}', 'warning')
        
        return render_template('search.html', 
                             query=query, 
                             results=all_results,
                             result_count=len(all_results))
    
    except Exception as e:
        flash(f'Error during search: {e}', 'error')
        return render_template('search.html', query=query, results=[])
