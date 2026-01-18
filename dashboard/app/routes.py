"""Flask routes for catalog management."""
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, session
from functools import wraps
from app.catalog_service import CatalogService
from pathlib import Path
from urllib.parse import urlencode
import requests


bp = Blueprint('main', __name__)


def requires_auth(f):
    """Decorator to require OAuth2 authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        print(f"[Auth Check] Request URL: {request.url}")
        print(f"[Auth Check] Request Method: {request.method}")
        print(f"[Auth Check] Request Headers: {dict(request.headers)}")
        print(f"[Auth Check] Session keys: {list(session.keys())}")
        
        if 'access_token' in session:
            print(f"[Auth Check] Access token: {session['access_token'][:20]}...")
        
        if 'access_token' not in session:
            print(f"[Auth Check] No access token, redirecting to login")
            return redirect(url_for('main.login_page'))
        return f(*args, **kwargs)
    return decorated


def get_catalog_service():
    """Get CatalogService instance."""
    catalog_path = current_app.config['CATALOG_PATH']
    return CatalogService(
        catalog_path,
        current_app.config['CREATE_BACKUPS']
    )


@bp.route('/login')
def login_page():
    """Show login page."""
    return render_template('login.html')


@bp.route('/oauth/login')
def oauth_login():
    """Redirect to OAuth2 authorization endpoint."""
    params = {
        'client_id': current_app.config['OAUTH2_CLIENT_ID'],
        'redirect_uri': current_app.config['OAUTH2_REDIRECT_URI'],
        'response_type': 'code',
        'scope': current_app.config['OAUTH2_SCOPE']
    }
    auth_url = f"{current_app.config['OAUTH2_AUTHORIZE_URL']}?{urlencode(params)}"
    
    print(f"[OAuth2] Redirecting to authorization URL: {auth_url}")
    print(f"[OAuth2] Client ID: {current_app.config['OAUTH2_CLIENT_ID']}")
    print(f"[OAuth2] Redirect URI: {current_app.config['OAUTH2_REDIRECT_URI']}")
    
    return redirect(auth_url)


@bp.route('/callback')
def oauth_callback():
    """Handle OAuth2 callback and exchange code for token."""
    code = request.args.get('code')
    error = request.args.get('error')
    
    print(f"[OAuth2 Callback] Received callback")
    print(f"[OAuth2 Callback] Code: {code}")
    print(f"[OAuth2 Callback] Error: {error}")
    print(f"[OAuth2 Callback] All args: {request.args}")
    
    if error:
        print(f"[OAuth2 Callback] Authentication error: {error}")
        flash(f'Authentication error: {error}', 'error')
        return redirect(url_for('main.login_page'))
    
    if not code:
        print(f"[OAuth2 Callback] No authorization code received")
        flash('No authorization code received', 'error')
        return redirect(url_for('main.login_page'))
    
    try:
        # Exchange authorization code for access token
        # The barramento expects Basic Auth header with client_id:client_secret
        import base64
        
        # Create Basic Auth header
        credentials = f"{current_app.config['OAUTH2_CLIENT_ID']}:{current_app.config['OAUTH2_CLIENT_SECRET']}"
        basic_auth = base64.b64encode(credentials.encode()).decode()
        
        token_url = current_app.config['OAUTH2_TOKEN_URL']
        
        # Payload according to barramento's OAuth2 implementation
        payload = {
            'grant_type': 'authorization_code',
            'code': code
        }
        
        headers = {
            'Authorization': f'Basic {basic_auth}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        print(f"[OAuth2 Token Exchange] URL: {token_url}")
        print(f"[OAuth2 Token Exchange] Payload: {payload}")
        print(f"[OAuth2 Token Exchange] Basic Auth: {basic_auth}")
        
        token_response = requests.post(
            token_url,
            data=payload,
            headers=headers,
            timeout=10
        )
        
        print(f"[OAuth2 Token Exchange] Status: {token_response.status_code}")
        print(f"[OAuth2 Token Exchange] Response: {token_response.text[:500]}")
        
        if token_response.status_code == 200:
            token_data = token_response.json()
            session['access_token'] = token_data.get('access_token')
            session['user'] = token_data.get('resource_owner', {})
            session['client'] = token_data.get('client', {})
            
            print(f"[OAuth2 Token Exchange] Success! Access token: {token_data.get('access_token')[:20]}...")
            print(f"[OAuth2 Token Exchange] User: {token_data.get('resource_owner', {}).get('login')}")
            print(f"[OAuth2 Session] Saved to session - keys: {list(session.keys())}")
            print(f"[OAuth2 Session] Session access_token: {session.get('access_token', 'NOT FOUND')[:20] if session.get('access_token') else 'NOT FOUND'}...")
            
            flash('Successfully logged in!', 'success')
            
            print(f"[OAuth2 Redirect] Redirecting to index")
            return redirect(url_for('main.index'))
        else:
            print(f"[OAuth2 Token Exchange] Failed with status {token_response.status_code}")
            flash(f'Authentication failed: {token_response.text}', 'error')
            return redirect(url_for('main.login_page'))
    
    except Exception as e:
        print(f"[OAuth2 Token Exchange] Exception: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f'Authentication error: {str(e)}', 'error')
        return redirect(url_for('main.login_page'))


@bp.route('/logout')
def logout():
    """Logout user by clearing session."""
    session.clear()
    flash('Successfully logged out', 'success')
    return redirect(url_for('main.login_page'))


@bp.route('/')
@requires_auth
def index():
    """Dashboard with catalog tree navigation."""
    try:
        catalog_service = get_catalog_service()
        
        # Build catalog tree
        tree = catalog_service.build_catalog_tree('catalog.json')
        
        if not tree:
            flash('Error loading catalog tree', 'error')
            return render_template('error.html', error='Could not load catalog tree'), 500
        
        return render_template('index.html', tree=tree)
    
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


@bp.route('/service/<path:file_path>/<int:entry_index>')
@requires_auth
def view_service_entry(file_path, entry_index):
    """View a specific service entry."""
    try:
        catalog_service = get_catalog_service()
        entry = catalog_service.get_service_entry(file_path, entry_index)
        
        if not entry:
            flash('Service entry not found', 'error')
            return redirect(url_for('main.index'))
        
        return render_template('service_entry_view.html',
                             entry=entry,
                             file_path=file_path,
                             entry_index=entry_index)
    
    except Exception as e:
        flash(f'Error loading service entry: {e}', 'error')
        return redirect(url_for('main.index'))


@bp.route('/service/<path:file_path>/<int:entry_index>/edit', methods=['GET', 'POST'])
@requires_auth
def edit_service_entry(file_path, entry_index):
    """Edit a specific service entry."""
    catalog_service = get_catalog_service()
    
    if request.method == 'POST':
        try:
            # Build updated entry from form data
            updated_entry = {}
            
            # Get all form fields
            for key in request.form.keys():
                if key.startswith('_'):  # Skip internal fields
                    continue
                value = request.form.get(key, '').strip()
                if value:  # Only include non-empty values
                    updated_entry[key] = value
            
            # Update the entry
            if catalog_service.update_service_entry(file_path, entry_index, updated_entry):
                flash('Service entry updated successfully!', 'success')
                return redirect(url_for('main.view_service_entry', 
                                      file_path=file_path, 
                                      entry_index=entry_index))
            else:
                flash('Error updating service entry', 'error')
        
        except Exception as e:
            flash(f'Error saving changes: {e}', 'error')
    
    # GET request - load entry for editing
    try:
        entry = catalog_service.get_service_entry(file_path, entry_index)
        
        if not entry:
            flash('Service entry not found', 'error')
            return redirect(url_for('main.index'))
        
        return render_template('service_entry_edit.html',
                             entry=entry,
                             file_path=file_path,
                             entry_index=entry_index)
    
    except Exception as e:
        flash(f'Error loading service entry: {e}', 'error')
        return redirect(url_for('main.index'))
