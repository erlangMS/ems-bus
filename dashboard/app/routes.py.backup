"""Flask routes for catalog management."""
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, session
from functools import wraps
from app.catalog_service import CatalogService
from pathlib import Path
from urllib.parse import urlencode
import requests


bp = Blueprint('main', __name__)

@bp.before_request
def log_request_info():
    print(f"[Request Debug] Path: {request.path}")
    print(f"[Request Debug] Headers: {dict(request.headers)}")
    print(f"[Request Debug] Cookies: {request.cookies}")
    if 'ems_dashboard_session' in request.cookies:
        print(f"[Request Debug] Session cookie found: {request.cookies['ems_dashboard_session'][:20]}...")
    else:
        print(f"[Request Debug] NO session cookie found")


@bp.after_request
def log_response_info(response):
    print(f"[Response Debug] Status: {response.status_code}")
    print(f"[Response Debug] Headers: {dict(response.headers)}")
    if 'Set-Cookie' in response.headers:
        print(f"[Response Debug] Set-Cookie: {response.headers['Set-Cookie']}")
    return response


def requires_auth(f):
    """Decorator to require OAuth2 authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'access_token' not in session:
            return redirect(url_for('main.login_page'))
        return f(*args, **kwargs)
    return decorated


def get_catalog_service():
    """Get CatalogService instance."""
    catalog_paths = current_app.config.get('CATALOG_PATHS', [current_app.config['CATALOG_PATH']])
    return CatalogService(
        catalog_paths,
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
        flash(f'Erro de autenticação: {error}', 'error')
        return redirect(url_for('main.login_page'))
    
    if not code:
        print(f"[OAuth2 Callback] No authorization code received")
        flash('Nenhum código de autorização recebido', 'error')
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
        print(f"[OAuth2 Token Exchange] SSL Verification: {current_app.config.get('VERIFY_SSL', True)}")
        
        token_response = requests.post(
            token_url,
            data=payload,
            headers=headers,
            timeout=10,
            verify=current_app.config.get('VERIFY_SSL', True)
        )
        
        print(f"[OAuth2 Token Exchange] Status: {token_response.status_code}")
        print(f"[OAuth2 Token Exchange] Response: {token_response.text[:500]}")
        
        if token_response.status_code == 200:
            token_data = token_response.json()
            session['access_token'] = token_data.get('access_token')
            
            # Minimize session data to avoid cookie size limits (4KB)
            raw_user = token_data.get('resource_owner', {})
            session['user'] = {
                'id': raw_user.get('id'),
                'login': raw_user.get('login'),
                'name': raw_user.get('name'),
                'email': raw_user.get('email')
            }
            
            # client info is minimal, likely safe, but let's be safe
            raw_client = token_data.get('client', {})
            session['client'] = {
                'id': raw_client.get('id'),
                'name': raw_client.get('name')
            }
            
            print(f"[OAuth2 Token Exchange] Success! Access token: {token_data.get('access_token')[:20]}...")
            print(f"[OAuth2 Token Exchange] User: {token_data.get('resource_owner', {}).get('login')}")
            print(f"[OAuth2 Session] Saved to session - keys: {list(session.keys())}")
            print(f"[OAuth2 Session] Session access_token: {session.get('access_token', 'NOT FOUND')[:20] if session.get('access_token') else 'NOT FOUND'}...")
            
            flash('Login realizado com sucesso!', 'success')
            
            print(f"[OAuth2 Redirect] Redirecting to index")
            
            # Debug session size
            import json
            try:
                # Estimate cookie size (base64 overhead approx 1.33x)
                session_str = json.dumps(dict(session))
                print(f"[OAuth2 Debug] Session data size (json): {len(session_str)} bytes")
                print(f"[OAuth2 Debug] Estimated cookie size: {len(session_str) * 1.4} bytes")
                if len(session_str) * 1.4 > 4000:
                    print(f"[OAuth2 Debug] WARNING: Session cookie might be too large!")
            except:
                pass

            # Create response object to manually set a test cookie
            response = redirect(url_for('main.index'))
            
            # Manually set a test cookie to verify browser acceptance
            # using the exact same settings we expect for the session
            response.set_cookie(
                'debug_cookie', 
                'hello_world', 
                max_age=300,
                secure=False,
                httponly=False,
                samesite='Lax',
                path='/'
            )
            print("[OAuth2 Debug] Manually added 'debug_cookie' to response")
            
            return response
        else:
            print(f"[OAuth2 Token Exchange] Failed with status {token_response.status_code}")
            flash(f'Falha na autenticação: {token_response.text}', 'error')
            return redirect(url_for('main.login_page'))
    
    except Exception as e:
        print(f"[OAuth2 Token Exchange] Exception: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f'Erro de autenticação: {str(e)}', 'error')
        return redirect(url_for('main.login_page'))


@bp.route('/logout')
def logout():
    """Logout user by clearing session."""
    session.clear()
    flash('Logout realizado com sucesso', 'success')
    return redirect(url_for('main.login_page'))


@bp.route('/')
@requires_auth
def index():
    """Dashboard with catalog tree navigation."""
    try:
        catalog_service = get_catalog_service()
        
        # Build trees for all catalogs
        trees = []
        catalog_dirs = current_app.config.get('CATALOG_PATHS', [current_app.config['CATALOG_PATH']])
        
        for catalog_dir in catalog_dirs:
            # Try catalog.json first
            catalog_file = catalog_dir / 'catalog.json'
            if not catalog_file.exists():
                # Look for any .json file
                json_files = list(catalog_dir.glob('*.json'))
                if json_files:
                    catalog_file = json_files[0]
                else:
                    continue
            
            tree = catalog_service.build_catalog_tree(catalog_file.name)
            if tree:
                tree['_catalog_dir'] = catalog_dir.name
                trees.append(tree)
        
        if not trees:
            flash('Error loading catalog trees', 'error')
            return render_template('error.html', error='Could not load any catalog trees'), 500
        
        return render_template('index.html', trees=trees)
    
    except Exception as e:
        flash(f'Error loading catalog: {e}', 'error')
        return render_template('error.html', error=str(e)), 500


@bp.route('/catalogs')
@requires_auth
def list_catalogs():
    """List all available catalogs."""
    try:
        catalog_paths = {}
        
        # Get all configured catalog directories
        catalog_dirs = current_app.config.get('CATALOG_PATHS', [current_app.config['CATALOG_PATH']])
        
        # Search for catalog files in each directory
        for catalog_dir in catalog_dirs:
            # First try catalog.json (standard name)
            catalog_file = catalog_dir / 'catalog.json'
            if catalog_file.exists():
                catalog_name = catalog_dir.name
                catalog_paths[catalog_name] = 'catalog.json'
            else:
                # Look for any .json file in the root directory
                json_files = list(catalog_dir.glob('*.json'))
                if json_files:
                    # Use the first .json file found
                    catalog_file = json_files[0]
                    catalog_name = catalog_dir.name
                    catalog_paths[catalog_name] = catalog_file.name
        
        # Fallback if no catalogs found
        if not catalog_paths:
            catalog_paths = {'ems-bus': 'catalog.json'}
        
        return render_template('catalogs.html', catalog_paths=catalog_paths)
    
    except Exception as e:
        flash(f'Error loading catalogs: {e}', 'error')
        return render_template('error.html', error=str(e)), 500


@bp.route('/catalog/<catalog_name>')
@requires_auth
def view_catalog(catalog_name):
    """View specific catalog with all services."""
    try:
        catalog_service = get_catalog_service()
        
        # Find the catalog file for this catalog name
        catalog_file_name = 'catalog.json'  # default
        catalog_dirs = current_app.config.get('CATALOG_PATHS', [current_app.config['CATALOG_PATH']])
        
        for catalog_dir in catalog_dirs:
            if catalog_dir.name == catalog_name:
                # Try catalog.json first
                catalog_file = catalog_dir / 'catalog.json'
                if not catalog_file.exists():
                    # Look for any .json file
                    json_files = list(catalog_dir.glob('*.json'))
                    if json_files:
                        catalog_file_name = json_files[0].name
                break
        
        # Load all services recursively
        services = catalog_service.list_catalogs_recursive(catalog_file_name)
        
        # Get statistics
        stats = catalog_service.get_catalog_stats(catalog_file_name)
        
        return render_template('catalog_view.html',
                             catalog_name=catalog_name,
                             catalog_path=catalog_file_name,
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
            
            flash('Catálogo salvo com sucesso! Backup criado.', 'success')
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
        
        # Search across all catalogs
        all_results = []
        catalog_dirs = current_app.config.get('CATALOG_PATHS', [current_app.config['CATALOG_PATH']])
        
        for catalog_dir in catalog_dirs:
            # Find the catalog file for this directory
            catalog_file = catalog_dir / 'catalog.json'
            if not catalog_file.exists():
                # Look for any .json file
                json_files = list(catalog_dir.glob('*.json'))
                if json_files:
                    catalog_file = json_files[0]
                else:
                    continue
            
            # Search in this catalog
            results = catalog_service.search_catalogs(catalog_file.name, query)
            
            # Add catalog name to each result
            for result in results:
                result['_catalog_name'] = catalog_dir.name
            
            all_results.extend(results)
        
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
            
            if catalog_service.update_service_entry(file_path, entry_index, updated_entry):
                flash('Serviço atualizado com sucesso!', 'success')
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
