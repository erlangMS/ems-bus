"""Application entry point."""
from app import create_app
from config import Config
import os
import sys
import threading

app = create_app()

def run_http_server(port):
    """Run HTTP server on specified port."""
    print(f"🌐 HTTP server starting on http://0.0.0.0:{port}")
    app.run(host='0.0.0.0', port=port, debug=True, use_reloader=False)

def run_https_server(port, ssl_context):
    """Run HTTPS server on specified port."""
    print(f"🔒 HTTPS server starting on https://0.0.0.0:{port}")
    app.run(host='0.0.0.0', port=port, debug=True, ssl_context=ssl_context, use_reloader=False)

if __name__ == '__main__':
    config = Config()
    
    # Check which ports are configured (now from config object)
    http_port = config.HTTP_PORT
    https_port = config.HTTPS_PORT
    
    servers = []
    
    # Configure HTTPS if SSL is enabled and HTTPS_PORT is set
    if config.USE_SSL and https_port:
        ssl_context = (config.SSL_CERT_FILE, config.SSL_KEY_FILE)
        servers.append({
            'type': 'HTTPS',
            'port': int(https_port),
            'ssl_context': ssl_context
        })
    
    # Configure HTTP if HTTP_PORT is set
    if http_port:
        servers.append({
            'type': 'HTTP',
            'port': int(http_port),
            'ssl_context': None
        })
    
    # Error if no ports configured
    if not servers:
        print("\n" + "="*80)
        print("ERROR: No server ports configured!")
        print("="*80)
        print("\nYou must set at least one of the following environment variables:\n")
        print("  - HTTP_PORT: Port for HTTP server (e.g., 5000)")
        print("  - HTTPS_PORT: Port for HTTPS server (requires SSL_CERT_FILE and SSL_KEY_FILE)")
        print("\nExample configuration:")
        print("  environment:")
        print("    - HTTP_PORT=5000")
        print("  OR")
        print("    - HTTPS_PORT=5443")
        print("    - SSL_CERT_FILE=/cert/server.crt")
        print("    - SSL_KEY_FILE=/cert/server.key")
        print("="*80 + "\n")
        sys.exit(1)
    
    # Print configuration
    print(f"\n{'='*80}")
    print("Dashboard Server Configuration")
    print(f"{'='*80}")
    for server in servers:
        protocol = server['type']
        port = server['port']
        if protocol == 'HTTPS':
            print(f"  🔒 {protocol} on port {port}")
            print(f"     Certificate: {config.SSL_CERT_FILE}")
            print(f"     Key: {config.SSL_KEY_FILE}")
        else:
            print(f"  🌐 {protocol} on port {port}")
    print(f"{'='*80}\n")
    
    # Start servers
    if len(servers) == 1:
        # Single server - run directly
        server = servers[0]
        if server['ssl_context']:
            app.run(host='0.0.0.0', port=server['port'], debug=True, ssl_context=server['ssl_context'])
        else:
            app.run(host='0.0.0.0', port=server['port'], debug=True)
    else:
        # Multiple servers - run in threads
        threads = []
        for i, server in enumerate(servers):
            if server['ssl_context']:
                thread = threading.Thread(
                    target=run_https_server,
                    args=(server['port'], server['ssl_context']),
                    daemon=True
                )
            else:
                thread = threading.Thread(
                    target=run_http_server,
                    args=(server['port'],),
                    daemon=True
                )
            threads.append(thread)
            thread.start()
        
        # Keep main thread alive
        print("Press Ctrl+C to stop all servers")
        try:
            for thread in threads:
                thread.join()
        except KeyboardInterrupt:
            print("\nShutting down servers...")
