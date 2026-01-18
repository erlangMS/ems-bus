# ems-bus Docker Integration

## Overview

The ems-bus Docker container now includes both the Erlang barramento and the Flask catalog management dashboard in a single unified container.

## Services Running

When you start the container, the following services will be available:

| Service | Port | URL | Description |
|---------|------|-----|-------------|
| **Barramento HTTP** | 2301 | http://localhost:2301 | Main ems-bus service |
| **Barramento HTTPS** | 2344 | https://localhost:2344 | Secure ems-bus service |
| **Dashboard** | 5000 | http://localhost:5000 | Catalog management web interface |

## Building the Container

```bash
# From the ems-bus directory
docker build -t ems-bus:latest .
```

## Running the Container

### Basic Usage

```bash
docker run -d \
  --name ems-bus \
  -p 2301:2301 \
  -p 2344:2344 \
  -p 5000:5000 \
  ems-bus:latest
```

### With Dashboard Authentication

```bash
docker run -d \
  --name ems-bus \
  -p 2301:2301 \
  -p 2344:2344 \
  -p 5000:5000 \
  -e CATALOG_USERNAME=admin \
  -e CATALOG_PASSWORD=your-secure-password \
  -e SECRET_KEY=your-random-secret-key \
  ems-bus:latest
```

### With Volume Mounts (Recommended)

```bash
docker run -d \
  --name ems-bus \
  -p 2301:2301 \
  -p 2344:2344 \
  -p 5000:5000 \
  -v $(pwd)/priv/conf:/app/lib/ems_bus-2.0.26/priv/conf \
  -v $(pwd)/priv/catalog:/app/lib/ems_bus-2.0.26/priv/catalog \
  -v $(pwd)/priv/log:/var/opt/erlangms/log \
  ems-bus:latest
```

## Environment Variables

### Dashboard Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CATALOG_USERNAME` | `admin` | Dashboard login username |
| `CATALOG_PASSWORD` | `admin123` | Dashboard login password |
| `SECRET_KEY` | `change-this-secret-key-in-production` | Flask secret key |

## Container Architecture

### Directory Structure

```
/app/                           # Barramento installation
├── bin/ems_bus                # Barramento executable
├── lib/ems_bus-2.0.26/       # Barramento files
│   └── priv/
│       ├── conf/             # Configuration
│       └── catalog/          # Service catalogs
└── docker-entrypoint.sh      # Startup script

/opt/dashboard/               # Dashboard application
├── app/                      # Flask application
├── config.py                 # Dashboard config
└── run.py                    # Dashboard entry point

/var/opt/erlangms/           # Runtime data
├── log/                     # Barramento logs
└── archive_log/             # Archived logs
```

### Startup Sequence

The `docker-entrypoint.sh` script performs the following:

1. **Start Barramento** - Launches ems-bus in foreground mode on port 2301/2344
2. **Wait for Stability** - Waits 6 seconds for barramento to initialize
3. **Start Dashboard** - Launches Flask dashboard on port 5000
4. **Monitor Processes** - Keeps both processes running, exits if either fails

## Accessing Services

### Barramento

```bash
# Test barramento
curl http://localhost:2301

# Expected response
{"message": "It works!!!"}
```

### Dashboard

1. Open browser to http://localhost:5000
2. Login with configured credentials (default: admin/admin123)
3. Manage service catalogs through the web interface

## Health Checks

### Check Running Processes

```bash
# Enter container
docker exec -it ems-bus bash

# Check processes
ps aux | grep -E 'beam|python'
```

### Check Logs

```bash
# Barramento logs
docker exec ems-bus tail -f /var/opt/erlangms/log/emsbus_out_*.log

# Dashboard logs (stdout)
docker logs -f ems-bus
```

## Stopping the Container

```bash
# Graceful shutdown
docker stop ems-bus

# Force stop
docker kill ems-bus

# Remove container
docker rm ems-bus
```

## Troubleshooting

### Dashboard Not Accessible

Check if Python process is running:
```bash
docker exec ems-bus ps aux | grep python
```

Check dashboard logs:
```bash
docker logs ems-bus | grep -i dashboard
```

### Barramento Not Accessible

Check if beam process is running:
```bash
docker exec ems-bus ps aux | grep beam
```

Check barramento logs:
```bash
docker exec ems-bus ls -la /var/opt/erlangms/log/
```

### Both Services Down

Check container status:
```bash
docker ps -a | grep ems-bus
```

View full logs:
```bash
docker logs ems-bus
```

## Security Considerations

1. **Change Default Passwords** - Always set `CATALOG_PASSWORD` in production
2. **Use HTTPS** - Configure SSL certificates for production use
3. **Restrict Network Access** - Use firewall rules to limit access
4. **Volume Permissions** - Ensure mounted volumes have correct permissions

## Production Deployment

For production, consider:

1. Using Docker Compose for easier management
2. Setting up reverse proxy (nginx) with SSL
3. Implementing proper logging and monitoring
4. Using secrets management for credentials
5. Regular backups of catalog files

## Example docker-compose.yml

```yaml
version: '3.8'

services:
  ems-bus:
    image: ems-bus:latest
    container_name: ems-bus
    ports:
      - "2301:2301"
      - "2344:2344"
      - "5000:5000"
    environment:
      - CATALOG_USERNAME=admin
      - CATALOG_PASSWORD=${DASHBOARD_PASSWORD}
      - SECRET_KEY=${FLASK_SECRET_KEY}
    volumes:
      - ./priv/conf:/app/lib/ems_bus-2.0.26/priv/conf
      - ./priv/catalog:/app/lib/ems_bus-2.0.26/priv/catalog
      - ./priv/log:/var/opt/erlangms/log
    restart: unless-stopped
```

Create `.env` file:
```bash
DASHBOARD_PASSWORD=your-secure-password
FLASK_SECRET_KEY=your-random-secret-key
```

Run with:
```bash
docker-compose up -d
```
