# ems-bus Catalog Manager

Flask-based web application for managing ems-bus service catalogs with Docker containerization and maximum security.

## 🔒 Security Features

- **Minimal Filesystem Access**: Container only accesses catalog directory and config file
- **Read-Only Config**: `emsbus.conf` mounted as read-only
- **Non-Root User**: Container runs as UID 1000
- **HTTP Basic Auth**: Password-protected access
- **Automatic Backups**: Creates `.bak` files before saving
- **Path Traversal Protection**: Validates all file paths
- **Server-Side Processing**: 100% Python/Flask (no client-side JavaScript)

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- ems-bus installed at `/dados/desenvolvimento/unb/erlangms/ems-bus`

### Installation

1. **Navigate to the catalog manager directory:**
   ```bash
   cd /dados/desenvolvimento/unb/erlangms/ems-bus/ems-catalog-manager
   ```

2. **Configure environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env and change the default password!
   nano .env
   ```

3. **Build and start the container:**
   ```bash
   docker-compose up -d
   ```

4. **Access the web interface:**
   - Open http://localhost:5000
   - Login with credentials from `.env` (default: admin/admin123)

### Stopping the Application

```bash
docker-compose down
```

## 📁 Volume Mounts

The Docker container has **minimal access** to the host filesystem:

| Host Path | Container Path | Mode | Purpose |
|-----------|----------------|------|---------|
| `../priv/conf/emsbus.conf` | `/app/priv/conf/emsbus.conf` | **read-only** | Configuration file |
| `../priv` | `/app/priv` | **read-write** | Priv directory (includes catalogs) |

**Note**: 
- The config file is mounted as **read-only** to prevent accidental modifications.
- Catalog paths in `emsbus.conf` are resolved relative to the config file's directory.
- For example, if the config file is at `/app/priv/conf/emsbus.conf` and specifies `"catalog_path": {"ems-bus": "priv/catalog/catalog.json"}`, the actual path will be `/app/priv/catalog/catalog.json`.

## 🎯 Features

- **📊 Dashboard** - Overview of all catalogs with statistics
- **📋 Catalog Browser** - View all services in a catalog
- **✏️ JSON Editor** - Edit catalog files with syntax highlighting
- **🔍 Search** - Find services across all catalogs
- **💾 Auto Backup** - Automatic `.bak` files before saves
- **✅ Validation** - JSON validation before saving
- **🔐 Authentication** - HTTP Basic Auth protection

## 🛠️ Development

### Running Without Docker

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set environment variables:**
   ```bash
   export EMSBUS_CONFIG_PATH=/dados/desenvolvimento/unb/erlangms/ems-bus/priv/conf/emsbus.conf
   export CATALOG_USERNAME=admin
   export CATALOG_PASSWORD=admin123
   ```
   
   **Note**: Catalog paths are read from the `catalog_path` parameter in `emsbus.conf` and resolved relative to the config file's directory.

3. **Run the application:**
   ```bash
   python run.py
   ```

4. **Access at http://localhost:5000**

### Project Structure

```
ems-catalog-manager/
├── app/
│   ├── __init__.py           # Flask app factory
│   ├── routes.py             # Route handlers
│   ├── catalog_service.py    # Catalog business logic
│   ├── config_reader.py      # Config file parser
│   └── templates/            # Jinja2 templates
│       ├── base.html
│       ├── index.html
│       ├── catalog_view.html
│       ├── catalog_file.html
│       ├── catalog_edit.html
│       ├── catalogs.html
│       ├── search.html
│       └── error.html
├── config.py                 # Flask configuration
├── run.py                    # Application entry point
├── requirements.txt          # Python dependencies
├── Dockerfile               # Container definition
├── docker-compose.yml       # Docker orchestration
└── README.md               # This file
```

## 🔧 Configuration

### Authentication

Change credentials in `.env`:

```bash
CATALOG_USERNAME=your_username
CATALOG_PASSWORD=your_secure_password
SECRET_KEY=generate-a-random-secret-key
```

### Custom Paths

If your ems-bus is installed elsewhere, update `docker-compose.yml`:

```yaml
volumes:
  - /path/to/your/priv/conf/emsbus.conf:/app/priv/conf/emsbus.conf:ro
  - /path/to/your/priv:/app/priv:rw
```

**Important**: Ensure the catalog paths in your `emsbus.conf` are relative to the config file's directory, or use absolute paths.

## 📝 Usage

### Viewing Catalogs

1. Go to **Dashboard** to see all configured catalogs
2. Click on a catalog to view all services
3. Click **Ver Arquivo** to see the raw JSON

### Editing Catalogs

1. Navigate to a catalog file
2. Click **✏️ Editar**
3. Modify the JSON in the editor
4. Click **💾 Salvar Alterações**
5. A backup (`.bak`) is automatically created

### Searching

1. Go to **Buscar** in the navigation
2. Type your search query
3. Results show matching services from all catalogs

## 🔐 Security Considerations

- **Change default password** immediately after deployment
- **Use HTTPS** in production (configure reverse proxy)
- **Restrict network access** to trusted IPs only
- **Regular backups** are created but should be archived externally
- **Monitor logs** for unauthorized access attempts

## 🐛 Troubleshooting

### Container won't start

Check logs:
```bash
docker-compose logs -f
```

### Permission denied errors

Ensure the catalog directory is writable:
```bash
chmod -R 755 priv/catalog
```

### Can't access web interface

Verify container is running:
```bash
docker-compose ps
```

Check if port 5000 is available:
```bash
netstat -tuln | grep 5000
```

## 📄 License

Part of the ems-bus project by Everton de Vargas Agilar.

## 🤝 Contributing

This is a utility tool for ems-bus. For issues or improvements, contact the ems-bus maintainers.
