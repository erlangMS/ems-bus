#!/bin/bash
#
# Setup script for Erlang environment
# Installs required packages, database drivers, and ODBC configuration
#
# Author: Everton de Vargas Agilar <evertonagilar@gmail.com>
#

set -e

echo "=== Erlang Environment Setup ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRIV_CONF_DIR="$SCRIPT_DIR/priv/conf"

echo "Script directory: $SCRIPT_DIR"
echo "Configuration directory: $PRIV_CONF_DIR"
echo ""

# ############## Install Microsoft ODBC Driver 17 for SQL Server ##############

echo "[1/4] Installing Microsoft ODBC Driver 17 for SQL Server..."

apt-get update
apt-get install -y --no-install-recommends \
    gnupg2 \
    apt-transport-https

# Add Microsoft repository
curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
curl https://packages.microsoft.com/config/ubuntu/22.04/prod.list > /etc/apt/sources.list.d/mssql-release.list

apt-get update
ACCEPT_EULA=Y apt-get install -y msodbcsql17

echo "✓ Microsoft ODBC Driver 17 installed"
echo ""

# ############## Install Erlang dependencies and ODBC packages ##############

echo "[2/4] Installing Erlang dependencies and ODBC packages..."

apt-get install -y --no-install-recommends \
    zip \
    unzip \
    net-tools \
    tdsodbc \
    freetds-common \
    libltdl7 \
    ldap-utils \
    odbc-postgresql

echo "✓ Dependencies installed"
echo ""

# ############## Configure ODBC ##############

echo "[3/4] Configuring ODBC..."

# Check if configuration files exist
if [ ! -f "$PRIV_CONF_DIR/odbc.ini" ]; then
    echo "ERROR: odbc.ini not found in $PRIV_CONF_DIR"
    exit 1
fi

if [ ! -f "$PRIV_CONF_DIR/odbcinst.ini" ]; then
    echo "ERROR: odbcinst.ini not found in $PRIV_CONF_DIR"
    exit 1
fi

# Copy ODBC configuration files
cp "$PRIV_CONF_DIR/odbcinst.ini" /etc/odbcinst.ini
cp "$PRIV_CONF_DIR/odbc.ini" /etc/odbc.ini

# Create symbolic links for user home directory
CURRENT_USER="${SUDO_USER:-$USER}"
USER_HOME=$(eval echo ~$CURRENT_USER)

if [ -n "$USER_HOME" ] && [ "$USER_HOME" != "/root" ]; then
    ln -sf /etc/odbc.ini "$USER_HOME/.odbc.ini"
    echo "✓ Created symbolic link: $USER_HOME/.odbc.ini -> /etc/odbc.ini"
fi

# Also create for root
ln -sf /etc/odbc.ini /root/.odbc.ini
echo "Created symbolic link: /root/.odbc.ini -> /etc/odbc.ini"

echo "ODBC configured"
echo ""

# ############## Configure .hosts.erlang ##############

echo "[4/4] Configuring .hosts.erlang..."

# Create .hosts.erlang file
echo "'127.0.0.1'." > "$SCRIPT_DIR/.hosts.erlang"

# Create symbolic link in user home directory
if [ -n "$USER_HOME" ] && [ "$USER_HOME" != "/root" ]; then
    ln -sf "$SCRIPT_DIR/.hosts.erlang" "$USER_HOME/.hosts.erlang"
    chown -h $CURRENT_USER:$CURRENT_USER "$USER_HOME/.hosts.erlang" 2>/dev/null || true
    echo "Created symbolic link: $USER_HOME/.hosts.erlang -> $SCRIPT_DIR/.hosts.erlang"
fi

# Also create for root
ln -sf "$SCRIPT_DIR/.hosts.erlang" /root/.hosts.erlang
echo "Created symbolic link: /root/.hosts.erlang -> $SCRIPT_DIR/.hosts.erlang"

echo ".hosts.erlang configured"
echo ""

# ############## Cleanup ##############

apt-get clean
rm -rf /var/lib/apt/lists/*

echo "=== Setup completed successfully! ==="
echo ""
echo "Summary:"
echo "  - Microsoft ODBC Driver 17 installed"
echo "  - Erlang dependencies installed"
echo "  - ODBC configuration files copied to /etc"
echo "  - Symbolic links created for odbc.ini and .hosts.erlang"
echo ""
echo "You can now start the Erlang application."
