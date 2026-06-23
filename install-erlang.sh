#!/bin/bash
#
# Setup script for Erlang environment using asdf
# Installs asdf, Erlang 28, required packages, database drivers, and ODBC configuration
#
# Author: Everton de Vargas Agilar <evertonagilar@gmail.com>
#

set -e

echo "=== Erlang Environment Setup with asdf ==="
echo ""

# Check if NOT running as root
if [ "$EUID" -eq 0 ]; then 
    echo "ERROR: Do not run this script as root or with sudo"
    echo "Run as a regular user: ./install-erlang.sh"
    exit 1
fi

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRIV_CONF_DIR="$SCRIPT_DIR/priv/conf"

echo "Script directory: $SCRIPT_DIR"
echo "Configuration directory: $PRIV_CONF_DIR"
echo "User: $USER"
echo "Home: $HOME"
echo ""

# Check command line arguments
USE_WX=false
ONLY_ASDF=false

for arg in "$@"; do
    if [ "$arg" == "--use-wx" ]; then
        USE_WX=true
    fi
    if [ "$arg" == "--asdf" ]; then
        ONLY_ASDF=true
    fi
    if [[ "$arg" == "--help" || "$arg" == "-h" ]]; then
        echo "Usage: ./install-erlang.sh [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --use-wx    Install optional wxWidgets GUI dependencies (Observer, Debugger)"
        echo "  --asdf      Install/Update ONLY asdf and exit (skips Erlang/ODBC install)"
        echo "  --help, -h  Show this help message"
        echo ""
        exit 0
    fi
done

# ############## Check for existing Erlang installation ##############

if [ "$ONLY_ASDF" = false ]; then
    echo "[1/7] Checking for existing Erlang installation..."

    if command -v erl &> /dev/null; then
        EXISTING_VERSION=$(erl -eval 'erlang:display(erlang:system_info(otp_release)), halt().' -noshell 2>/dev/null | sed 's/[^0-9]//g')
        echo "ERROR: Erlang $EXISTING_VERSION is already installed on this system"
        echo ""
        echo "Please remove the existing Erlang installation first:"
        echo "  - If installed via apt: sudo apt remove erlang*"
        echo "  - If installed via asdf: asdf uninstall erlang $EXISTING_VERSION"
        echo "  - Check with: which erl"
        echo ""
        exit 1
    else
        echo "No existing Erlang installation found"
    fi
    echo ""
fi

# ############## Install asdf dependencies ##############



if [ "$ONLY_ASDF" = true ]; then
  echo "Installing ONLY asdf (skipping Erlang and ODBC)..."
fi

echo "[2/7] Installing asdf and build dependencies..."
echo "This step requires sudo privileges for apt-get"
if [ "$USE_WX" = true ]; then
    echo "Files for wxWidgets GUI enabled..."
fi
echo ""

PACKAGES=(
    curl
    git
    build-essential
    autoconf
    m4
    libncurses5-dev
    libssl-dev
    libncurses-dev
    libssh-dev
    unixodbc-dev
    xsltproc
    fop
    libxml2-utils
    openjdk-11-jdk
)

if [ "$USE_WX" = true ]; then
    echo "Including wxWidgets dependencies..."
    PACKAGES+=(
        libgl1-mesa-dev
        libglu1-mesa-dev
        libpng-dev
    )
    
    # Detect Ubuntu version for wxWidgets
    # lsb_release -rs returns version like "22.04"
    UBUNTU_RELEASE=$(lsb_release -rs)
    UBUNTU_MAJOR=$(echo "$UBUNTU_RELEASE" | cut -d. -f1)
    
    if [ "$UBUNTU_MAJOR" -ge 24 ]; then
        echo "Detected Ubuntu $UBUNTU_RELEASE >= 24. Using libwxgtk3.2..."
        PACKAGES+=(libwxgtk3.2-dev libwxgtk-webview3.2-dev)
    else
        echo "Detected Ubuntu $UBUNTU_RELEASE < 24. Using libwxgtk3.0..."
        PACKAGES+=(libwxgtk3.0-gtk3-dev libwxgtk-webview3.0-gtk3-dev)
    fi
fi

sudo apt-get update
sudo apt-get install -y --no-install-recommends "${PACKAGES[@]}"

echo "Build dependencies installed"
echo ""

# ############## Install asdf ##############

echo "[3/7] Installing asdf version manager..."

ASDF_DIR="$HOME/.asdf"

# Check if asdf is already installed
if [ -d "$ASDF_DIR" ]; then
    echo "asdf already installed at $ASDF_DIR"
else
    # Clone asdf repository
    git clone https://github.com/asdf-vm/asdf.git "$ASDF_DIR" --branch v0.15.0
    echo "asdf cloned to $ASDF_DIR"
fi

# Configure asdf in shell profiles
configure_shell_profile() {
    local SHELL_RC="$1"
    local SHELL_NAME="$2"
    
    if [ ! -f "$SHELL_RC" ]; then
        touch "$SHELL_RC"
    fi
    
    # Check if asdf shims are already configured
    if ! grep -q "asdf/shims" "$SHELL_RC" 2>/dev/null; then
        echo "" >> "$SHELL_RC"
        echo "# Add asdf shims to PATH for Erlang and other tools" >> "$SHELL_RC"
        echo "export PATH=\"\$HOME/.asdf/shims:\$PATH\"" >> "$SHELL_RC"
        echo "Added asdf shims to PATH in $SHELL_RC"
    else
        echo "asdf shims already configured in $SHELL_RC"
    fi
}

# Configure both bash and zsh if they exist
if [ -f "$HOME/.bashrc" ] || [ ! -f "$HOME/.zshrc" ]; then
    configure_shell_profile "$HOME/.bashrc" "bash"
fi

if [ -f "$HOME/.zshrc" ]; then
    configure_shell_profile "$HOME/.zshrc" "zsh"
fi

echo "asdf installed and configured"
echo "asdf installed and configured"
echo ""

if [ "$ONLY_ASDF" = true ]; then
  echo "=== asdf setup completed successfully! ==="
  echo "Skipping Erlang and ODBC installation as requested."
  exit 0
fi

# ############## Install Erlang plugin and Erlang 28 ##############

echo "[4/7] Installing Erlang 28 via asdf..."

# Set up asdf for this script execution
export ASDF_DIR="$ASDF_DIR"
export ASDF_DATA_DIR="$ASDF_DIR"
export PATH="$ASDF_DIR/shims:$ASDF_DIR/bin:$PATH"

# Source asdf
source "$ASDF_DIR/asdf.sh"

# Add Erlang plugin if not already added
if ! asdf plugin list | grep -q "erlang"; then
    asdf plugin add erlang https://github.com/asdf-vm/asdf-erlang.git
    echo "Erlang plugin added to asdf"
else
    echo "Erlang plugin already installed"
fi

# Install Erlang 28.0
ERLANG_VERSION="28.0"
if ! asdf list erlang 2>/dev/null | grep -q "$ERLANG_VERSION"; then
    echo "Installing Erlang $ERLANG_VERSION (this may take 10-20 minutes)..."
    asdf install erlang "$ERLANG_VERSION"
    echo "Erlang $ERLANG_VERSION installed"
else
    echo "Erlang $ERLANG_VERSION already installed"
fi

# Set global Erlang version
asdf global erlang "$ERLANG_VERSION"
echo "Erlang $ERLANG_VERSION set as global version"

# Reshim to update shims
asdf reshim erlang

echo "Erlang 28 installed and configured"
echo ""

# ############## Install Microsoft ODBC Driver 17 for SQL Server ##############

echo "[5/7] Installing Microsoft ODBC Driver 17 for SQL Server..."
echo "This step requires sudo privileges"
echo ""

sudo apt-get install -y --no-install-recommends \
    gnupg2 `# GNU Privacy Guard for package verification` \
    apt-transport-https `# HTTPS transport for APT`

# Add Microsoft repository
UBUNTU_VERSION="22.04"
curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/microsoft.gpg
curl https://packages.microsoft.com/config/ubuntu/${UBUNTU_VERSION}/prod.list | sudo tee /etc/apt/sources.list.d/mssql-release.list > /dev/null

sudo apt-get update
sudo ACCEPT_EULA=Y apt-get install -y msodbcsql17 `# Microsoft ODBC Driver 17 for SQL Server`

echo "Microsoft ODBC Driver 17 installed"
echo ""

# ############## Install additional ODBC packages ##############

echo "[6/7] Installing additional ODBC packages..."
echo ""

sudo apt-get install -y --no-install-recommends \
    zip `# ZIP archive utility` \
    unzip `# ZIP extraction utility` \
    net-tools `# Network tools (ifconfig, netstat, etc.)` \
    tdsodbc `# FreeTDS ODBC driver for SQL Server/Sybase` \
    freetds-common `# FreeTDS common files` \
    libltdl7 `# GNU libtool dynamic module loader` \
    ldap-utils `# LDAP client utilities` \
    odbc-postgresql `# PostgreSQL ODBC driver`

echo "Additional packages installed"
echo ""

# ############## Configure ODBC and .hosts.erlang ##############

echo "[7/7] Configuring ODBC and .hosts.erlang..."

# Check if configuration files exist
if [ ! -f "$PRIV_CONF_DIR/odbc.ini" ]; then
    echo "ERROR: odbc.ini not found in $PRIV_CONF_DIR"
    exit 1
fi

if [ ! -f "$PRIV_CONF_DIR/odbcinst.ini" ]; then
    echo "ERROR: odbcinst.ini not found in $PRIV_CONF_DIR"
    exit 1
fi

# Create symbolic links for ODBC configuration files in /etc
echo "Creating ODBC configuration symbolic links (requires sudo)..."
sudo ln -sf "$PRIV_CONF_DIR/odbcinst.ini" /etc/odbcinst.ini
sudo ln -sf "$PRIV_CONF_DIR/odbc.ini" /etc/odbc.ini
echo "Created symbolic links in /etc for ODBC configuration"

# Create symbolic links in user home directory
ln -sf /etc/odbc.ini "$HOME/.odbc.ini"
echo "Created symbolic link: $HOME/.odbc.ini -> /etc/odbc.ini"

# Create .hosts.erlang file
echo "'127.0.0.1'." > "$SCRIPT_DIR/.hosts.erlang"

# Create symbolic link in user home directory
ln -sf "$SCRIPT_DIR/.hosts.erlang" "$HOME/.hosts.erlang"
echo "Created symbolic link: $HOME/.hosts.erlang -> $SCRIPT_DIR/.hosts.erlang"

echo "ODBC and .hosts.erlang configured"
echo ""

# ############## Cleanup ##############

sudo apt-get clean
sudo rm -rf /var/lib/apt/lists/*

# ############## Verification ##############

echo "=== Verifying installation ==="
echo ""

# Verify Erlang installation
ERLANG_VERSION_CHECK=$(erl -eval 'erlang:display(erlang:system_info(otp_release)), halt().' -noshell 2>/dev/null | sed 's/[^0-9]//g')

if [ "$ERLANG_VERSION_CHECK" = "28" ]; then
    echo "Erlang 28 verified successfully"
else
    echo "WARNING: Erlang version check returned: $ERLANG_VERSION_CHECK (expected: 28)"
fi

echo ""
echo "=== Setup completed successfully! ==="
echo ""
echo "Summary:"
echo "  - asdf version manager installed"
echo "  - Erlang 28.0 installed via asdf"
echo "  - Microsoft ODBC Driver 17 installed"
echo "  - Additional dependencies installed"
echo "  - ODBC configuration symbolic links created in /etc"
echo "  - Symbolic links created for .odbc.ini and .hosts.erlang in $HOME"
echo ""
echo "Next steps:"
echo "  1. Open a new terminal or run: source ~/.bashrc (or source ~/.zshrc)"
echo "  2. Verify Erlang: erl -eval 'erlang:display(erlang:system_info(otp_release)), halt().' -noshell"
echo "  3. Build the project: ./build.sh"
echo ""
