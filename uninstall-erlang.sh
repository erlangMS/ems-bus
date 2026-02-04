#!/bin/bash
#
# Uninstall script for Erlang
# Removes Erlang from system (apt), asdf, and configuration files
#
# Author: Everton de Vargas Agilar <evertonagilar@gmail.com>
#

echo "=== Erlang Uninstallation ==="
echo ""

# 1. Remove System Packages (apt/dpkg)
echo "[1/4] Removing system Erlang packages..."
if dpkg -l | grep -q "erlang"; then
    echo "Found system Erlang packages. Removing..."
    # Get list of all packages containing "erlang"
    ERLANG_PACKAGES=$(dpkg -l | grep erlang | awk '{print $2}')
    
    if [ -n "$ERLANG_PACKAGES" ]; then
        echo "Packages to remove:"
        echo "$ERLANG_PACKAGES"
        echo ""
        echo "Running apt-get remove --purge..."
        sudo apt-get remove --purge -y $ERLANG_PACKAGES
        sudo apt-get autoremove -y
        echo "System Erlang packages removed."
    fi
else
    echo "No system Erlang packages found via dpkg."
fi
echo ""

# 2. Remove asdf Erlang
# 2. Remove asdf Erlang
echo "[2/4] Removing asdf Erlang..."
if [ -d "$HOME/.asdf" ]; then
    if command -v asdf &> /dev/null; then
        # Use asdf to list installed versions
        INSTALLED_VERSIONS=$(asdf list erlang 2>/dev/null)
        if [ -n "$INSTALLED_VERSIONS" ]; then
            echo "Found asdf Erlang versions: $INSTALLED_VERSIONS"
            for version in $INSTALLED_VERSIONS; do
                 echo "Uninstalling Erlang $version..."
                 asdf uninstall erlang "$version"
            done
        fi
    fi
    
    echo "Removing asdf directory ($HOME/.asdf)..."
    rm -rf "$HOME/.asdf"
    echo "asdf removed."
else
    echo "asdf not installed."
fi
echo ""

# 3. Remove Configuration Files and links
echo "[3/4] Removing configuration files and links..."

# Remove .hosts.erlang
if [ -L "$HOME/.hosts.erlang" ] || [ -f "$HOME/.hosts.erlang" ]; then
    rm "$HOME/.hosts.erlang"
    echo "Removed $HOME/.hosts.erlang"
fi

if [ -f "$(dirname "$0")/.hosts.erlang" ]; then
    rm "$(dirname "$0")/.hosts.erlang"
    echo "Removed $(dirname "$0")/.hosts.erlang"
fi

# Remove .odbc.ini link
if [ -L "$HOME/.odbc.ini" ]; then
    rm "$HOME/.odbc.ini"
    echo "Removed $HOME/.odbc.ini"
fi

echo "Configuration files cleanup complete."
echo ""

# 4. Verify
echo "[4/4] Verifying removal..."
if command -v erl &> /dev/null; then
    echo "WARNING: 'erl' command is still found at: $(which erl)"
    echo "This might be due to manual installation or unhashed paths."
else
    echo "Success: 'erl' command not found."
fi

echo ""
echo "=== Uninstallation Complete ==="
