#!/bin/bash
#
# Autor: Everton de Vargas Agilar
#
# Objetivo: Faz o build do projeto.
#
# Modo de usar: 
#
#    $ ./build.sh
#
#
#
## Software modification history:
#
# Data       |  Quem           |  Mensagem  
# -----------------------------------------------------------------------------------------------------
# 10/11/2015  Everton Agilar     Initial release script release
# 19/01/2026  Everton Agilar     Instalação do rebar3 se não estiver instalado
# 01/02/2026  Everton Agilar     Refatorado para usar rebar3
#
#
#
#
########################################################################################################

VERSION_SCRIPT="3.0.3"
set -e

# Erlang Runtime version required
ERLANG_VERSION=28

# Erlang Runtime version installled
ERLANG_VERSION_OS=`erl -eval 'erlang:display(erlang:system_info(otp_release)), halt().'  -noshell 2> /dev/null | sed 's/[^0-9]//g'`

# Skip deps before build 
SKIP_DEPS="false"

# Skip clean before build 
SKIP_CLEAN="false"

# Keep db before build 
KEEP_DB="false"

# Release flag
BUILD_RELEASE="false"

# The settings may be stored in the /etc/default/erlangms-build
CONFIG_ARQ="/etc/default/erlangms-build"

# Prints a message and ends the system
# Parâmetros:
#  $1  - Mensagem que será impressa 
#  $2  - Código de retorno para o comando exit
die () {
    echo $1
    echo
    exit $2
}

# Prints on the screen the command help
help() {
    echo
    echo "How to use: ./build.sh"
    echo ""
    echo "Additional parameters:"
    echo "  --keep-db               -> Does not delete the priv/db folder"
    echo "  --skip-deps             -> Skip rebar deps before build"
    echo "  --skip-clean            -> Skip rebar clean before build"
    echo "  --keep-db=true|false    -> Define if delete the priv/db folder"
    echo "  --skip-dep=true|false   -> Define if skip rebar deps"
    echo "  --skip-clean=true|false -> Define if rebar clean"
    echo "  --clean                 -> Equal to --skip-clean=true"
    echo "  --release               -> Execute rel/release.sh after build"
    echo
    exit 1
}


# Reads a specific configuration file configuration. Accepts default if not set
# Parameters
#   $1 -> Nome da configuração. Ex. REGISTRY
#   $2 -> Valor default
le_setting () {
    KEY=$1
    DEFAULT=$2
    # Reads the setting value, removes leading spaces and makes the unquoted of the double quotation marks
    RESULT=$(egrep "^$KEY" $CONFIG_ARQ | cut -d"=" -f2 | sed -r 's/^ *//' | sed -r 's/^\"?(\<.*\>\$?)\"?$/\1/')
    if [ -z "$RESULT" ] ; then
        echo $DEFAULT
    else
        echo $RESULT
    fi
}    


## Checks if the version of erlang installed is compatible with this script
check_erlang_version(){
    printf "Checking Erlang Runtime version... "
    if [ -n "$ERLANG_VERSION_OS" ]; then
        if [ $ERLANG_VERSION_OS -ge $ERLANG_VERSION ]; then
            printf "OK\n"
        else
            printf "ERROR\n"
            die "Erlang required: $ERLANG_VERSION Installed: $ERLANG_VERSION_OS"
        fi 
    else
        die "Erlang required: $ERLANG_VERSION"
    fi
}

# Remove all deps
function clean_deps(){
    echo "Clearing the deps folder..."
    rm -rf ./deps
    rm -rf ./ebin
}

# Ensure rebar3 is available
ensure_rebar() {
    if command -v rebar3 &> /dev/null; then
        REBAR="rebar3"
    elif [ -f tools/rebar/rebar3 ]; then
        REBAR="tools/rebar/rebar3"
    else
        echo "Rebar not found. Downloading rebar3 (v3.24.0)..."
        mkdir -p tools/rebar
        if command -v wget &> /dev/null; then
            wget https://github.com/erlang/rebar3/releases/download/3.24.0/rebar3 -O tools/rebar/rebar3
        elif command -v curl &> /dev/null; then
            curl -L -o tools/rebar/rebar3 https://github.com/erlang/rebar3/releases/download/3.24.0/rebar3
        else
            die "Error: wget or curl not found to download rebar3." 1
        fi
        chmod +x tools/rebar/rebar3
        REBAR="tools/rebar/rebar3"
    fi
    echo "Using rebar: $REBAR"
}

# ========================== main ==============================

if [ "$1" = "--help" ]; then
    help
fi

# Read command line parameters
for P in $*; do
    if [[ "$P" =~ ^--.+$ ]]; then
        if [[ "$P" =~ ^--skip[\_-]deps=(true|false)$ ]]; then
            SKIP_DEPS="$(echo $P | cut -d= -f2)"
        elif [[ "$P" =~ ^--skip[\_-]clean=(true|false)$ ]]; then
            SKIP_CLEAN="$(echo $P | cut -d= -f2)"
        elif [[ "$P" =~ ^--keep[\_-]db=(true|false)$ ]]; then
            KEEP_DB="$(echo $P | cut -d= -f2)"
        elif [[ "$P" =~ --skip[\_-]deps?$ ]]; then
            SKIP_DEPS="true"
        elif [[ "$P" =~ --skip[\_-]clean$ ]]; then
            SKIP_CLEAN="true"
        elif [ "$P" = "--clean" ]; then
            SKIP_CLEAN="false"
        elif [[ "$P" =~ --keep[\_-]db$ ]]; then
            KEEP_DB="true"
        elif [ "$P" = "--release" ]; then
            BUILD_RELEASE="true"
        elif [ "$P" = "--help" ]; then
            help
        else
            echo "Invalid parameter: $P"
            help
        fi
    fi
done

check_erlang_version

echo "============================================================================="
echo "Erlang version: $ERLANG_VERSION_OS"
echo "Skip get-deps before build: $SKIP_DEPS" 
echo "Skip clear before build: $SKIP_CLEAN" 
echo "Keep database before build: $KEEP_DB" 
echo "Build release after build: $BUILD_RELEASE" 
echo "Date: $(date '+%d/%m/%Y %H:%M:%S')"
echo "============================================================================="

# Clean somes files
rm -f *.dump
rm -Rf priv/log

if [ "$KEEP_DB" = "false" ]; then
    echo "Clearing the db folder before build..."
    rm -Rf priv/db
    rm -Rf ~/.erlangms/db
fi    

ensure_rebar

echo "Compiling the project erlangms..."


if [ "$SKIP_DEPS" = "false" ]; then
    clean_deps
    if [ "$SKIP_CLEAN" = "false" ]; then    
        $REBAR clean
        $REBAR get-deps
        $REBAR compile    
    else
        $REBAR get-deps
        $REBAR compile    
    fi
else
    if [ "$SKIP_CLEAN" = "false" ]; then    
        $REBAR clean
        $REBAR compile    
    else
        $REBAR compile    
    fi
fi

if [ "$?" = "1" ]; then
    echo "Oops, something wrong!"
else
    # Build release if requested
    if [ "$BUILD_RELEASE" = "true" ]; then
        if [ -f "rel/release.sh" ]; then
            echo "Executing release script..."
            chmod +x rel/release.sh
            ./rel/release.sh
        else
            echo "Release script not found at rel/release.sh"
        fi
    fi
fi
