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
# 29/09/2017  Everton Agilar     Reads /etc/default/erlangms-build
# 05/05/2018  Everton Agilar     Build with docker
#
#
#
#
#
#
########################################################################################################

LINUX_DISTRO=$(awk -F"=" '{ if ($1 == "ID"){ 
                                gsub("\"", "", $2);  print $2 
                            } 
                          }' /etc/os-release)

VERSION_SCRIPT="3.0.1"


# Necessário para as bibliotecas c utilizadas
export CFLAGS='-std=c11 -static -w'
export CXXFLAGS='-w'
echo "Usando CFLAGS=$CFLAGS"

# Erlang Runtime version required > 20
ERLANG_VERSION=20

# Skip deps before build 
SKIP_DEPS="false"

# Skip clean before build 
SKIP_CLEAN="false"

KEEP_DB="false"

# Release flag
BUILD_RELEASE="false"


if [ "$LINUX_DISTRO" = "centos" -o "$LINUX_DISTRO" = "redhat" -o "$LINUX_DISTRO" = "fedora" -o "$LINUX_DISTRO" = "kdeneon" ]; then
    BUILD_RPM_FLAG="true"
    if ! g++ --version 2> /dev/null ; then
        echo "G++ is not installed, build canceled!!!"
        echo "Use: sudo yum group install \"Development Tools\""
        exit
    fi
fi
if [ ! "$BUILD_RPM_FLAG" = "true" ]; then
    if [ "$LINUX_DISTRO" = "debian" -o "$LINUX_DISTRO" = "ubuntu" -o "$LINUX_DISTRO" = "deepin" -o "$LINUX_DISTRO" = "linuxmint" ]; then
        BUILD_DEB_FLAG="true"  
        if ! g++ --version 2> /dev/null ; then
            echo "Tool dpkg-deb is not installed, build canceled!!!"
            echo "Use: sudo apt install build-essential"
            exit
        fi
    else
        BUILD_DEB_FLAG="false"  
    fi
fi



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


# Reads the settings for running the default configuration file /etc/default/erlangms-docker
# These configurations can be redefined via the command line
le_all_settings () {
    printf "Verify if exist conf file $CONFIG_ARQ... "
    if [ -f "$CONFIG_ARQ" ]; then
        printf "OK\n"
        echo "Reading settings from $CONFIG_ARQ... OK"
        SKIP_DEPS=$(le_setting 'SKIP_DEPS' "$SKIP_DEPS")
        SKIP_CLEAN=$(le_setting 'SKIP_CLEAN' "$SKIP_CLEAN")
        KEEP_DB=$(le_setting 'KEEP_DB' "$KEEP_DB")
        ERLANG_VERSION=$(le_setting 'ERLANG_VERSION' "$ERLANG_VERSION" | sed 's/[^0-9]//g')
    else
        printf "NO\n"
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
            die "Build canceled because the Erlang Runtime installed is incompatible with this software. Expected version: $ERLANG_VERSION"
        fi 
    else
        die "Oops, you should install Erlang Runtime $ERLANG_VERSION first !!!"
    fi
}

# Remove all deps except jiffy
function clean_deps(){
    echo "Clearing the deps folder..."
    rm -rf ./deps
}

ensure_rebar() {
    if command -v rebar3 &> /dev/null; then
        REBAR="rebar3"
    elif command -v rebar &> /dev/null; then
        REBAR="rebar"
    elif [ -f tools/rebar/rebar3 ]; then
        REBAR="tools/rebar/rebar3"
    else
        echo "Rebar not found. Downloading rebar3 (v3.22.0)..."
        mkdir -p tools/rebar
        if command -v wget &> /dev/null; then
            wget https://github.com/erlang/rebar3/releases/download/3.22.0/rebar3 -O tools/rebar/rebar3
        elif command -v curl &> /dev/null; then
            curl -L -o tools/rebar/rebar3 https://github.com/erlang/rebar3/releases/download/3.22.0/rebar3
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

le_all_settings

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


# Erlang Runtime version installled
ERLANG_VERSION_OS=`erl -eval 'erlang:display(erlang:system_info(otp_release)), halt().'  -noshell 2> /dev/null | sed 's/[^0-9]//g'`

# Get linux description
LINUX_DESCRIPTION=$(awk -F"=" '{ if ($1 == "PRETTY_NAME"){ 
                                gsub("\"", "", $2);  print $2 
                                } 
                                }'  /etc/os-release)


echo "============================================================================="
echo "Distro: $LINUX_DESCRIPTION"
echo "Erlang version: $ERLANG_VERSION_OS"
echo "Skip get-deps before build: $SKIP_DEPS" 
echo "Skip clear before build: $SKIP_CLEAN" 
echo "Keep database before build: $KEEP_DB" 
echo "Build release after build: $BUILD_RELEASE" 
echo "Date: $(date '+%d/%m/%Y %H:%M:%S')"
echo "============================================================================="

# Clean somes files
rm -f *.dump

if [ "$KEEP_DB" = "false" ]; then
    echo "Clearing the db folder before build..."
    rm -Rf priv/db
    rm -Rf ~/.erlangms/db
fi    

rm -Rf priv/log

echo "Compiling the project erlangms..."

ensure_rebar

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
    # Copy artifacts to ./ebin and ./deps for backward compatibility
    echo "Copying artifacts to ./ebin and ./deps..."
    mkdir -p ebin
    cp -r _build/default/lib/ems_bus/ebin/* ebin/

    mkdir -p deps
    for d in _build/default/lib/*; do
        NAME=$(basename $d)
        if [ "$NAME" != "ems_bus" ]; then
            mkdir -p deps/$NAME/ebin
            cp -r $d/ebin/* deps/$NAME/ebin/
        fi
    done

    echo "Ok!"

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
