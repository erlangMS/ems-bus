#!/bin/bash
#
# Autor: Everton de Vargas Agilar
# Data: 08/06/2016
#
# Objective: To generate the bus release in the main Linux distros
#
# How to use: 
#
#    $ ./release.sh
#
#
## Software modification history:
#
# Data       |  Quem           |  Mensagem  
# -----------------------------------------------------------------------------------------------------
# 28/11/2016  Everton Agilar     Release inicial do script de release
# 06/07/2017  Everton Agilar     New: --skip_build
# 28/09/2017  Everton Agilar     New: --clean
#
########################################################################################################

# Imprime uma mensagem e termina o script
# Parâmetros:
#  $1  - Mensagem que será impressa 
#  $2  - Código de retorno para o comando exit (default 1)
die () {
    echo "$1"
    exit ${2:-1}
}

# Parameters
# script is in rel/ directory, so we need to go up if running from there, 
# or stay if running from root. 
# Better approach: determine script directory and work from there.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")
WORKING_DIR=$PROJECT_ROOT

cd "$WORKING_DIR" || die "Could not change to working directory $WORKING_DIR"

SKIP_BUILD="false"

# Get ErlangMS version in the file src/ems_bus.app.src
VERSION_RELEASE=$(cat src/ems_bus.app.src | sed -rn  's/^.*\{vsn.*([0-9]{1,2}\.[0-9]{1,2}.[0-9]{1,2}).*$/\1/p')
[ -z "$VERSION_RELEASE" ] && die "Could not get version to be generated in src/ems_bus.app.src"

RELEASE_FILE="ems-bus-$VERSION_RELEASE.tar.gz"


# ***** Clean ******
clean(){
	echo "Clean release build..."
	rm -Rf _build/default/rel/ems_bus
	rm -f *.tar.gz
	rm -f *.tar
}


# show help 
help(){
	echo "How to use: ./rel/release.sh (from project root) or ./release.sh (from rel/)"
	echo
	echo "Additional parameters:"
	echo "  --skip-build		-> skip build with rebar. Default is false."
	echo "  --clean          	-> clean build release."
	exit 0
}


make_release(){
	if [ "$SKIP_BUILD" = "false" ]; then
		echo 'Recompiling the project with rebar3...'
		./build.sh || die "Build failed"
	fi


	# ******** Gera o release *********
	echo 'Begin generate release with rebar3 now...'
    
    # Ensure rebar3 is available
    if [ ! -f "tools/rebar/rebar3" ]; then
         die "rebar3 not found at tools/rebar/rebar3"
    fi

	./tools/rebar/rebar3 release || die 'Failed to generate release with rebar3 release!'
    ./tools/rebar/rebar3 tar || die 'Failed to generate release tarball with rebar3 tar!'

    # The tarball is generated in _build/default/rel/ems_bus/ems_bus-VERSION.tar.gz
    # We want to move it to the root or where expected
    
    GENERATED_TAR="_build/default/rel/ems_bus/ems_bus-$VERSION_RELEASE.tar.gz"
    
    if [ -f "$GENERATED_TAR" ]; then
        cp "$GENERATED_TAR" "$RELEASE_FILE"
        echo "Release generated at $RELEASE_FILE"
        
        # Cria cópia com nome fixo para facilitar build do Docker
        cp "$GENERATED_TAR" "ems-bus.tar.gz"
        echo "Docker-friendly copy created at ems-bus.tar.gz"
    else
        die "Could not find generated tarball at $GENERATED_TAR"
    fi

}


# *************** main ***************

echo "Start erlangms release tool"

# Read command line parameters
for P in "$@"; do
	if [[ "$P" =~ ^--.+$ ]]; then
		if [ "$P" = "--help" ]; then
			help
		elif [[ "$P" = "--clean" ]]; then
			clean
			exit 0
		elif [[ "$P" =~ --skip[_-]build ]]; then
			SKIP_BUILD="true"
		else
			echo "Invalid parameter: $P"
			help
		fi
	fi
done

clean

# check remove link to fix Unable to generate spec: read file info
if [ -L /usr/lib/erlang/man ]; then
	echo "Preciso de permissão para remover o link /usr/lib/erlang/man (fix Unable to generate spec: read file info)"
	sudo rm  /usr/lib/erlang/man
fi	

if [ "$SKIP_BUILD" = "false" ]; then
	make_release
fi

echo "Cleaning build artifacts..."
rm -Rf _build/default/rel/ems_bus

cd $WORKING_DIR
echo "Ok!"
echo "Release file: $RELEASE_FILE"


