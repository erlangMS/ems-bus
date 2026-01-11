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
#
#
#
## Software modification history:
#
# Data       |  Quem           |  Mensagem  
# -----------------------------------------------------------------------------------------------------
# 28/11/2016  Everton Agilar     Release inicial do script de release
# 05/03/2017  Everton Agilar     Improve release to deb and rpm
# 06/07/2017  Everton Agilar     New: --skip_build
# 28/09/2017  Everton Agilar     New: --clean
# 25/10/2018  Everto Agilar		 Faz build somente do SO ativo usando o template deste SO
#
#
#
#
#
########################################################################################################

# Identify the linux distribution: ubuntu, debian, centos
LINUX_DISTRO=$(awk -F"=" '{ if ($1 == "ID"){ 
								gsub("\"", "", $2);  print $2 
							} 
						  }' /etc/os-release)

LINUX_DESCRIPTION=$(awk -F"=" '{ if ($1 == "PRETTY_NAME"){ 
									gsub("\"", "", $2);  print $2 
								 } 
							   }'  /etc/os-release)

LINUX_VERSION_ID=$(awk -F"=" '{ if ($1 == "VERSION_ID"){ 
									gsub("\"", "", $2);  print $2 
								 } 
							   }'  /etc/os-release)

# Imprime uma mensagem e termina o script
# Parâmetros:
#  $1  - Mensagem que será impressa 
#  $2  - Código de retorno para o comando exit (default 1)
die () {
    echo "$1"
    exit ${2:-1}
}

clear

echo "Start erlangms release tool ( Date: $(date '+%d/%m/%Y %H:%M:%S')  Distro: $LINUX_DISTRO )"
echo "Linux: $LINUX_DESCRIPTION  Version: $LINUX_VERSION_ID"

# Parameters
# script is in rel/ directory, so we need to go up if running from there, 
# or stay if running from root. 
# Better approach: determine script directory and work from there.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")
WORKING_DIR=$PROJECT_ROOT

cd "$WORKING_DIR" || die "Could not change to working directory $WORKING_DIR"

SKIP_BUILD="false"
SKIP_BUILD_IMAGE="false"

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
	echo "release.sh tool"
	echo "How to use: ./rel/release.sh (from project root) or ./release.sh (from rel/)"
	echo
	echo "Additional parameters:"
	echo "  --skip-build		-> skip build with rebar. Default is false."
	echo "  --skip-build-image	-> skip docker image build. Default is false."
	echo "  --clean          	-> clean build release."
	exit 1
}




# make release for each distro
# make release for each distro
make_release(){
	echo "Please wait, generating the release $VERSION_RELEASE of the ems-bus, this may take a while!"


	# ########## Recompile the project before generating the release ########## 
	
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
    else
        die "Could not find generated tarball at $GENERATED_TAR"
    fi

}


make_imagem(){
    if [ -d "docker" ]; then
	    cd docker
	    cp ../$RELEASE_FILE . 
	    sudo docker compose build
        cd ..
    else
        echo "Docker directory not found, skipping image build."
    fi
}

# *************** main ***************

# Read command line parameters
# Read command line parameters
for P in "$@"; do
	if [[ "$P" =~ ^--.+$ ]]; then
		if [ "$P" = "--help" ]; then
			help
		elif [[ "$P" = "--clean" ]]; then
			clean
			exit 0
		elif [[ "$P" =~ --skip[_-]build[_-]image ]]; then
			SKIP_BUILD_IMAGE="true"
		elif [[ "$P" =~ --skip[_-]build ]]; then
			SKIP_BUILD="true"
		else
			echo "Invalid parameter: $P"
			help
		fi
	fi
done

echo "Skip build is $SKIP_BUILD..."
echo "Skip build image is $SKIP_BUILD_IMAGE..."

clean

# check remove link to fix Unable to generate spec: read file info
if [ -L /usr/lib/erlang/man ]; then
	echo "Preciso de permissão para remover o link /usr/lib/erlang/man (fix Unable to generate spec: read file info)"
	sudo rm  /usr/lib/erlang/man
fi	

if [ "$SKIP_BUILD" = "false" ]; then
	make_release
fi

if [ "$SKIP_BUILD_IMAGE" = "false" ]; then
	make_imagem
fi

# Clean only build artifacts, not the release file
echo "Cleaning build artifacts..."
rm -Rf _build/default/rel/ems_bus

cd $WORKING_DIR
echo "Ok!"
echo "Release file: $RELEASE_FILE"


