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
# 23/09/2017  Everton Agilar     New: --push
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

clear

echo "Start erlangms release tool ( Date: $(date '+%d/%m/%Y %H:%M:%S')  Distro: $LINUX_DISTRO )"
echo "Linux: $LINUX_DESCRIPTION  Version: $LINUX_VERSION_ID"

# Parameters
WORKING_DIR=$(pwd)
RELEASE_PATH=$WORKING_DIR
GIT_RELEASE_REPO=https://github.com/erlangms/releases
BUILD_DEB_FLAG="false"  
BUILD_RPM_FLAG="false"  
SKIP_BUILD="true"
PUSH="false"

# Imprime uma mensagem e termina o script
# Parâmetros:
#  $1  - Mensagem que será impressa 
die () {
    echo $1
    exit 1
}


# ***** Clean ******
clean(){
	echo "Clean release build..."
	cd $WORKING_DIR
	rm -Rf ems-bus
	rm -Rf ems_bus
	#rm -f *.tar.gz
	rm -f *.tar
	rm -f ../priv/scripts/*.log
	rm -f ../priv/scripts/*.tar
	rm -f ../priv/scripts/~*
	rm -rf ../priv/db
	rm -rf ../priv/log
	rm -rf ../priv/tmp
	rm -rf ../priv/archive
	
}


# show help 
help(){
	echo "release.sh tool"
	echo "How to use: ./release.sh"
	echo
	echo "Additional parameters:"
	echo "  --skip-build=true|false		-> skip build with rebar. Default is true."
	echo "  --clean          			-> clean build release."
	echo "  --distro_name=name    		-> define the distro name."
	exit 1
}




# make release for each distro
make_release(){
	cd $WORKING_DIR

	# Get ErlangMS version in the file src/ems_bus.app.src
	VERSION_RELEASE=$(cat ../src/ems_bus.app.src | sed -rn  's/^.*\{vsn.*([0-9]{1,2}\.[0-9]{1,2}.[0-9]{1,2}).*$/\1/p')
	[ -z "$VERSION_RELEASE" ] && die "Could not get version to be generated in rebar.config"

	echo "Please wait, generating the release $VERSION_RELEASE of the ems-bus, this may take a while!"


	# ########## Recompile the project before generating the release ########## 
	
	cd ..
	if [ "$SKIP_BUILD" = "false" ]; then
		echo 'Recompiling the fonts with rebar...'
		./build.sh
	fi


	# rebar is installed
	#if ! rebar --version 2> /dev/null ]; then
	#	if [ "$LINUX_DISTRO" = "ubuntu" ]; then
	#		echo "O software de build rebar não está instalado mas eu posso instalar para você!"
	#		sudo apt-get install rebar
	#	fi
	#fi


	# ******** Gera o release na pasta rel *********
	echo 'Begin generate release with rebar now...'
	cd rel
	../tools/rebar/rebar generate || die 'Failed to generate release with rebar compile generate!'

	mv ems_bus ems-bus
	mv ems-bus/bin/ems_bus ems-bus/bin/ems-bus


	#Creates the symlink of the priv folder for the project lib ems_bus-$VERSION/priv
	cd ems-bus
	ln -sf lib/ems_bus-$VERSION_RELEASE/priv/ priv || die "The symbolic priv link could not be created for lib/ems_bus-$VERSION_RELEASE/priv!"
	# Faz algumas limpezas para não ir lixo no pacote
	rm -rf log || die 'Could not remove log folder in cleanup!'
	rm -rf priv/db || die 'Unable to remove db folder in cleanup!'
	rm -rf priv/log || die 'Unable to remove log folder in cleanup!'
	rm -rf priv/tmp || die 'Unable to remove tmp folder in cleanup!'
	rm -rf priv/archive || die 'Unable to remove tmp archive in cleanup!'
	cd ..


	# ####### Create the package ems-bus-x.x.x.tar.gz #######

	# Create the package file gz
	echo "Begin create compress file ems-bus-$VERSION_RELEASE.gz now..."
	tar -czf ems-bus-$VERSION_RELEASE.tar.gz ems-bus/ 

}


# *************** main ***************

# Read command line parameters
for P in $*; do
	if [[ "$P" =~ ^--.+$ ]]; then
		if [ "$P" = "--help" ]; then
			help
		elif [[ "$P" = "--clean" ]]; then
			clean
			exit 1
		elif [[ "$P" =~ ^--skip[_-]build=.+$ ]]; then
			SKIP_BUILD="$(echo $P | cut -d= -f2)"
			echo "Skip build is $SKIP_BUILD..."
		elif [[ "$P" =~ --skip[_-]build ]]; then
			echo "Skip build uildis true..."
			SKIP_BUILD="true"
		elif [[ "$P" =~ --push ]]; then
			echo "Push release after build to repository..."
			PUSH="true"
		elif [[ "$P" =~ ^--distro_name=.+$ ]]; then
			LINUX_DISTRO="$(echo $P | cut -d= -f2)"
		else
			echo "Invalid parameter: $P"
			help
		fi
	else
		echo "Invalid parameter: $P"
		help
	fi
done

clean

# check remove link to fix Unable to generate spec: read file info
if [ -L /usr/lib/erlang/man ]; then
	echo "Preciso de permissão para remover o link /usr/lib/erlang/man (fix Unable to generate spec: read file info)"
	sudo rm  /usr/lib/erlang/man
fi	

make_release
clean
cd $WORKING_DIR
echo "Ok!"


