#!/bin/bash
#
# Author: Renato Carauta Ribeiro
# Date: 26/10/2017
#
# Goal: Build frontend application and compile dependndecy modules
#
#
#
## Software modification history:
#
# Data       |  Quem           |  Mensagem  
# -----------------------------------------------------------------------------------------------------
# 26/10/2017  Renato Carauta     Initial release
#
#
#
#
#
########################################################################################################

CURRENT_DIR=$(pwd)
VERSION_SCRIPT="1.0.0"


# Imprime na tela a ajuda do comando
help() {
	echo "Build modules frontend (Version $VERSION_SCRIPT)"
	echo "how to use: sudo ./build-modules.sh"
	echo ""
	echo "Additional parameters:"
	echo "  --modules                      -> name of all modules to compile (separete modules with ,)"
	echo
	echo "Obs.: Use only com root or sudo!"
	cd $CURRENT_DIR
	exit 1
}



# Imprime uma mensagem e termina o sistema
# Parâmetros:
#  $1  - Mensagem que será impressa 
#  $2  - Código de Return para o comando exit
die () {
    echo $1
    exit $2
}


# Não precisa ser root para pedir ajuda
if [ "$1" = "--help" ]; then
	help
fi

# Make sure only root can run our script
if [[ $EUID -ne 0 ]]; then
   echo "Only the root user can build docker images" 1>&2
   exit 1
fi



# Identify the linux distribution: ubuntu, debian, centos
LINUX_DISTRO=$(awk -F"=" '{ if ($1 == "ID"){ 
								gsub("\"", "", $2);  print $2 
							} 
						  }' /etc/os-release)

# Get linux description
LINUX_DESCRIPTION=$(awk -F"=" '{ if ($1 == "PRETTY_NAME"){ 
									gsub("\"", "", $2);  print $2 
								 } 
							   }'  /etc/os-release)


LINUX_VERSION_ID=$(awk -F"=" '{ if ($1 == "VERSION_ID"){ 
									gsub("\"", "", $2);  print $2 
								 } 
							   }'  /etc/os-release)



# Versões do npm e node necessárias. 
# Será verificado se as versões instaladas estão igual ou maiores do que as definidas aqui
NPM_VERSION="4.2.0"
NODE_VERSION="v7.10.0"
DOCKER_VERSION="17.03.2"

# O nome do projeto é o nome do próprio projeto docker mas sem o sufíxo .docker
APP_NAME='';

# Github repository ERLANGMS release: onde está o setup do barramento
ERLANGMS_RELEASE_URL="https://github.com/erlangms/releases/raw/master"

# Onde está o template docker utilizado por este build
ERLANGMS_DOCKER_GIT_URL="https://github.com/erlangMS/docker"

LOG_FILE="$CURRENT_DIR/build-frontend.log"

# Modules need to compile
MODULES=''


# Build node modules
NAME_MODULE=''
ES_MODULE=''


add_user(){
	echo 'Add user npm for publish all modules'
    npm adduser 
	echo 'user npm added'
}


build_modules(){
	    	                  	
		echo $MODULES > /tmp/node_modules | sed -i 's/,/\n/g' /tmp/node_modules   
		
		while read X; 
		do 		
			echo "Building module $X"
			cd $CURRENT_DIR/$X	
			npm run build
			echo "Module $X compile"
			echo "Module $X push in npm repository"	
			
		    egrep '("module".*:.*".\/modules\/)'.*.js package.json> /tmp/module
		    egrep '("es2015".*:.*".\/modules\/)'.*.js package.json> /tmp/es2015
			
			NAME_MODULE=$(egrep -o '\/.*.js' /tmp/module)
			ES_MODULE=$(egrep -o '\/.*.js' /tmp/es2015)
				
			cd dist
			
			echo "NAME_MODULE: $NAME_MODULE ES_MODULE: $ES_MODULE"
			
			sed -i 's/seguranca\/index/seguranca/g'  $CURRENT_DIR/$X/dist$NAME_MODULE 
			sed -i 's/seguranca\/index/seguranca/g'	 $CURRENT_DIR/$X/dist$ES_MODULE
			
			npm publish	
			echo "Module $X in npm repository"
		done < /tmp/node_modules

	echo "Modules generated and push in npm"
	
}



# Verifica se a versão do npm instalado é compatível com este script de build
check_npm_version(){
	printf "Checking installed npm version... "
	npm --version > /dev/null || die "O npm não está instalado, build cancelado!"
	NPM_VERSION_OS=$(npm --version)
	NPM_VERSION2=$(echo $NPM_VERSION | sed -r 's/[^0-9]+//g')
	NPM_VERSION_OS=$(echo $NPM_VERSION_OS | sed -r 's/[^0-9]+//g')
	if [ "$NPM_VERSION_OS" -ge "$NPM_VERSION2" ]; then
		printf "OK\n"
	else
		printf "ERROR\n"
		die "Build canceled because the npm installed is incompatible with this software. Expected version: $NPM_VERSION"
	fi 
}


# Verifica se o node instalado é compatível com este script de build
check_node_version(){
	printf "Checking installed node version ... "
	node --version > /dev/null || die "O node não está instalado, build cancelado!"
	NODE_VERSION_OS=$(node --version)
	NODE_VERSION2=$(echo $NODE_VERSION | sed -r 's/[^0-9]+//g')
	NODE_VERSION_OS=$(echo $NODE_VERSION_OS | sed -r 's/[^0-9]+//g')
	if [ "$NODE_VERSION_OS" -ge "$NODE_VERSION2" ]; then
		printf "OK\n"
	else
		printf "ERROR\n"
		die "Build canceled because the installed node is incompatible with this software. Expected version: $NODE_VERSION"
	fi 
}


######################################## main ########################################

# Command line parameters
for P in $*; do
	# Permite informar a tag no gitlab para gerar a imagem. 
	# Se não informar, busca a última tag
	if [[ "$P" =~ ^--modules=.+$ ]]; then
		MODULES="$(echo $P | cut -d= -f2)"	
	fi
done

check_npm_version
check_node_version

add_user
build_modules












