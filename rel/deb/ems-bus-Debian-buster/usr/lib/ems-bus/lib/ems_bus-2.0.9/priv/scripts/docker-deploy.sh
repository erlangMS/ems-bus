#!/bin/bash
#
# Author: Everton de Vargas Agilar
# Date: 03/07/2017
#
# Goal: Deploy erlangms docker project
#
#
#
## Software modification history:
#
# Data       |  Quem           |  Mensagem  
# -----------------------------------------------------------------------------------------------------
# 28/07/2017  Everton Agilar     Initial release
# 05/03/2018  Everton Agilar     Add url_mask option in conf file
# 10/08/2018  Everton Agilar     Passa variáveis do ambiente rest_base_url e rest_auth_url para a imagem
# 16/10/2018  Everton Agilar     Quando informa --entrypoint, inicia em primeiro plano
#
#
#
########################################################################################################

clear
WORKING_DIR=$(pwd)

# Será verificado se a versão está igual ou maior que a definida aqui
DOCKER_VERSION="17.03.2"

# Parameters
VERSION_SCRIPT="3.0.2"

echo "Deploy ErlangMS images for apps with Docker and ErlangMS Technology ( Version $VERSION_SCRIPT  Date: $(date '+%d/%m/%Y %H:%M:%S') )"


# As configurações podem estar armazenadas no diretório /etc/default/erlangms-docker
CONFIG_ARQ="/etc/default/erlangms-docker"

# HTTP Server
SERVER_ADDR=$(hostname -I | cut -d" " -f1)       
SERVER_HTTP_PORT_LISTENER=
SERVER_HTTPS_PORT_LISTENER=

ENTRYPOINT="ems-bus/bin/ems-bus console"
CLIENT_CONF="/tmp/erlangms_$$_barramento_client.conf"
CLIENT_CONF_IN_MEMORY="true"
APP_ID="0"
APP_VERSION="1.0.0"
ENVIRONMENT="desenv"
SKIP_CHECK="false"
IMAGE_ID="latest"

# Erlangms parameters
ERLANGMS_ADDR="127.0.0.1"
ERLANGMS_HTTP_PORT_LISTENER="2301"
ERLANGMS_HTTPS_PORT_LISTENER="2344"
ERLANGMS_BASE_URL=""
ERLANGMS_AUTH_URL=""
ERLANGMS_AUTH_PROTOCOL="oauth2"
ERLANGMS_URL_MASK="false"
ERLANGMS_USER="geral"
ERLANGMS_PASSWD="$(echo -n "123456" | openssl dgst -binary -sha1 | openssl base64)"
ERLANGMS_VERSION="1.0.0"

# Imprime uma mensagem e termina o sistema
# Parâmetros:
#  $1  - Mensagem que será impressa 
#  $2  - Código de retorno para o comando exit
die () {
    echo $1
    exit $2
}


# Lê uma configuração específica do arquivo de configuração. Aceita default se não estiver definido
# Parâmetros
#   $1 -> Nome da configuração. Ex. REGISTRY
#   $2 -> Valor default
le_setting () {
	KEY=$1
	DEFAULT=$2
	# Lê o valor configuração, remove espaços a esquerda e faz o unquoted das aspas duplas
	RESULT=$(egrep "^$KEY" $CONFIG_ARQ | sed -r 's/^[A-Za-z_]+=(.+)/\1/' | sed -r 's/^\"?(\<.*\>\$?)\"?$/\1/')
	if [ -z "$RESULT" ] ; then
		echo $DEFAULT
	else
		echo $RESULT
	fi
}	


# Lê as configurações para execução do arquivo de configuração default /etc/default/erlangms-docker
# Essas confiurações podem ser redefinidas via linha de comando
le_all_settings () {
	printf "Verify if exist conf file $CONFIG_ARQ... "
	if [ -f "$CONFIG_ARQ" ]; then
		printf "OK\n"
		echo "Reading settings from $CONFIG_ARQ... OK"
		REGISTRY=$(le_setting 'REGISTRY' "$REGISTRY_SERVER")
		ENVIRONMENT=$(le_setting 'ENVIRONMENT' "$ENVIRONMENT")
		SERVER_HTTP_PORT_LISTENER=$(le_setting 'SERVER_HTTP_PORT_LISTENER' "$SERVER_HTTP_PORT_LISTENER")
		SERVER_HTTPS_PORT_LISTENER=$(le_setting 'SERVER_HTTPS_PORT_LISTENER' "$SERVER_HTTPS_PORT_LISTENER")
		ENTRYPOINT=$(le_setting 'ENTRYPOINT' "$ENTRYPOINT")
		CLIENT_CONF=$(le_setting 'CLIENT_CONF' "$CLIENT_CONF")
		DOCKER_VERSION=$(le_setting 'DOCKER_VERSION' "$DOCKER_VERSION")

		# Erlangms settings
		ERLANGMS_ADDR=$(le_setting 'ERLANGMS_ADDR' "$ERLANGMS_ADDR")
		ERLANGMS_HTTP_PORT_LISTENER=$(le_setting 'ERLANGMS_HTTP_PORT' "$ERLANGMS_HTTP_PORT")
		ERLANGMS_HTTPS_PORT_LISTENER=$(le_setting 'ERLANGMS_HTTPS_PORT' "$ERLANGMS_HTTPS_PORT")
		ERLANGMS_AUTH_PROTOCOL=$(le_setting 'ERLANGMS_AUTH_PROTOCOL' "$ERLANGMS_AUTH_PROTOCOL")
		ERLANGMS_BASE_URL=$(le_setting 'ERLANGMS_BASE_URL' "$ERLANGMS_BASE_URL")
		ERLANGMS_URL_MASK=$(le_setting 'ERLANGMS_URL_MASK' "$ERLANGMS_URL_MASK")
		ERLANGMS_USER=$(le_setting 'ERLANGMS_USER' "$ERLANGMS_USER")
		ERLANGMS_PASSWD=$(le_setting 'ERLANGMS_PASSWD' "$ERLANGMS_PASSWD")

		
		# E-mail settings
		IMAP_SERVER=$(le_setting 'IMAP_SERVER' "imap.unb.br")
		SMTP_SERVER=$(le_setting 'SMTP_SERVER' "smtp.unb.br")
		SMTP_PORT=$(le_setting 'SMTP_PORT' '587')
		SMTP_LOGIN=$(le_setting 'SMTP_LOGIN')
		SMTP_PASSWD=$(le_setting 'SMTP_PASSWD')
		SMTP_DE=$(le_setting 'SMTP_DE')
		SMTP_PARA=$(echo `le_setting 'SMTP_PARA'` | tr -s ' ' |  sed -r "s/([A-Za-z0-9@\._]+) *[,$]?/'\1',/g; s/,$//")
	else
		printf "NO\n"
	fi
}


# Verifica se a versão do docker instalado é compatível com este script
check_docker_version(){
	printf "Checking installed docker version... "
	docker --version > /dev/null || die "Docker is not installed, deploy canceled!"
	DOCKER_VERSION_OS=$(docker --version)
	DOCKER_VERSION2=$(echo $DOCKER_VERSION | sed -r 's/[^0-9]+//g')
	DOCKER_VERSION_OS=$(echo $DOCKER_VERSION_OS | sed -r 's/[^0-9]+//g')
	if [ "$DOCKER_VERSION_OS" -ge "$DOCKER_VERSION2" ]; then
		printf "OK\n"
	else
		printf "ERROR\n"
		die "Deploy canceled because the docker installed is incompatible with this software. Expected version: $DOCKER_VERSION"
	fi 
}


# Imprime na tela a ajuda do comando
help() {
	echo "Deploy erlang docker image frontend (Version $VERSION_SCRIPT)"
	echo "by registry image: sudo ./docker-deploy.sh --image=image [--app=name]"
	echo "by tarfile: sudo ./docker-deploy.sh --tar[file]=image.tar [--app=name]"
	echo "by gitlab project: sudo ./docker-deploy.sh"
	echo ""
	echo "Additional parameters:"
	echo "  --app              -> name of docker app"
	echo "  --image              -> name of image app"
	echo "  --entrypoint       -> entry pont of docker image. The default is ems-bus/bin/ems-bus console"
	echo "  --registry         -> registry server"
	echo "  --http_port        -> port of http server listener"
	echo "  --https_port       -> port of https server listener"
	echo "  --environment      -> set optional environment description"
	echo "  --client_conf	     -> set client_conf filename. The default is to generate automatically"
	echo "  --skip_check	     -> skip check requirements"
	echo "  --docker_version   -> check npm version to this"
	echo "  --erlangms_addr    -> ip of erlangms"
	echo "  --erlangms_http_port   ->  port of http erlangms listener"
	echo "  --erlangms_https_port   ->  port of https erlangms listener"
	echo "  --erlangms_auth_protocol    -> authorization protocol to use. The default is oauth2"
	echo "  --erlangms_base_url    -> base url of erlangms"
	echo "  --erlangms_user    -> authorization user"
	echo "  --erlangms_passwd    -> authorization user passwd"
	echo "  --image_id         -> id of a specific docker image. The default is latest"
	echo
	echo "Obs.: Use only com root or sudo!"
	exit 1
}


# Um volume será criado ao subir a imagem docker que aponta para este arquivo.
# Este arquivo contém configurações para o cliente que é dependente do ambiente.
# Cria este arquivo se o flag CLIENT_CONF_IN_MEMORY for true
# Se o arquivo for informado com --client_conf, então o arquivo não precisa ser gerado
make_conf_file(){
	if [ "$CLIENT_CONF_IN_MEMORY" = "true" ]; then
		echo "make conf_file $CLIENT_CONF in memory..."
		echo "{\"ip\":\"$ERLANGMS_ADDR\",\"http_port\":$ERLANGMS_HTTP_PORT_LISTENER,\"https_port\":$ERLANGMS_HTTPS_PORT_LISTENER,\"base_url\":\"$ERLANGMS_BASE_URL\",\"auth_url\":\"$ERLANGMS_AUTH_URL\",\"auth_protocol\":\"$ERLANGMS_AUTH_PROTOCOL\",\"app_id\":$APP_ID,\"app_name\":\"$APP_NAME\",\"app_version\":\"$APP_VERSION\",\"environment\":\"$ENVIRONMENT\",\"docker_version\":\"$DOCKER_VERSION\",\"url_mask\":\"$ERLANGMS_URL_MASK\",\"erlangms_version\":\"$ERLANGMS_VERSION\"}" > $CLIENT_CONF
	fi
}


# Get expose ports from docker image if not defined in parameters
# Labels: HTTP_PORT and HTTPS_PORT
get_expose_ports(){
	echo "Get expose ports from image..."
	if [ -z "$SERVER_HTTP_PORT_LISTENER" ]; then
		SERVER_HTTP_PORT_LISTENER=$( sudo docker inspect $IMAGE | sed -n '/HTTP_PORT/ p' | uniq | sed -r 's/[^0-9]+//g;' )
	fi
	if [ -z "$SERVER_HTTPS_PORT_LISTENER" ]; then
		SERVER_HTTPS_PORT_LISTENER=$( sudo docker inspect $IMAGE | sed -n '/HTTPS_PORT/ p' | uniq | sed -r 's/[^0-9]+//g;' )
	fi
	if [ -z "$SERVER_HTTP_PORT_LISTENER" ]; then
		die "Inform HTTP port of docker image!"
	fi
	if [ -z "$SERVER_HTTPS_PORT_LISTENER" ]; then
		die "Inform HTTPS port of docker image!"
	fi
}


print_info(){
	echo "-----------------------------------------------------------------------------"
	echo "App id: $APP_ID"
	echo "App name: $APP_NAME"
	echo "App version: $APP_VERSION"
	echo "App environment: $ENVIRONMENT"
	echo "ErlangMS version: $ERLANGMS_VERSION"
	echo "ErlangMS base url: $ERLANGMS_BASE_URL"
	echo "ErlangMS auth url: $ERLANGMS_AUTH_URL"
	echo "ErlangMS auth protocol: $ERLANGMS_AUTH_PROTOCOL"
	echo "ErlangMS auth user: $ERLANGMS_USER"
	echo "ErlangMS server listener IP: $ERLANGMS_ADDR  HTTP/REST PORT: $ERLANGMS_HTTP_PORT_LISTENER   HTTPS/REST PORT: $ERLANGMS_HTTPS_PORT_LISTENER"
	echo "Frontend server listener IP: $SERVER_ADDR  HTTP PORT: $SERVER_HTTP_PORT_LISTENER   HTTPS PORT: $SERVER_HTTPS_PORT_LISTENER"
	echo "Frontend client conf: $CLIENT_CONF"
	echo "Docker registry: $REGISTRY"
	echo "Docker entrypoint: $ENTRYPOINT"
	echo "Docker version: $(docker --version)"
	echo "-----------------------------------------------------------------------------"
}


######################################## main ########################################

# Não precisa ser root para pedir ajuda
if [ "$1" = "--help" ]; then
	help
fi

# Make sure only root can run our script
if [[ $EUID -ne 0 ]]; then
   die "Only the root user can deploy docker images"
fi


# Lê as configurações do arquivo de configuração default /etc/default/erlangms-docker.
le_all_settings


# Read command line parameters
for P in $*; do
	if [[ "$P" =~ ^--.+$ ]]; then
		if [[ "$P" =~ ^--tar_?(file)?=.+$ ]]; then
			TAR_FILE="$(echo $P | cut -d= -f2)"
		elif [[ "$P" =~ ^--app_?(name)?=.+$ ]]; then
			APP_NAME="$(echo $P | cut -d= -f2)"
		elif [[ "$P" =~ ^--image=.+$ ]]; then
			IMAGE="$(echo $P | cut -d= -f2)"
		elif [[ "$P" =~ ^--entrypoint=.+$ ]]; then
			ENTRYPOINT="$(echo $P | cut -d= -f2)"
		elif [[ "$P" =~ ^--http_port=.+$ ]]; then
			SERVER_HTTP_PORT_LISTENER="$(echo $P | cut -d= -f2)"
		elif [[ "$P" =~ ^--https_port=.+$ ]]; then
			SERVER_HTTPS_PORT_LISTENER="$(echo $P | cut -d= -f2)"
		elif [[ "$P" =~ ^--environment=.+$ ]]; then
			ENVIRONMENT="$(echo $P | cut -d= -f2)"
		elif [[ "$P" =~ ^--skip_check$ ]]; then
			SKIP_CHECK="$(echo $P | cut -d= -f2)"
		elif [[ "$P" =~ ^--docker_version=.+$ ]]; then
			DOCKER_VERSION="$(echo $P | cut -d= -f2)"
		elif [[ "$P" =~ ^--registry=.+$ ]]; then
			REGISTRY="$(echo $P | cut -d= -f2)"
		elif [[ "$P" =~ ^--image_id=.+$ ]]; then
			IMAGE_ID="$(echo $P | cut -d= -f2)"
		elif [[ "$P" =~ ^--erlangms_addr=.+$ ]]; then
			ERLANGMS_ADDR="$(echo $P | cut -d= -f2)"
		elif [[ "$P" =~ ^--erlangms_http_port=.+$ ]]; then
			ERLANGMS_HTTP_PORT_LISTENER_LISTENER="$(echo $P | cut -d= -f2)"
		elif [[ "$P" =~ ^--erlangms_https_port=.+$ ]]; then
			ERLANGMS_HTTPS_PORT_LISTENER_LISTENER="$(echo $P | cut -d= -f2)"
		elif [[ "$P" =~ ^--erlangms_auth_protocol=.+$ ]]; then
			ERLANGMS_AUTH_PROTOCOL="$(echo $P | cut -d= -f2)"
		elif [[ "$P" =~ ^--erlangms_base_url=.+$ ]]; then
			ERLANGMS_BASE_URL="$(echo $P | cut -d= -f2)"
		elif [[ "$P" =~ ^--client_conf=.+$ ]]; then
			CLIENT_CONF="$(echo $P | cut -d= -f2)"
			if [ ! -f "$CLIENT_CONF" ]; then
				echo "Client conf does not exist, auto generate..."
			else
				CLIENT_CONF_IN_MEMORY="false"
			fi
		elif [[ "$P" =~ ^--ERLANGMS_AUTH_URL=.+$ ]]; then
			ERLANGMS_AUTH_URL="$(echo $P | cut -d= -f2)"
		elif [[ "$P" =~ ^--user=.+$ ]]; then
			ERLANGMS_USER="$(echo $P | cut -d= -f2)"
		elif [[ "$P" =~ ^--passwd=.+$ ]]; then
			ERLANGMS_PASSWD="$(echo $P | cut -d= -f2)"
		elif [ "$P" = "--help" ]; then
			help
		else
			echo "Invalid parameter: $P"
			help
		fi
	else
		# Se for informado apenas um parâmetro e não começa com -- então é o nome do tarfile
		if [ "$#" = "1" ]; then
			TAR_FILE=$P
		else
			echo "Invalid parameter: $P"
			help
		fi
	fi
done

if [ -z "$TAR_FILE" ]; then
	# Vamos precisar do registry. Validar registry settings
	if [ ! -z $REGISTRY ]; then
		if [[ "$REGISTRY" =~ ^[0-9a-zA-Z_.]+:[0-9]+$ ]] ; then
		   REGISTRY_PORT=$(echo $REGISTRY | awk -F: '{ print $2; }')
		   REGISTRY_SERVER=$REGISTRY
		elif [[ $REGISTRY =~ ^[0-9a-zA-Z_-.]+$ ]] ; then
			REGISTRY_SERVER=$REGISTRY:$REGISTRY_PORT
		else
			die "Parameter --registry $REGISTRY is invalid. Example: 127.0.0.1:5000"
		fi
		REGISTRY_IP="$(echo $REGISTRY_SERVER | cut -d: -f1)"
	else
		die "Parameter --registry is required. Example: 127.0.0.1:5000"
	fi
else
	# O arquivo tar foi informado, valida se existe
	if [ ! -f "$TAR_FILE" ]; then
		die "tarfile $TAR_FILE does not exist!"
	fi
fi



# Verifica se estamos dentro da pasta do projeto gitlab
CURRENT_DIR_IS_DOCKER_PROJECT_GITLAB=$(pwd | grep -c .docker$)


if [ "$SKIP_CHECK" = "false" ]; then
	check_docker_version
else
	echo "Skip check requirements enabled..."	
fi


# Erlangms settings
if [ -z "$ERLANGMS_HTTP_PORT_LISTENER" ]; then
	die "Informe HTTP port of erlangms!"
fi
if [ -z "$ERLANGMS_HTTPS_PORT_LISTENER" ]; then
	die "Informe HTTPS port of erlangms!"
fi

if [ -z "$ERLANGMS_BASE_URL" ]; then
	ERLANGMS_BASE_URL="https://$ERLANGMS_ADDR:$ERLANGMS_HTTPS_PORT_LISTENER"
fi
ERLANGMS_AUTH_URL="$ERLANGMS_BASE_URL/authorize"


# Credentials to HTTP REST
echo "Get access_token from $ERLANGMS_BASE_URL/authorize..."
ERLANGMS_ACCESS_TOKEN=$(curl -ksX POST $ERLANGMS_BASE_URL/authorize -H 'Content-Type: application/x-www-form-urlencoded' -d "grant_type=password&username=$ERLANGMS_USER&password=$ERLANGMS_PASSWD" | egrep -o "\"access_token\":? ?\"[A-Za-z0-9]+\"" | awk -F: '{ print $2 }' | sed -r 's/^\"?(\<.*\>\$?)\"?$/\1/')
ERLANGMS_AUTHORIZATION_HEADER="Bearer $ERLANGMS_ACCESS_TOKEN"
ERLANGMS_VERSION=$(curl -ks "$ERLANGMS_BASE_URL/netadm/version" -H "Authorization: $ERLANGMS_AUTHORIZATION_HEADER" | sed -r 's/[^0-9.]+//g')
if [ -z "$ERLANGMS_VERSION" ]; then
	ERLANGMS_VERSION="1.0.0"
	echo "Error: HTTT/REST request $ERLANGMS_BASE_URL/netadm/version failed, check the credentials of the configured user in /etc/default/erlangms-docker."
fi


# Se não foi informado o parâmetro --tarfile e a pasta atual 
# é a pasta do projeto do docker no gitlab, então tenta subir
if [ -z "$TAR_FILE" -a -z "$IMAGE" -a "$CURRENT_DIR_IS_DOCKER_PROJECT_GITLAB"="1" ]; then
	if [ -z "$APP_NAME" ]; then
		APP_NAME=$(basename $WORKING_DIR | sed -r 's/(.docker|_frontend)//g')
	fi
	APP_VERSION=$(docker inspect $APP_NAME | grep APP_VERSION | sed '1!d' |  sed -r 's/^.+=(.+)"$/\1/')
	IMAGE=$APP_NAME
	URL_REST_CLIENT_ID="$ERLANGMS_BASE_URL/auth/client?filter=\{%22name%22%20:%20%22$APP_NAME%22\}&fields=id&limit=1"
	APP_ID=$(curl -ks "$URL_REST_CLIENT_ID" -H "Authorization: $ERLANGMS_AUTHORIZATION_HEADER" 2>> /dev/null | sed -r 's/[^0-9.]+//g')
	if [ -z "$APP_ID" ]; then
		APP_ID=0
		echo "Error: HTTT/REST request to $URL_REST_CLIENT_ID failed, check the credentials of the configured user in /etc/default/erlangms-docker."
	fi
	get_expose_ports
	make_conf_file
	print_info

	echo "docker stop previous $IMAGE"
	docker image stop $IMAGE > /dev/null 2>&1

	echo "docker image remove previous $IMAGE"
	docker image remove $IMAGE > /dev/null 2>&1

	if [ "$ENTRYPOINT" = "ems-bus/bin/ems-bus console" ]; then
			echo docker run --network bridge -p $SERVER_HTTP_PORT_LISTENER:$SERVER_HTTP_PORT_LISTENER \
					   --network bridge -p $SERVER_ADDR:$SERVER_HTTPS_PORT_LISTENER:$SERVER_HTTPS_PORT_LISTENER \
					   -v $CLIENT_CONF:/app/$APP_NAME/barramento \
					   -e rest_base_url="$ERLANGMS_BASE_URL" \
					   -e rest_auth_url="$ERLANGMS_AUTH_URL" \
					   -dit --restart always $APP_NAME:$IMAGE_ID $ENTRYPOINT 
			docker run --network bridge -p $SERVER_HTTP_PORT_LISTENER:$SERVER_HTTP_PORT_LISTENER \
					   -v $CLIENT_CONF:/app/$APP_NAME/barramento \
					   -e rest_base_url="$ERLANGMS_BASE_URL" \
					   -e rest_auth_url="$ERLANGMS_AUTH_URL" \
					   -dit --restart always $APP_NAME:$IMAGE_ID $ENTRYPOINT 
	else
			echo docker run --network bridge -p $SERVER_HTTP_PORT_LISTENER:$SERVER_HTTP_PORT_LISTENER \
					   --network bridge -p $SERVER_ADDR:$SERVER_HTTPS_PORT_LISTENER:$SERVER_HTTPS_PORT_LISTENER \
					   -v $CLIENT_CONF:/app/$APP_NAME/barramento \
					   -e rest_base_url="$ERLANGMS_BASE_URL" \
					   -e rest_auth_url="$ERLANGMS_AUTH_URL" \
					   -it $APP_NAME:$IMAGE_ID $ENTRYPOINT 
			docker run --network bridge -p $SERVER_HTTP_PORT_LISTENER:$SERVER_HTTP_PORT_LISTENER \
					   -v $CLIENT_CONF:/app/$APP_NAME/barramento \
					   -e rest_base_url="$ERLANGMS_BASE_URL" \
					   -e rest_auth_url="$ERLANGMS_AUTH_URL" \
					   -it $APP_NAME:$IMAGE_ID $ENTRYPOINT 
	fi
	
elif [ ! -z "$IMAGE" ]; then
	if [ -z "$APP_NAME" ]; then
		APP_NAME=$(echo $IMAGE | awk -F/ '{ print $2 }')
	fi
	URL_REST_CLIENT_ID="$ERLANGMS_BASE_URL/auth/client?filter=\{%22name%22%20:%20%22$APP_NAME%22\}&fields=id&limit=1"
	APP_ID=$(curl -ks "$URL_REST_CLIENT_ID" -H "Authorization: $ERLANGMS_AUTHORIZATION_HEADER" 2>> /dev/null | sed -r 's/[^0-9.]+//g')
	if [ -z "$APP_ID" ]; then
		APP_ID=0
		echo "Error: HTTT/REST request to $URL_REST_CLIENT_ID failed, check if client $APP_NAME exist!"
	fi
	
	ID_IMAGE=$(docker ps -f name=$APP_NAME | awk '{print $1}' | sed '1d')
	if [ ! -z "$ID_IMAGE" ]; then
		echo "Stop current image $IMAGE..."
		docker stop $ID_IMAGE > /dev/null 2>&1
	fi

	LS_IMAGES=$(docker images $IMAGE)
	if [ ! -z "$LS_IMAGE" ]; then
		echo "Remove previous images $LS_IMAGES..."
		docker rmi $LS_IMAGES > /dev/null 2>&1
	fi

	docker rm erlangms_$APP_NAME > /dev/null 2>&1
	docker pull $IMAGE

	APP_VERSION=$(docker inspect $IMAGE | grep APP_VERSION | sed '1!d' |  sed -r 's/^.+=(.+)"$/\1/')

	get_expose_ports
	make_conf_file
	print_info

	if [ "$ENTRYPOINT" = "ems-bus/bin/ems-bus console" ]; then
		  echo docker run  --name erlangms_$APP_NAME \
					 --network bridge -p $SERVER_HTTP_PORT_LISTENER:$SERVER_HTTP_PORT_LISTENER \
					 -v $CLIENT_CONF:/app/$APP_NAME/barramento \
					 -e rest_base_url="$ERLANGMS_BASE_URL" \
					 -e rest_auth_url="$ERLANGMS_AUTH_URL" \
					 -dit --restart always $IMAGE:$IMAGE_ID $ENTRYPOINT 
		  docker run --name erlangms_$APP_NAME \
					 --network bridge -p $SERVER_HTTP_PORT_LISTENER:$SERVER_HTTP_PORT_LISTENER \
					 -v $CLIENT_CONF:/app/$APP_NAME/barramento \
					 -e rest_base_url="$ERLANGMS_BASE_URL" \
					 -e rest_auth_url="$ERLANGMS_AUTH_URL" \
					 -dit --restart always $IMAGE:$IMAGE_ID $ENTRYPOINT
    else
 
		  echo docker run  --name erlangms_$APP_NAME \
					 --network bridge -p $SERVER_HTTP_PORT_LISTENER:$SERVER_HTTP_PORT_LISTENER \
					 -v $CLIENT_CONF:/app/$APP_NAME/barramento \
					 -e rest_base_url="$ERLANGMS_BASE_URL" \
					 -e rest_auth_url="$ERLANGMS_AUTH_URL" \
					 -it $IMAGE:$IMAGE_ID $ENTRYPOINT 
		  docker run --name erlangms_$APP_NAME \
					 --network bridge -p $SERVER_HTTP_PORT_LISTENER:$SERVER_HTTP_PORT_LISTENER \
					 -v $CLIENT_CONF:/app/$APP_NAME/barramento \
					 -e rest_base_url="$ERLANGMS_BASE_URL" \
					 -e rest_auth_url="$ERLANGMS_AUTH_URL" \
					 -it $IMAGE:$IMAGE_ID $ENTRYPOINT
    fi

else
	if [ -z "$APP_NAME" ]; then
		APP_NAME=$(echo $TAR_FILE | awk -F: '{ print $1 }')
	fi
	APP_VERSION=$(docker inspect $APP_NAME | | grep APP_VERSION | sed '1!d' |  sed -r 's/^.+=(.+)"$/\1/')
	IMAGE=$APP_NAME
	APP_ID=$(curl -ks "$ERLANGMS_BASE_URL/auth/client?filter=\{%22name%22%20:%20%22$APP_NAME%22\}&fields=id&limit=1" -H "Authorization: $ERLANGMS_AUTHORIZATION_HEADER" | sed -r 's/[^0-9.]+//g')
	if [ -z "$APP_ID" ]; then
		APP_ID=0
		echo "Error: HTTT/REST request to $ERLANGMS_BASE_URL/auth/client failed, check the credentials of the configured user in /etc/default/erlangms-docker."
	fi
	get_expose_ports
	make_conf_file
	print_info

	echo "Stop current image $IMAGE..."
	docker image stop $IMAGE > /dev/null 2>&1

	echo "Remove previous images $IMAGE..."
	docker image remove $IMAGE > /dev/null 2>&1

	echo docker load -i $TAR_FILE
	docker load -i $TAR_FILE

	if [ "$ENTRYPOINT" = "ems-bus/bin/ems-bus console" ]; then
			echo docker run --network bridge -p $SERVER_HTTP_PORT_LISTENER:$SERVER_HTTP_PORT_LISTENER \
					   -v $CLIENT_CONF:/app/$APP_NAME/barramento \
					   -e rest_base_url="$ERLANGMS_BASE_URL" \
					   -e rest_auth_url="$ERLANGMS_AUTH_URL" \
					   -dit --restart always $APP_NAME:$IMAGE_ID $ENTRYPOINT 
			docker run --network bridge -p $SERVER_HTTP_PORT_LISTENER:$SERVER_HTTP_PORT_LISTENER \
					   -v $CLIENT_CONF:/app/$APP_NAME/barramento \
					   -e rest_base_url="$ERLANGMS_BASE_URL" \
					   -e rest_auth_url="$ERLANGMS_AUTH_URL" \
					   -dit --restart always $APP_NAME:$IMAGE_ID $ENTRYPOINT 
	else
			echo docker run --network bridge -p $SERVER_HTTP_PORT_LISTENER:$SERVER_HTTP_PORT_LISTENER \
					   -v $CLIENT_CONF:/app/$APP_NAME/barramento \
					   -e rest_base_url="$ERLANGMS_BASE_URL" \
					   -e rest_auth_url="$ERLANGMS_AUTH_URL" \
					   -it $APP_NAME:$IMAGE_ID $ENTRYPOINT 
			docker run --network bridge -p $SERVER_HTTP_PORT_LISTENER:$SERVER_HTTP_PORT_LISTENER \
					   -v $CLIENT_CONF:/app/$APP_NAME/barramento \
					   -e rest_base_url="$ERLANGMS_BASE_URL" \
					   -e rest_auth_url="$ERLANGMS_AUTH_URL" \
					   -it $APP_NAME:$IMAGE_ID $ENTRYPOINT 
	fi
fi
