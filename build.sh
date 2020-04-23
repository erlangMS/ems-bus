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

if [ -z "$ERLANGMS_IN_DOCKER" ]; then
	echo "Build erlangms tool ( Version: $VERSION_SCRIPT   Hostname: `hostname` )"
fi

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

# Profile of build: local or docker
PROFILE="local"


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

function prerequisites_docker(){
  printf "Checking ErlangMS prerequisites... "
  apt-get -y install libodbc1

  echo "Create .hosts.erlang if it not exist..."
  if [ ! -f $HOME/.hosts.erlang ]; then
	echo \'$(hostname | cut -d. -f1)\'. > $HOME/.hosts.erlang 
  fi

  echo "Config /etc/odbcinst.ini FreeTDS SQL-server driver..."
  JTDS_ENTRY_CONF=$(sed -rn '/\[FreeTDS\]/, /(^$|^#)/p' /etc/odbcinst.ini 2> /dev/null)
  if [ -z "$JTDS_ENTRY_CONF" ]; then
	LIB_TDODBC_PATH="/usr/lib/x86_64-linux-gnu/odbc/libtdsodbc.so"
	if [ ! -z "$LIB_TDODBC_PATH" ]; then
		echo " " >> /etc/odbcinst.ini 
		echo "# Driver for SQL-server" >> /etc/odbcinst.ini 
		echo "[FreeTDS]" >> /etc/odbcinst.ini 
		echo "Description=FreeTDS Driver" >> /etc/odbcinst.ini 
		echo "Driver=$LIB_TDODBC_PATH" >> /etc/odbcinst.ini 
		echo " " >> /etc/odbcinst.ini 
	fi
  fi

  echo "Tunning fs.file-max. At least it should be 1000000..."
  FILE_MAX_DEF=1000000
  FILE_MAX=$(cat /proc/sys/fs/file-max)
  if [ $FILE_MAX -lt $FILE_MAX_DEF ]; then
		# Ajusta ou adiciona o valor para fs.file-max
		if grep -q 'fs.file-max' /etc/sysctl.conf ; then
			sed -ri "s/^fs.file-max=[0-9]{1,10}$/fs.file-max=$FILE_MAX_DEF/" /etc/sysctl.conf
		else
			echo "" >> /etc/sysctl.conf
			echo "# File descriptors limit" >> /etc/sysctl.conf
			echo "fs.file-max=$FILE_MAX_DEF" >> /etc/sysctl.conf
		fi
		sysctl -p > /dev/null 2>&1
  fi


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
		elif [[ "$P" =~ ^--profile=(local|docker)$ ]]; then
			PROFILE="$(echo $P | cut -d= -f2)"
		elif [ "$P" = "--help" ]; then
			help
		else
			echo "Invalid parameter: $P"
			help
		fi
	fi
done


if [ "$PROFILE" = "docker" ]; then
	#VERSION=$(cat src/ems_bus.app.src | sed -rn  's/^.*\{vsn.*([0-9]{1,2}\.[0-9]{1,2}.[0-9]{1,2}).*$/\1/p')
	VERSION=$$
	IMAGE=erlangms

	ID_IMAGE=$(sudo docker ps -f name=erlangms | awk '{print $1}' | sed '1d')
	if [ ! -z "$ID_IMAGE" ]; then
		echo "Stop current image $IMAGE..."
		sudo docker stop $ID_IMAGE > /dev/null 2>&1
	fi

	LS_IMAGES=$(sudo docker images $IMAGE)
	if [ ! -z "$LS_IMAGE" ]; then
		echo "Remove previous images $LS_IMAGES..."
		sudo docker rmi $LS_IMAGES > /dev/null 2>&1
	fi

	sudo docker rm erlangms > /dev/null 2>&1

	sudo docker build --no-cache -t $IMAGE:$VERSION $(dirname $0)

	ID=$(sudo docker images | grep "$IMAGE" | head -n 1 | awk '{print $3}')

	sudo docker tag "$ID" $IMAGE:latest
	sudo docker tag "$ID" $IMAGE:$VERSION
else
	if [ "$ERLANGMS_IN_DOCKER" = "true" ]; then
		prerequisites_docker
	fi

	# Erlang Runtime version installled
	ERLANG_VERSION_OS=`erl -eval 'erlang:display(erlang:system_info(otp_release)), halt().'  -noshell 2> /dev/null | sed 's/[^0-9]//g'`

	# Get linux description
	LINUX_DESCRIPTION=$(awk -F"=" '{ if ($1 == "PRETTY_NAME"){ 
										gsub("\"", "", $2);  print $2 
									 } 
								   }'  /etc/os-release)

	if [ -s "$ERLANGMS_IN_DOCKER" ]; then
		check_erlang_version	
	fi


	echo "============================================================================="
	echo "Distro: $LINUX_DESCRIPTION"
	echo "Erlang version: $ERLANG_VERSION_OS"
	echo "Skip get-deps before build: $SKIP_DEPS" 
	echo "Skip clear before build: $SKIP_CLEAN" 
	echo "Keep database before build: $KEEP_DB" 
	echo "Date: $(date '+%d/%m/%Y %H:%M:%S')"
	echo "============================================================================="

	# Clean somes files
	rm -f *.dump

	if [ "$KEEP_DB" = "false" ]; then
		echo "Clearing the db folder before build..."
		rm -Rf priv/db
	fi	
	
	rm -Rf priv/log
	
	echo "Compiling the project erlangms..."

	if [ "$SKIP_DEPS" = "false" ]; then
		clean_deps
		if [ "$SKIP_CLEAN" = "false" ]; then	
			tools/rebar/rebar clean get-deps compile	
		else
			tools/rebar/rebar get-deps compile	
		fi
	else
		if [ "$SKIP_CLEAN" = "false" ]; then	
			tools/rebar/rebar clean compile	
		else
			tools/rebar/rebar compile	
		fi
	fi

	if [ "$?" = "1" ]; then
		echo "Oops, something wrong!"
	else
		echo "Ok!"
	fi

fi
