#!/bin/sh
#
# author Everton de Vargas Agilar <<evertonagilar@gmail.com>>
#

VERSION_SCRIPT="3.0.0"
ERLANG_VERSION=20
OBSERVER="false"
PROFILE="local"

if [ ! "$ERLANGMS_IN_DOCKER" = "true" ]; then
	echo "Start erlangms tool ( Version: $VERSION_SCRIPT   Hostname: `hostname` )"
fi	


# Prints a message and ends the system
# Parâmetros:
#  $1  - Mensagem que será impressa 
#  $2  - Código de retorno para o comando exit
die () {
    echo $1
    echo
    exit $2
}

# Checks if the version of erlang installed is compatible
check_erlang_version(){
	ERLANG_VERSION_OS=`erl -eval 'erlang:display(erlang:system_info(otp_release)), halt().'  -noshell 2> /dev/null | sed 's/[^0-9]//g'`
	if [ -n "$ERLANG_VERSION_OS" ]; then
		if [ ! $ERLANG_VERSION_OS -ge $ERLANG_VERSION ]; then
			die "Opps, the Erlang Runtime installed is incompatible with this software. Expected version: $ERLANG_VERSION"
		fi 
	else
		die "Oops, you should install Erlang Runtime $ERLANG_VERSION first !!!"
	fi
}

# Prints on the screen the command help
help() {
	echo
	echo "How to use: ./start.sh"
	echo ""
	echo "Additional parameters:"
	echo "  --observer              -> Show Erlang Observer"
	echo "  --profile=local|docker  -> Profile to use"
	echo
	exit 1
}

if [ "$ERLANGMS_IN_DOCKER" != "true" ]; then
	check_erlang_version
fi	


# Read command line parameters
for P in $*; do
	if [[ "$P" =~ ^--.+$ ]]; then
		if [[ "$P" =~ ^--profile=\(local|docker\)$ ]]; then
			PROFILE="$(echo $P | cut -d= -f2)"
		elif [ "$P" = "--help" ]; then
			help
		elif [ "$P" = "--observer" ]; then
			OBSERVER="true"
		else
			echo "Invalid parameter: $P"
			help
		fi
	fi
done

if [ "$PROFILE" = "local" ]; then
	current_dir=$(dirname $0)
	cd $current_dir
	deps=$(ls -d deps/*/ebin)
	odbcinst -i -s -f ~/.odbc.ini
	
	if [ "$OBSERVER" = "true" ]; then
		echo "Start with observer daemon..."
		erl -pa $current_dir/ebin $deps \
			-sname emsbus -setcookie erlangms \
			-eval "ems_bus:start()" \
			-boot start_sasl \
			-config $current_dir/priv/conf/elog \
			-run observer \
			--enable-dirty-schedulers
	else
		erl -pa $current_dir/ebin $deps \
			-sname emsbus -setcookie erlangms \
			-eval "ems_bus:start()" \
			-boot start_sasl \
			-config $current_dir/priv/conf/elog \
			--enable-dirty-schedulers
	fi
else
	epmd -kill > /dev/null 2>&1
	
	ID_IMAGE=$(sudo docker ps -f name=erlangms | awk '{print $1}' | sed '1d')
	if [ ! -z "$ID_IMAGE" ]; then
		echo "Stop current image $IMAGE..."
		sudo docker stop $ID_IMAGE > /dev/null 2>&1
	fi

	sudo docker run -p 2300:2300 \
					-p 2301:2301 \
					-p 2389:2389 \
					-p 4369:4369 \
					-v ~/.erlangms:/var/opt/erlangms/.erlangms \
					-v ~/.odbc.ini:/var/opt/erlangms/.odbc.ini \
					-it erlangms
fi

