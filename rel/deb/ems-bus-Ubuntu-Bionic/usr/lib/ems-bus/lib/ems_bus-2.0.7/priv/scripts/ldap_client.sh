#!/bin/bash 
#
# Title: ERLANGMS ldap client tool (bash version)
# Author: Everton de Vargas Agilar
# Data: 16/03/2016
#
# Requires ldap-utils package
#
# How to use: sudo ./ldap_client.sh 1 localhost geral 123456 --sendemail --auto_restart
#

# Test if ldap-utils package is intalled
ldapsearch --help 2> /dev/null
if [ "$?" != "1" ]; then
	echo "Error: Requires ldap-utils package to execute this command."
	exit
fi


# locale
LANG=en_US.UTF-8

# Get linux description
LINUX_DESCRIPTION=$(awk -F"=" '{ if ($1 == "PRETTY_NAME"){ 
									gsub("\"", "", $2);  print $2 
								 } 
							   }'  /etc/os-release)

# Primary IP of the server
LINUX_IP_SERVER=$(hostname -I | cut -d" " -f1)

LINUX_HOST=$(hostname)

VERSION=1.0.0
CURRENT_DIR=$(pwd)
TMP_DIR="/tmp/erlangms_$$_ldap_client_$(date '+%d%m%Y_%H%M%S')"
EMS_NODE="ems-bus"
CURRENT_DATE=$(date '+%d/%m/%Y %H:%M:%S')
IS_LOCAL_SERVER="false"
TYPE_SERVER="remote"
REPORT_FILE="$TMP_DIR/report_ldap_client.txt"
SEND_EMAIL="false"
PRINT_HEADER="true"
FALHA_LDAP="false"
AUTO_RESTART="false"
RESTARTED="false"
LDAP_PORT="2389"
LDAP_SERVER="127.0.0.1:$LDAP_PORT"
ENVIRONMENT="$LINUX_DESCRIPTION   Host: $LINUX_HOST   IP $LINUX_IP_SERVER"
NET_INTERFACES=$(netstat -tnl | awk -v PORT=$LDAP_PORT '$4 ~ PORT { print $4; }' | tr '\n' ' ')
MEM=$(free -h | awk '$1 == "Mem:" {  print "Total: " $2 "   Free: " $4 "   Avaiable: " $7; }')
LOAD_AVERAGE=$(cat /proc/loadavg | awk '{ print "Min: "$1"     5 Min: "$2"    15 Min: "$3 ; }')
UPTIME=$(echo since `uptime -s` " ( " `uptime -p` " )" | sed 's/hours/hs/; s/minutes/min/ ;')
SERVICE_UPTIME=$(systemctl status ems-bus 2> /dev/null | awk '/Active/ { print $2" "$3" "$4" "$6$7" "" ( up "$9" "$10" )";  }' | sed -r 's/ago //')
MAIN_PID=$(systemctl status ems-bus  2> /dev/null | grep "Main PID:")
TIME_WAIT_START_SERVER=20  # seconds
TIME_WAIT_TEST=3 # seconds
EMAIL_ONLY_ERROR="false"
RETRY=1


# tmpfiles go to /$TMP_DIR
mkdir -p $TMP_DIR && cd $TMP_DIR

# SMTP parameter
SMTP_SERVER="mail.unb.br"
SMTP_PORT=587
SMTP_DE="erlangms@unb.br"
SMTP_TO="evertonagilar@unb.br"
SMTP_PASSWD=erl1523


# print header (only one time)
print_header(){
	if [ "$PRINT_HEADER" = "true" ]; then
		# Output to report file if send email
		if [ "$SEND_EMAIL" = "true" ]; then
			exec > >(tee -a ${REPORT_FILE} )
			exec 2> >(tee -a ${REPORT_FILE} >&2)
		fi

		echo "Starting ERLANGMS ldap_client.sh tool   ( Version: $VERSION   Date: $CURRENT_DATE )"
		if [ "$IS_LOCAL_SERVER" = "true" ]; then
			echo "Server: $LDAP_SERVER"
			echo "Environment: $ENVIRONMENT"
			echo "Memory $MEM"
			echo "Listen interfaces: $NET_INTERFACES"
			echo "Load average: $LOAD_AVERAGE"
			echo "Server machine uptime: $UPTIME"
			echo "Service uptime: $SERVICE_UPTIME"
			echo "Node: $EMS_NODE $MAIN_PID"
		fi

		PRINT_HEADER="false"
	fi
}	
	
# send email with python	
send_email(){	
	REPORT_CONTENT=$(cat $REPORT_FILE | sed 's/passwd:.*/passwd: ************/')
	TITULO_MSG="ERLANGMS LDAP Client Test  -  Date: $CURRENT_DATE   IP: $LINUX_IP_SERVER" 
	SUBJECT="<html>
			<head>
				<style>
					pre {
						font-family: \"Courier New\", Courier, \"Lucida Sans Typewriter\", \"Lucida Typewriter\", monospace;
						font-size: 14px;
						font-style: normal;
						font-variant: normal;
						font-weight: 460;
						line-height: 18.5714px;
					}
					
				</style>
			<head>
			<body>
				<pre>$REPORT_CONTENT<pre>
			</body>
			</html>"
    python <<EOF
# -*- coding: utf-8 -*-
import smtplib
from email.mime.text import MIMEText
from email.Utils import formatdate
from email.mime.multipart import MIMEMultipart
from email import encoders
try:
	smtp = smtplib.SMTP("$SMTP_SERVER", $SMTP_PORT)
	smtp.starttls()
	smtp.login("$SMTP_DE", "$SMTP_PASSWD")
	msg = MIMEMultipart()
	msg['Subject'] = "$TITULO_MSG"
	msg['From'] = "$SMTP_DE"
	msg['To'] = "$SMTP_TO"
	msg['Date'] = formatdate(localtime=True)
	part1 = MIMEText("Relatório em anexo.", 'plain')
	part2 = MIMEText("""$SUBJECT""", 'html', 'utf-8')
	msg.attach(part2)
	smtp.sendmail("$SMTP_DE", ['evertonagilar@unb.br'], msg.as_string())
	smtp.quit()
	exit(0)
except Exception as e:
	print("Send email error: "+ str(e))
	exit(1)
EOF
	
}	


# Performs the ldap query using the ldapsearch
ldap_search(){
	if [ "$COUNTER" = "1" ]; then
		echo "Performing LDAP request on $TYPE_SERVER server $LDAP_SERVER with user $USER using ldapsearch"
		echo ldapsearch -xLLL -h "$LDAP_SERVER" -b 'dc=unb,dc=br' -D 'cn=admin,dc=unb,dc=br' uid="$USER" -w "xxxxxxx"
		echo ""
		ldapsearch -xLLL -h "$LDAP_SERVER" -b 'dc=unb,dc=br' -D 'cn=admin,dc=unb,dc=br' uid="$USER" -w "$ADMIN_PASSWD"
	else
		echo "Performing $COUNTER LDAP request on $TYPE_SERVER server $LDAP_SERVER with user $USER using ldapsearch"
		echo ldapsearch -xLLL -h "$LDAP_SERVER" -b 'dc=unb,dc=br' -D 'cn=admin,dc=unb,dc=br' uid="$USER" -w "xxxxxxx"
		until [  $COUNTER -lt 1 ]; do
			echo ""
			let COUNTER-=1
			ldapsearch -xLLL -h "$LDAP_SERVER" -b 'dc=unb,dc=br' -D 'cn=admin,dc=unb,dc=br' uid="$USER" -w "$ADMIN_PASSWD"
		done
	fi
}

# Performs the LDAP request test
generate_test(){
	print_header
	for T in `seq $RETRY`; do
		# ocorre erro 49 quando invalid credentials
		# ocorre erro 50 quando não tem permissão de acesso
		# ocorre erro 255 quando consegue contactar o servidor na porta
		ldap_search
		if [ "$?" = "0" -o "$?" = "49" -o "$?" = "50" ]; then
			FALHA_LDAP="false"
			break;
		else
			FALHA_LDAP="true"
		fi

		if [ $RETRY -gt 1 -a $T -lt $RETRY ]; then
			WAIT_TIMEOUT=$(($T*$TIME_WAIT_TEST))
			echo "Failed, waiting $WAIT_TIMEOUT seconds to retry..."
			echo $$ > $EXEC_CONTROL
			sleep $WAIT_TIMEOUT  # Awaits increasing
			echo 
			echo "$(($T+1)) attempt..."
		fi
	done
}


# Check parameters
if [ "$#" = "0" ] || [ "$1" = "--help" ]; then
	echo "Starting ERLANGMS ldap_client.sh tool   ( Version: $VERSION )"
	echo "How to use 1: ./ldap_client.sh login"
	echo "How to use 2: ./ldap_client.sh login admin_passwd"
	echo "How to use 3: ./ldap_client.sh qtd_requests ldap_server login admin_passwd  [ --sendemail  --auto_restart --email_only_error --retry ]"
	printf "%-20s  => %-150s.\n" "login" "login do user"
	printf "%-20s  => %-150s.\n" "admin_passwd" "password do admin do ldap"	
	printf "%-20s  => %-150s.\n" "ldap_server" "host do ldap (default é localhost:2389)"	
	printf "%-20s  => %-150s.\n" "qtd_requests" "Number of simultaneous requests (default is 1)"
	printf "%-20s  => %-150s.\n" "--sendemail"	"Send an email to admin"
	printf "%-20s  => %-150s.\n" "--auto_restart"	"Restarts the bus on failure (local server only)"
	printf "%-20s  => %-150s.\n" "--email_only_error" "Send email only if there is an error"
	printf "%-20s  => %-150s.\n" "--retry" "Number of attempts in case of failure. Allowed Range: 1-9"
	printf "%-20s  => %-150s.\n" "--email_to" "Emails to send report"
	exit
fi

# Parameter qtd_requests
if [ $# -gt 3 ]; then
	COUNTER=$1
    RE='^[0-9]+$'
    if ! [[ $COUNTER =~ $RE ]] ; then
       echo "Parameter qtd_requests ($COUNTER) must be a number!" >&2; exit 1
    fi
else
    COUNTER=1
fi

# Parameter LDAP_SERVER
if [ $# -ge 4 ]; then
    LDAP_SERVER="$2"
    if [[ $LDAP_SERVER =~ ^[0-9a-zA-Z_-.]+:[0-9]+$ ]] ; then
       LDAP_PORT=$(echo $LDAP_SERVER | awk -F: '{ print $2; }')
    elif [[ $LDAP_SERVER =~ ^[0-9a-zA-Z_-.]+$ ]] ; then
		LDAP_SERVER=$LDAP_SERVER:$LDAP_PORT
    else
		echo "Parameter LDAP_SERVER ( $LDAP_SERVER ) is invalid. Example: localhost:2389" >&2; exit 1
    fi
    LDAP_SERVER_IP="$(echo $LDAP_SERVER | cut -d: -f1)"
fi

# Parameter user
if [ "$#" = "1" ] || [ "$#" = "2" ]; then
    USER=$1
elif [ "$#" = "3" ]; then
    USER=$2
else
    USER=$3
fi

# Parameter admin_passwd
if [ $# -ge  4 ]; then
	ADMIN_PASSWD="$4"
elif [ "$#" = "3" ]; then
    ADMIN_PASSWD="$3"
elif [ "$#" = "2" ]; then
	ADMIN_PASSWD="$2"
else
	echo "Enter the LDAP administrator password for authentication:"
	read -s ADMIN_PASSWD
fi



# Optional parameters
for P in $*; do
	if [[ "$P" =~ ^--send_?email$ ]]; then
		SEND_EMAIL="true"
	elif [ "$P" = "--auto_restart" ]; then
		AUTO_RESTART="true"
	elif [ "$P" = "--email_only_error" ]; then
		EMAIL_ONLY_ERROR="true"
	elif [[ "$P" =~ ^--email_to=.+$ ]]; then
		SMTP_TO="$(echo $P | cut -d= -f2)"
	elif [[ "$P" =~ ^--retry=.+$ ]]; then
		RETRY="$(echo $P | cut -d= -f2)"
		if [[ ! "$RETRY" =~ ^[0-9]{1}$ ]] ; then
			echo "Parameter $P is invalid. Allowed Range: 1-99" && exit 1
			RETRY=1
		else
			if [ ! $RETRY -gt 0 ]; then
				echo "Parameter $P is invalid. Allowed Range: 1-9" && exit 1
			fi
		fi
	fi
done


# Check if command is running local or remote server
if [ $LDAP_SERVER = "localhost:$LDAP_PORT" -o $LDAP_SERVER = "127.0.0.1:$LDAP_PORT" -o "$LDAP_SERVER_IP" = "$LINUX_IP_SERVER" ]; then
	IS_LOCAL_SERVER="true"
	TYPE_SERVER="local"
else
	IS_LOCAL_SERVER="false"
	TYPE_SERVER="remote"
fi	


# Only one instance of this script can run
EXEC_CONTROL="/tmp/erlangms_ldap_client"
TMP_EXEC_CONTROL=$(find $EXEC_CONTROL -type f -mmin 1 2> /dev/null)
if [ -z "$TMP_EXEC_CONTROL" ]; then
	echo $$ > $EXEC_CONTROL
else
	echo "An instance of this script already exists running." && exit 0
fi


# Do test with ldap
generate_test


# Auto restart option restart ems-bus in case of failure (local server only)
if [ "$AUTO_RESTART" = "true" -a "$FALHA_LDAP" = "true" -a $IS_LOCAL_SERVER="true" ]; then
	if systemctl --version > /dev/null 2>&1 ; then
		echo "Restarting server in case of failure, please wait..."
		if sudo systemctl restart ems-bus 2> /dev/null ; then
			RESTARTED="true"
			echo "Ok, waiting $TIME_WAIT_START_SERVER seconds to verify that the ldap service is ok...."
			sleep $TIME_WAIT_START_SERVER
			generate_test
		fi
	else
		echo "Systemctl is required to restart the LDAP server."
	fi

	if [ "$FALHA_LDAP" = "true" ]; then
		if [ "$AUTO_RESTART" = "true" ]; then
			echo "WARNING: $LDAP_SERVER server is out of service and could not be restarted!"
		else
			echo "WARNING: $LDAP_SERVER server is out of service!"
		fi
	else
		if [ "$RESTARTED" = "true" ]; then
			echo "The $LDAP_SERVER server has been successfully restarted and is operating normally."
		fi
	fi
fi



# Envia e-mail?
if [ "$SEND_EMAIL" = "true" ]; then
	if [ "$FALHA_LDAP" = "true" -a "$EMAIL_ONLY_ERROR" = "true" ]; then
		send_email && echo "This report was send to $SMTP_TO."
	elif [ "$EMAIL_ONLY_ERROR" = "false" ]; then
		send_email && echo "This report was send to $SMTP_TO."
	fi
fi

# back to CURRENT_DIR and remove tmp dir
cd $CURRENT_DIR
rm $EXEC_CONTROL
rm -rf $TMP_DIR/
