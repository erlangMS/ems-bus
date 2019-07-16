#!/bin/bash 
#
# Title: ERLANGMS audit ldap log tool
# Author: Everton de Vargas Agilar
# Data: 14/02/2017
#
#
# Requirements to run the service:
#       * Python
#
# Use mode: 
#
#    $ sudo ./audit_ldap_log.sh minutes [ --sendemail --showlogs ]
#
#   ./audit_ldap_log.sh 10 --sendemail  
#   ./audit_ldap_log.sh  
#
# Obs.: parameter --sendmail is optional and send email to admin
#
#
## History of changes:
#
# Data       |  Quem           |  Mensagem  
# -----------------------------------------------------------------------------------------------------
# 14/02/2017  Everton Agilar     Release inicial    
# 03/03/2017  Everton Agilar     Add --showlogs option and improve ldap report
# 19/05/2017  Everton Agilar     Add --email_to option
# 27/11/2017  Everton Agilar     Add --fix send_email to multiples emails
#
#
#
########################################################################################################

# Check pre-requisites: netstat
if [ "`netstat --version 2> /dev/null`" = "" ]; then
	echo "Prerequisite: netstat is not installed, exiting..."
	exit 1
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

# Script version
VERSION=1.0.1
LDAP_PORT="2389"
LDAP_SERVER="$LINUX_IP_SERVER:$LDAP_PORT"
CURRENT_DIR=$(pwd)
TMP_DIR="/tmp/erlangms_$$_audit_ldap_log_$(date '+%d%m%Y_%H%M%S')"
EMS_NODE="ems-bus"
ENVIRONMENT="$LINUX_DESCRIPTION  Host: $LINUX_HOST  IP $LINUX_IP_SERVER "
NET_INTERFACES=$(netstat -tnl | awk -v PORT=$LDAP_PORT '$4 ~ PORT { print $4; }' | tr '\n' ' ')
MEM=$(free -h | awk '$1 == "Mem:" {  print "Total: " $2 "   Free: " $4 "   Avaiable: " $7; }')
LOAD_AVERAGE=$(cat /proc/loadavg | awk '{ print "Min: "$1"     5 Min: "$2"    15 Min: "$3 ; }')
UPTIME=$(echo since `uptime -s` " ( " `uptime -p` " )" | sed 's/hours/hs/; s/minutes/min/ ;')
SERVICE_UPTIME=$(systemctl status ems-bus 2> /dev/null | awk '/Active/ { print $2" "$3" "$4" "$6$7" "" ( up "$9" "$10" )";  }' | sed -r 's/ago //')
MAIN_PID=$(systemctl status ems-bus 2> /dev/null | grep "Main PID:")
MMIN="1440"
CURRENT_DATE=$(date '+%d/%m/%Y %H:%M:%S')
REPORT_FILE="$TMP_DIR/report_audit_ldap_log_$(date '+%d%m%Y_%H%M%S').txt"
SUB_TITLE_REPORT="LAST DAY OF OPERATION"
SHOW_LOGS="false"
SEND_EMAIL="false"


# Log destination parameter
LOG_YEAR=$(date '+%Y')
LOG_DEST_BASE="/var/log/$EMS_NODE"
LOG_DEST="$LOG_DEST_BASE"
LOG_FILE_TMP="$TMP_DIR/full_log_file.tmp"
LOG_FILE="$TMP_DIR/full_log_file_filtered.tmp"

# SMTP parameter
SMTP_SERVER="mail.unb.br"
SMTP_PORT=587
SMTP_DE="erlangms@unb.br"
SMTP_TO="evertonagilar@unb.br"
SMTP_PASSWD=erl1523


# tmpfiles go to /$TMP_DIR
mkdir -p $TMP_DIR && cd $TMP_DIR


# Parameters
if [ "$#" = "0" ]; then
	MMIN="1440"	
elif [ "$1" = "--help" ]; then
	echo "How to use: ./audit_ldap_log.sh minutes  [ --send_email --showlogs ]"
	echo "where minutes is logfile's data was last modified minutes ago (default is 1 day or 43200 minutes)."
	echo "parameter --send_email is optional and send email to admin."
	echo "parameter --email_to is list of email to send."			
	echo "parameter --showlogs show content of logs."
	exit 1
else
	if [ "$1" == "--sendemail" ] || [ "$1" == "--send_email" ] || [ "$1" == "--showlogs" ]; then
		MMIN="1440"	
	else
		MMIN="$1"
		if ! [[ $MMIN =~ ^[0-9]{1,6}$ ]] ; then
			echo "Parameter minutes with value \"$MMIN\" is inválid. Values allowed from 1 to 99999."
			echo "How to use: ./audit_ldap_log.sh minutes  [ --sendemail  --showlogs ]"
			echo "where minutes is logfile's data was last modified minutes ago (default is 1 day or 43200 minutes)."
			echo "parameter --send_email is optional and send email to admin."
			echo "parameter --email_to is list of email to send."
			echo "parameter --showlogs show log files content."
			exit 1
		fi
	fi
fi

# Compute initial date
DATE_INIT=$(date --date="$MMIN min ago" '+%d/%m/%Y %H:%M:%S')   # Calcula a data retroativa


# generate a report
generate_report(){
	# Output to report file
	exec > >(tee -a ${REPORT_FILE} )
	exec 2> >(tee -a ${REPORT_FILE} >&2)
	
	echo "Starting ERLANGMS audit_ldap_log tool   ( Version: $VERSION   Date: $CURRENT_DATE )"
	echo "Environment: $ENVIRONMENT"
	echo "Memory $MEM"
	echo "Listen interfaces: $NET_INTERFACES"
	echo "Load average: $LOAD_AVERAGE"
	echo "Server machine uptime: $UPTIME"
	echo "ErlangMs uptime: $SERVICE_UPTIME"
	echo "Node: $EMS_NODE $MAIN_PID"
	echo "Log dest: $LOG_DEST"
	echo
	
	if [ "$MMIN" = "1440" ]; then
		echo "Analyzing logfiles between $DATE_INIT (1 day ago) and $CURRENT_DATE"
	elif [ "$MMIN" = "2880" ]; then
		echo "Analyzing logfiles between $DATE_INIT (2 day ago) and $CURRENT_DATE"
	elif [ "$MMIN" = "4320" ]; then
		echo "Analyzing logfiles between $DATE_INIT (3 day ago) and $CURRENT_DATE"
	elif [ "$MMIN" = "5760" ]; then
		echo "Analyzing logfiles between $DATE_INIT (4 day ago) and $CURRENT_DATE"
	elif [ "$MMIN" = "7200" ]; then
		echo "Analyzing logfiles between $DATE_INIT (5 day ago) and $CURRENT_DATE"
	elif [ "$MMIN" = "8640" ]; then
		echo "Analyzing logfiles between $DATE_INIT (6 day ago) and $CURRENT_DATE"
	elif [ "$MMIN" = "10080" ]; then
		echo "Analyzing logfiles between $DATE_INIT (1 week ago) and $CURRENT_DATE"
	elif [ "$MMIN" = "14400" ]; then
		echo "Analyzing logfiles between $DATE_INIT (10 day ago) and $CURRENT_DATE"
	elif [ "$MMIN" = "21600" ]; then
		echo "Analyzing logfiles between $DATE_INIT (15 day ago) and $CURRENT_DATE"
	elif [ "$MMIN" = "43200" ]; then
		echo "Analyzing logfiles between $DATE_INIT (1 month ago) and $CURRENT_DATE"
	elif [ "$MMIN" = "86400" ]; then
		echo "Analyzing logfiles between $DATE_INIT (2 month ago) and $CURRENT_DATE"
	elif [ "$MMIN" = "129600" ]; then
		echo "Analyzing logfiles between $DATE_INIT (3 month ago) and $CURRENT_DATE"
	else
		echo "Analyzing logfiles between $DATE_INIT ($MMIN minutes ago) and $CURRENT_DATE"
	fi

	# copies the log files to $TMP_DIR tmp and returns a list of them
	LOG_FILE_LIST=$(find "$LOG_DEST/" -type f -mmin "-$MMIN" -follow -name "*.log" -size +0 -exec cp {} $TMP_DIR \; -exec basename  {} \;) 

	if [ -z "$LOG_FILE_LIST" ]; then
		echo "No logfiles to analyze."
		exit 1
	else
		echo "Reading and parsing the following logfiles:"
		echo $LOG_FILE_LIST  | tr " " "\n" | awk '{
			printf "   * "$1 ;
			printf "  -  ";
			system("du -h "$1 "| cut -f1");
		}'
	fi 
 

	# concat all logfiles of ems_ldap_handler and create $LOG_FILE_TMP
	# remove characters control of the line colors too
	cat $TMP_DIR/*.log | grep "ems_ldap_handler" | sed -r '/ERROR/ { s/.{7}// ;  s/.{4}$// } ; y/áÁàÀãÃâÂéÉêÊíÍóÓõÕôÔúÚçÇ/aAaAaAaAeEeEiIoOoOoOuUcC/ ; s/<//g; s/>//g ; /ems_ldap_handler search "erlangms"/d' > $LOG_FILE_TMP
	
	

	# filter only the log lines of the defined interval	$DATE_INIT
	awk -v DT_INIT="$DATE_INIT" '{
			DT_LOG=$2" "$3;
			if (DT_LOG >= DT_INIT){
				print; 
			}
	}' $LOG_FILE_TMP > $LOG_FILE
	

	# Check if show logfiles content
	if [ "$SHOW_LOGS" == "true" ]; then
		echo
		echo
		echo "Show content os log files:"
		cat $LOG_FILE
		echo
	fi
	
	echo


	# Print title
	echo
	echo
	echo "                                 ERLANGMS LDAP REPORT FOR THE"
	if [ "$MMIN" == "1440" ]; then
		SUB_TITLE_REPORT="LAST DAY OF OPERATION"
	elif [ "$MMIN" = "2880" ]; then
		SUB_TITLE_REPORT="LAST 2 DAY OF OPERATION"
	elif [ "$MMIN" = "4320" ]; then
		SUB_TITLE_REPORT="LAST 3 DAY OF OPERATION"
	elif [ "$MMIN" = "5760" ]; then
		SUB_TITLE_REPORT="LAST 4 DAY OF OPERATION"
	elif [ "$MMIN" = "7200" ]; then
		SUB_TITLE_REPORT="LAST 5 DAY OF OPERATION"
	elif [ "$MMIN" = "8640" ]; then
		SUB_TITLE_REPORT="LAST 6 DAY OF OPERATION"
	elif [ "$MMIN" = "10080" ]; then		
		SUB_TITLE_REPORT="LAST 1 WEEK OF OPERATION"
	elif [ "$MMIN" = "14400" ]; then
		SUB_TITLE_REPORT="LAST 10 DAY OF OPERATION"
	elif [ "$MMIN" = "21600" ]; then
		SUB_TITLE_REPORT="LAST 15 DAY OF OPERATION"
	elif [ "$MMIN" = "43200" ]; then
		SUB_TITLE_REPORT="LAST 1 MONTH OF OPERATION"
	elif [ "$MMIN" = "86400" ]; then
		SUB_TITLE_REPORT="LAST 2 MONTH OF OPERATION"
	elif [ "$MMIN" = "129600" ]; then
		SUB_TITLE_REPORT="LAST 3 MONTH OF OPERATION"
	elif [ "$MMIN" == "1" ]; then
		SUB_TITLE_REPORT="LAST $MMIN MINUTE OF OPERATION"
	else 
		SUB_TITLE_REPORT="LAST $MMIN MINUTES OF OPERATION"
	fi
	SUB_TITLE_SIZE=$[$(echo $SUB_TITLE_REPORT | wc -c) / 2]
	printf "%*s\n" $[47 + $SUB_TITLE_SIZE] "$SUB_TITLE_REPORT"
	echo
	


	# filter data
	egrep '^INFO.*ems_ldap_handler search' $LOG_FILE > info_request_search.tmp
	grep 'success' info_request_search.tmp | cut -d" " -f7- | sed 's/ success.//g' | sort > request_search_success.tmp
	uniq request_search_success.tmp > request_search_success_uniq.tmp
	egrep '^ERROR.*ems_ldap_handler' $LOG_FILE > error_request_search.tmp
	grep ' does not exist.' error_request_search.tmp | cut -d" " -f7- | sed 's/ does not exist.//g' | sort > request_search_login_does_not_exist.tmp
	uniq request_search_login_does_not_exist.tmp > request_search_login_does_not_exist_uniq.tmp


	# totals
	REQ_SEARCH_TOTAL_INFO=$(wc -l info_request_search.tmp | cut -d" " -f1)
	REQ_SEARCH_SUCCESS_TOTAL=$(wc -l request_search_success.tmp | cut -d" " -f1)
	REQ_SEARCH_SUCCESS_UNIQ_TOTAL=$(wc -l request_search_success_uniq.tmp | cut -d" " -f1)
	REQ_SEARCH_FAIL=$(wc -l error_request_search.tmp | cut -d" " -f1)
	REQ_SEARCH_FAIL_LOGIN_DOES_NOT_EXIST_TOTAL=$(wc -l request_search_login_does_not_exist.tmp | cut -d" " -f1)
	REQ_SEARCH_FAIL_LOGIN_DOES_NOT_EXIST_UNIQ_TOTAL=$(wc -l request_search_login_does_not_exist_uniq.tmp | cut -d" " -f1)
	REQ_LDAP_TOTAL=$[REQ_SEARCH_TOTAL_INFO + REQ_SEARCH_FAIL]

	############################################  PRINT REPORT  #######################################################################
	
	echo "1) Number of ldap requests (success + failed): $REQ_LDAP_TOTAL requests"
	echo
	echo "2) Number of success ldap requests: $REQ_SEARCH_SUCCESS_TOTAL requests"
	echo

	echo "3) Number of success search operation per user:"
	echo '+-----------------------------------+------------------------------------------------------------------+'
	printf "| %-33s | %-47s | %14s |\n"  "LOGIN" "NAME" "REQUESTS" " "
	echo '+-----------------------------------+------------------------------------------------------------------+'
	
	TMP_NUMBER_SUCCESS_SEARCH_PER_USER=$TMP_DIR/tmp_number_success_search_per_user.tmp
	while read USER; do
		REQ_SEARCH_SUCCESS_TOTAL_BY_USER=$(grep -w "$USER" request_search_success.tmp | wc -l | cut -d" " -f1)
		USER_FORMAT=$(echo $USER | xargs printf "%-33s | %-47s")
		printf "| %-45s | %14d |\n"   "$USER_FORMAT"   $REQ_SEARCH_SUCCESS_TOTAL_BY_USER >> $TMP_NUMBER_SUCCESS_SEARCH_PER_USER
	done < request_search_success_uniq.tmp
	if [ -f $TMP_NUMBER_SUCCESS_SEARCH_PER_USER ]; then
		cat $TMP_NUMBER_SUCCESS_SEARCH_PER_USER | sort -t'|' -n -r  -nk4
	else
		printf "| %-33s | %64s |\n"   "no records found"   " "
	fi
	echo '+-----------------------------------+------------------------------------------------------------------+'
	printf "| %-33s | %40s TOTAL: %16d |\n"   " " " " $REQ_SEARCH_SUCCESS_TOTAL
	echo '+-----------------------------------+------------------------------------------------------------------+'
	
	echo
	echo "4) Number of failed ldap requests: $REQ_SEARCH_FAIL requests"
	echo
	echo "5) Number of failed ldap request attempts because login does not exist: $REQ_SEARCH_FAIL_LOGIN_DOES_NOT_EXIST_TOTAL requests"
	echo
	echo "6) Users not found in the search operation: $REQ_SEARCH_FAIL_LOGIN_DOES_NOT_EXIST_UNIQ_TOTAL users"
	echo '+-----------------------------------------------+------------------------------------------------------+'
	printf "| %-45s | %19s %33s|\n"  "LOGIN"   "REQUESTS"   " "                                                               
	echo '+-----------------------------------------------+------------------------------------------------------+'
	TMP_USERS_NOT_FOUND_SEARCH_OP=$TMP_DIR/tmp_users_not_found_search_op.tmp
	while read USER; do
		USER=$(echo $USER | tr -d '"')
		REQ_SEARCH_FAIL_LOGIN_DOES_NOT_EXIST_TOTAL_BY_USER=$(grep -w "$USER" request_search_login_does_not_exist.tmp | wc -l | cut -d" " -f1)
		printf "| %-45s | %19d         %25s|\n"   "$USER"   $REQ_SEARCH_FAIL_LOGIN_DOES_NOT_EXIST_TOTAL_BY_USER " " >> $TMP_USERS_NOT_FOUND_SEARCH_OP
	done <  request_search_login_does_not_exist_uniq.tmp
	if [ -f $TMP_USERS_NOT_FOUND_SEARCH_OP ]; then
		cat $TMP_USERS_NOT_FOUND_SEARCH_OP | sort -t'|' -n -r  -nk3 
	else
		printf "| %-45s | %19s         %25s|\n"   "no records found"   "" " "
	fi
	echo '+-----------------------------------------------+------------------------------------------------------+'
	printf "| %-45s | TOTAL: %12d %33s|\n"   " " $REQ_SEARCH_FAIL_LOGIN_DOES_NOT_EXIST_TOTAL " "
	echo '+-----------------------------------------------+------------------------------------------------------+'
	echo
	

}

# send email with python	
send_email(){	
	REPORT_CONTENT=$(cat $REPORT_FILE)
	TITULO_MSG="ERLANGMS LDAP REPORT    HOST: $LINUX_HOST   IP: $LINUX_IP_SERVER  Date: $CURRENT_DATE" 
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
				<!--[if mso]>
				 <center>
				 <table><tr><td width=\"980\">
				<![endif]-->
				 <div style=\"max-width:980px; margin:0 auto;\"> 
					<pre>$REPORT_CONTENT<pre>
				</div>
				<!--[if mso]>
				 </td></tr></table>
				 </center>
				<![endif]-->
			</body>
			</html>"
    
    Emails=$(echo $SMTP_TO | tr "," "\n")
	for Addr in $Emails; do
		SEND_TO=["'''$Addr'''"]	
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
	msg['To'] = "$Addr"
	msg['Date'] = formatdate(localtime=True)
	part1 = MIMEText("Relatório em anexo.", 'plain')
	part2 = MIMEText("""$SUBJECT""", 'html', 'utf-8')
	msg.attach(part2)
	smtp.sendmail("$SMTP_DE", $SEND_TO, msg.as_string())
	smtp.quit()
	exit(0)
except Exception as e:
	print("Send email error: "+ str(e))
	exit(1)
EOF
	done
	
}	


# /////////////////// main /////////////////


# Optional parameters
for P in $*; do
	if [ "$P" == "--showlogs" ]; then
		SHOW_LOGS="true"		
	elif [[ "$P" =~ ^--send_email$ ]]; then
		SEND_EMAIL="true"
	elif [[ "$P" =~ ^--email_to=.+$ ]]; then
		SMTP_TO="$(echo $P | cut -d= -f2)"
	else
		echo "Invalid parameter: $P"
		exit 1
	fi
done

# generate report
generate_report

# send e-mail to admins. Only send email if has records
if [ "$SEND_EMAIL" == "true" ]; then
	if [ $REQ_LDAP_TOTAL -gt 0 ]; then
		send_email && echo "This report was send to $SMTP_TO."
	else
		echo "No ldap requests in this time for send report to $SMTP_TO."
	fi
fi

# back to CURRENT_DIR and remove tmp dir
cd $CURRENT_DIR
rm -rf $TMP_DIR/

