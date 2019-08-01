#!/bin/bash
#
# Author: Everton de Vargas Agilar
# Date: 07/02/2017
#
# Goal: Installer for Linux Ubuntu, Debian and CentOS
#
#
#
## Software modification history:
#
# Data       |  Quem           |  Mensagem  
# -----------------------------------------------------------------------------------------------------
# 15/01/2017  Everton Agilar     Initial release
# 05/03/2017  Everton Agilar     Make sure only root can run our script
# 28/07/2017  Everton Agilar     Remove sudo command and add options --send_email, --email_to
# 26/09/2017  Everton Agilar     New parameters: --from_file, --only_install_libs, --release_version
# 22/10/2017  Everton Agilar     By default, does not install erlang runtime system
# 22/11/2017  Everton Agilar     Install curl and wget if necessary
#
#
#
########################################################################################################

VERSION_SCRIPT="3.0.0"

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
							   
							   
echo "Setup erlangms tool ( Version: $VERSION_SCRIPT  Distro: $LINUX_DISTRO )"

# show help 
help(){
	echo "How to use: sudo ./setup-emsbus-linux.x86_64.sh"
	echo
	echo "Additional parameters:"
	echo "  --install_erlang_runtime -> Install Erlang Runtime"
	echo "  --release_version        -> Set release version to install. The default is to get the version from git"
	echo "  --from_file              -> Get the ems-bus file from a fixed location instead of downloading from git"
	echo "  --help                   -> Show help"
	echo
	echo "This command must be run as root."
	exit 1
}

# Make sure only root can run our script
if [[ $EUID -ne 0 ]]; then
   help
   exit 1
fi


LINUX_IP_SERVER=$(hostname -I | cut -d" " -f1)
CURRENT_DIR=$(pwd)
TMP_DIR="/tmp/erlangms/setup_$SETUP_VERSION_$$/"
mkdir -p $TMP_DIR && cd $TMP_DIR
LOG_FILE="$CURRENT_DIR/setup_emsbus__$(date '+%d%m%Y_%H%M%S').log"
INSTALL_ERLANG_RUNTIME="false"
RELEASE_VERSION=""
REPO_RELEASE_URL="https://github.com/erlangms/releases/raw/master"


# Performs the installation of the ems-bus
install(){
	# Enables installation logging
	exec > >(tee -a ${LOG_FILE} )
	exec 2> >(tee -a ${LOG_FILE} >&2)

	# Indicates whether it will be necessary to update the repository
	UPDATE_NECESSARY="false"

	# Install pre-requisites: curl
	if ! curl --version >> /dev/null 2>&1; then
		if [ "$LINUX_DISTRO" = "centos" ]; then
			yum -y install curl
		elif [ "$LINUX_DISTRO" = "ubuntu" ]; then
			apt-get -y install curl
		elif [ "$LINUX_DISTRO" = "deepin" ]; then
			apt-get -y install curl
		elif [ "$LINUX_DISTRO" = "debian" ]; then
			apt-get -y install curl
		fi	
	fi

	# Install pre-requisites: wget
	if ! wget --version >> /dev/null 2>&1; then
		if [ "$LINUX_DISTRO" = "centos" ]; then
			yum -y install wget
		elif [ "$LINUX_DISTRO" = "ubuntu" ]; then
			apt-get -y install wget
		elif [ "$LINUX_DISTRO" = "deepin" ]; then
			apt-get -y install wget
		elif [ "$LINUX_DISTRO" = "debian" ]; then
			apt-get -y install wget
		fi	
	fi
				  
	if [ -n "$FROM_FILE" ]; then
		SETUP_PACKAGE=$(basename $FROM_FILE)
		LINUX_DISTRO2=$(echo $SETUP_PACKAGE | sed -r 's/ems-bus-([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})-([[:alpha:]]+).+/\2/')
		if [ "$LINUX_DISTRO" != "$LINUX_DISTRO" ]; then
			echo "Setup $SETUP_VERSION is incompatible with this Linux distribution. It is possible to install in the Ubuntu, Debian and Centos distributions."
			exit 1
		fi
		SETUP_FILE=$FROM_FILE
		RELEASE_VERSION=$(echo $SETUP_PACKAGE | sed -r 's/ems-bus-([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}).+/\1/')
		SETUP_VERSION=$(echo $SETUP_PACKAGE | sed -r 's/.(deb|rpm)$//')
		cp $FROM_FILE .
	fi
		
	if [ -z "$FROM_FILE" ]; then
		# Get the last release version of the ems-bus
		if [ -z "$RELEASE_VERSION" ]; then
			printf "Verifying the latest version available for installation... "
			RELEASE_VERSION=$(curl -k https://raw.githubusercontent.com/erlangms/releases/master/setup/current_version 2> /dev/null)
			if [ -z "$RELEASE_VERSION" ]; then
				printf "[ ERROR ]\n"
				echo "Could not check the latest version available. Check your internet connection!!!"
				exit 1
			else
				printf "[ $RELEASE_VERSION ]\n"
			fi
		fi


		# Define $SETUP_VERSION, SETUP_PACKAGE and $SETUP_FILE
		if [[ "$LINUX_DISTRO" =~ (centos|debian|ubuntu|deepin) ]]; then
			SETUP_VERSION="ems-bus-$RELEASE_VERSION-$LINUX_DISTRO.$LINUX_VERSION_ID.x86_64"
			if [ "$LINUX_DISTRO" == "centos" ]; then
				SETUP_PACKAGE="$SETUP_VERSION.rpm"
			else
				SETUP_PACKAGE="$SETUP_VERSION.deb"
			fi
			SETUP_FILE="$REPO_RELEASE_URL/$RELEASE_VERSION/$SETUP_PACKAGE"
		else
			echo "Setup $SETUP_VERSION is incompatible with this Linux distribution. It is possible to install in the Ubuntu, Debian and Centos distributions."
			exit 1
		fi	


		# Download the ems-bus package according to the distribution
		echo "Downloading package $SETUP_PACKAGE..."
		wget -nvc $SETUP_FILE  2> /dev/null
		if [ ! $? -eq 0 ]; then
			echo "The ems-bus package $SETUP_PACKAGE could not be downloaded."
			exit 1
		fi
	fi

	echo "Starting installation of $SETUP_VERSION on Linux $LINUX_DESCRIPTION"
	echo "Purpose: A service-oriented bus developed in Erlang/OTP by Everton de Vargas Agilar"
	echo "Log file: $LOG_FILE" 
	echo "Host IP: $LINUX_IP_SERVER"
	echo "Host name: `hostname`"
	echo "Date: $(date '+%d/%m/%Y %H:%M:%S')"
	echo "============================================================================="


	if [ "$LINUX_DISTRO" = "centos" ]; then

		if [ "$INSTALL_ERLANG_RUNTIME" = "true" ]; then

			# ***** EPEL 7 repository **********
			if ! rpm -qi epel-release  >> /dev/null 2>&1; then
				echo "Installing the latest EPEL 7 repository..."
				 yum -y install epel-release
				UPDATE_NECESSARY="true"
			else
				echo "Skipping EPEL 7 repository installation because it is already installed."
			fi

			# ***** Erlang Runtime Library **********

			# erlang-solutions is a rpm package for Erlang repository
			if ! rpm -qi erlang-solutions >> /dev/null ; then
				echo "Adding Erlang repository entry."
				wget -nv https://packages.erlang-solutions.com/erlang-solutions-1.0-1.noarch.rpm

				# Check internet connectivity
				if [ "$?" -eq "4" ]; then
					echo "Make sure your DNS is well configured or if there is Internet on this host. Canceling installation..."
					exit 1
				fi

				 rpm -Uvh erlang-solutions-1.0-1.noarch.rpm
				UPDATE_NECESSARY="true"
			fi


			# update yum if necessary
			if [ "$UPDATE_NECESSARY" == "true" ]; then
				echo "yum update..."
				 yum -y update
			fi


			# Check if Erlang runtime already exist
			if ! erl -version 2> /dev/null;  then
				echo "Installing Erlang Runtime Library packages..."
				 yum -y install erlang-hipe-19.2-1.el7.centos.x86_64 \
				erlang-erl_docgen-19.2-1.el7.centos.x86_64 \
				erlang-erts-19.2-1.el7.centos.x86_64 \
				erlang-asn1-19.2-1.el7.centos.x86_64 \
				erlang-eunit-19.2-1.el7.centos.x86_64 \
				erlang-syntax_tools-19.2-1.el7.centos.x86_64 \
				erlang-runtime_tools-19.2-1.el7.centos.x86_64 \
				erlang-erl_interface-19.2-1.el7.centos.x86_64 \
				erlang-ic-19.2-1.el7.centos.x86_64 \
				erlang-stdlib-19.2-1.el7.centos.x86_64 \
				erlang-ssl-19.2-1.el7.centos.x86_64 \
				erlang-eldap-19.2-1.el7.centos.x86_64 \
				erlang-crypto-19.2-1.el7.centos.x86_64 \
				erlang-public_key-19.2-1.el7.centos.x86_64 \
				erlang-odbc-19.2-1.el7.centos.x86_64 \
				erlang-compiler-19.2-1.el7.centos.x86_64 \
				erlang-tools-19.2-1.el7.centos.x86_64 \
				erlang-edoc-19.2-1.el7.centos.x86_64 \
				erlang-kernel-19.2-1.el7.centos.x86_64 \
				erlang-inets-19.2-1.el7.centos.x86_64 \
				erlang-xmerl-19.2-1.el7.centos.x86_64 \
				erlang-parsetools-19.2-1.el7.centos.x86_64 \
				erlang-mnesia-19.2-1.el7.centos.x86_64 \
				erlang-doc-19.2-1.el7.centos.x86_64 \
				erlang-jinterface-19.2-1.el7.centos.x86_64 \
				erlang-gs-19.2-1.el7.centos.x86_64 \
				erlang-solutions-1.0-1.noarch \
				erlang-sasl-19.2-1.el7.centos.x86_64
			else
				echo "Skipping Erlang Runtime Library installation because it is already installed."
			fi
		fi
		
		# ***** Install or update ems-bus *****
		
		if ! rpm -qi ems-bus >> /dev/null ; then
			echo "Installing $SETUP_PACKAGE..."
			if rpm -ihv $SETUP_FILE; then
				echo "Installation done successfully!!!"
			else
				echo "Installation was unsuccessful."
			fi
		else
			systemctl stop ems-bus > /dev/null 2>&1
			VERSION_INSTALLED=$(rpm -qi ems-bus | grep Version | cut -d: -f2)
			echo "Removing previously installed$VERSION_INSTALLED version."
			if  rpm -e ems-bus > /dev/null ; then
				echo "Installing $SETUP_PACKAGE..."
				if  rpm -ihv $SETUP_PACKAGE; then
					echo "Installation done successfully!!!"
				else
					echo "Installation was unsuccessful."
				fi
			else
				echo "It was not possible remove previously installed$VERSION_INSTALLED version."
			fi
		fi


	elif [ "$LINUX_DISTRO" = "ubuntu" ]; then
		
		if [ "$INSTALL_ERLANG_RUNTIME" = "true" ]; then
		
			# erlang-solutions is a rpm package for Erlang repository
			if ! dpkg -s erlang-solutions > /dev/null 2>&1; then
				echo "Adding Erlang repository entry."
				wget -nv https://packages.erlang-solutions.com/erlang-solutions_1.0_all.deb

				# Check internet connectivity
				if [ "$?" -eq "4" ]; then
					echo "Make sure your DNS is well configured or if there is Internet on this host. Canceling installation..."
					exit 1
				fi

				 dpkg -i erlang-solutions_1.0_all.deb
				UPDATE_NECESSARY="true"
			fi


			# update yum if necessary
			if [ "$UPDATE_NECESSARY" = "true" ]; then
				echo "apt update..."
				 apt-get -y update
			fi


			# Check if Erlang runtime already exist
			if ! erl -version 2> /dev/null;  then
				echo "Installing Erlang Runtime Library packages..."
				  apt-get install erlang
			else
				echo "Skipping Erlang Runtime Library installation because it is already installed."
			fi

		fi
		
		# ***** Install or update ems-bus *****
		
		if ! dpkg -s ems-bus > /dev/null 2>&1 ; then
			echo "Installing $SETUP_PACKAGE..."
			if dpkg -i $SETUP_PACKAGE; then
				echo "Installation done successfully!!!"
			else
				echo "Installation was unsuccessful."
			fi
		else
			systemctl stop ems-bus > /dev/null 2>&1
			VERSION_INSTALLED=$(dpkg -s ems-bus | grep Version | cut -d: -f2)
			echo "Removing previously installed$VERSION_INSTALLED version."
			apt-get -y remove ems-bus > /dev/null 2>&1
			echo "Installing $SETUP_PACKAGE..."
			if  dpkg -i $SETUP_PACKAGE; then
				echo "Installation done successfully!!!"
			else 
				echo "Installation was unsuccessful."
			fi
		fi

	elif [ "$LINUX_DISTRO" = "deepin" ]; then
		
		if [ "$INSTALL_ERLANG_RUNTIME" = "true" ]; then
		
			# erlang-solutions is a rpm package for Erlang repository
			if ! dpkg -s erlang-solutions > /dev/null 2>&1; then
				echo "Adding Erlang repository entry."
				wget -nv https://packages.erlang-solutions.com/erlang-solutions_1.0_all.deb

				# Check internet connectivity
				if [ "$?" -eq "4" ]; then
					echo "Make sure your DNS is well configured or if there is Internet on this host. Canceling installation..."
					exit 1
				fi

				 dpkg -i erlang-solutions_1.0_all.deb
				UPDATE_NECESSARY="true"
			fi


			# update yum if necessary
			if [ "$UPDATE_NECESSARY" = "true" ]; then
				echo "apt update..."
				 apt-get -y update
			fi


			# Check if Erlang runtime already exist
			if ! erl -version 2> /dev/null;  then
				echo "Installing Erlang Runtime Library packages..."
				  apt-get install erlang
			else
				echo "Skipping Erlang Runtime Library installation because it is already installed."
			fi

		fi
		
		# ***** Install or update ems-bus *****
		
		if ! dpkg -s ems-bus > /dev/null 2>&1 ; then
			echo "Installing $SETUP_PACKAGE..."
			if dpkg -i $SETUP_PACKAGE; then
				echo "Installation done successfully!!!"
			else
				echo "Installation was unsuccessful."
			fi
		else
			systemctl stop ems-bus > /dev/null 2>&1
			VERSION_INSTALLED=$(dpkg -s ems-bus | grep Version | cut -d: -f2)
			echo "Removing previously installed$VERSION_INSTALLED version."
			apt-get -y remove ems-bus > /dev/null 2>&1
			echo "Installing $SETUP_PACKAGE..."
			if  dpkg -i $SETUP_PACKAGE; then
				echo "Installation done successfully!!!"
			else 
				echo "Installation was unsuccessful."
			fi
		fi


	elif [ "$LINUX_DISTRO" = "debian" ]; then

		if [ "$INSTALL_ERLANG_RUNTIME" = "true" ]; then
		
			# erlang-solutions is a rpm package for Erlang repository
			if ! dpkg -s erlang-solutions > /dev/null 2>&1 ; then
				echo "Adding Erlang repository entry."
				wget -nv https://packages.erlang-solutions.com/erlang-solutions_1.0_all.deb

				# Check internet connectivity
				if [ "$?" -eq "4" ]; then
					echo "Make sure your DNS is well configured or if there is Internet on this host. Canceling installation..."
					exit 1
				fi

				 dpkg -i erlang-solutions_1.0_all.deb
				UPDATE_NECESSARY="true"
			fi


			# update yum if necessary
			if [ "$UPDATE_NECESSARY" = "true" ]; then
				echo "apt update..."
				 apt-get -y update
			fi

			# Check if Erlang runtime already exist
			if ! erl -version 2> /dev/null;  then
				echo "Installing Erlang Runtime Library packages..."
				  apt-get install erlang
			else
				echo "Skipping Erlang Runtime Library installation because it is already installed."
			fi

		fi


		# ***** Install or update ems-bus *****
		
		if ! dpkg -s ems-bus >> /dev/null ; then
			echo "Installing $SETUP_PACKAGE..."
			if dpkg -i $SETUP_PACKAGE; then
				echo "Installation done successfully!!!"
			else
				echo "Installation was unsuccessful."
			fi
		else
			 systemctl stop ems-bus > /dev/null 2>&1
			VERSION_INSTALLED=$(dpkg -s ems-bus | grep Version | cut -d: -f2)
			echo "Removing previously installed$VERSION_INSTALLED version."
			apt-get -y remove ems-bus > /dev/null 2>&1
			echo "Installing $SETUP_PACKAGE..."
			if  dpkg -i $SETUP_PACKAGE; then
				echo "Installation done successfully!!!"
			else 
				echo "Installation was unsuccessful."
			fi
		fi

	fi	
}


# *************** main ***************

# Read command line parameters
for P in $*; do
	if [[ "$P" =~ ^--.+$ ]]; then
		if [[ "$P" =~ ^--release[_-]version=.+$ ]]; then
			RELEASE_VERSION="$(echo $P | cut -d= -f2)"
		elif [ "$P" = --install_erlang_runtime ]; then
			INSTALL_ERLANG_RUNTIME="true"
		elif [[ "$P" =~ ^--from_file=.+$ ]]; then
			FROM_FILE="$(echo $P | cut -d= -f2)"
		elif [ "$P" = "--help" ]; then
			help
		else
			echo "Invalid parameter: $P"
			help
		fi
	else
		echo "Invalid parameter: $P"
		help
	fi
done

if [ -n "$RELEASE_VERSION" -a -n "$FROM_FILE" ]; then
	echo "Parameters --release_version and --from_file can not be entered together."
fi

install
cd $CURRENT_DIR
rm -rf $TMP_DIR

