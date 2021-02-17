#!/bin/bash

# Make sure only root can run our script
if [[ $EUID -ne 0 ]]; then
   echo "Execute com sudo!"
   exit 1
fi

echo "User: $SUDO_USER"
USUARIO=$(echo $SUDO_USER)

# Config /etc/security/limits.conf if necessary for erlangms group
  echo "Configurando limits..."
  if ! grep -q '$USUARIO' /etc/security/limits.conf ; then
	echo " " >> /etc/security/limits.conf
	echo "# Security for $USUARIO" >> /etc/security/limits.conf
	echo "$USUARIO         hard    nofile      500000" >> /etc/security/limits.conf
	echo "$USUARIO         soft    nofile      500000" >> /etc/security/limits.conf
	echo "$USUARIO         hard    nproc       500000" >> /etc/security/limits.conf
	echo "$USUARIO         soft    nproc       500000" >> /etc/security/limits.conf
	echo "" >> /etc/security/limits.conf
	sed -ri '/^# *End of file$/d;' /etc/security/limits.conf
	sed -i '$ a # End of file' /etc/security/limits.conf	 
  fi

  # Tunning fs.file-max. At least it should be 1000000
  FILE_MAX_DEF=1000000
  FILE_MAX=$(cat /proc/sys/fs/file-max)

  echo "Configurando fs.file-max..."
  # Ajusta ou adiciona o valor para fs.file-max
  if grep -q 'fs.file-max' /etc/sysctl.conf ; then
		sed -ri "s/^fs.file-max=[0-9]{1,10}$/fs.file-max=$FILE_MAX_DEF/" /etc/sysctl.conf
  else
		echo "" >> /etc/sysctl.conf
		echo "# File descriptors limit" >> /etc/sysctl.conf
		echo "fs.file-max=$FILE_MAX_DEF" >> /etc/sysctl.conf
  fi 
  sysctl -p > /dev/null 2>&1
