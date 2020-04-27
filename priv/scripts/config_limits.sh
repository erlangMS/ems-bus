# Config /etc/security/limits.conf if necessary for erlangms group
  if ! grep -q '@erlangms' /etc/security/limits.conf ; then
	echo " " >> /etc/security/limits.conf
	echo "# Security for ERLANGMS ESB" >> /etc/security/limits.conf
	echo "@erlangms         hard    nofile      500000" >> /etc/security/limits.conf
	echo "@erlangms         soft    nofile      500000" >> /etc/security/limits.conf
	echo "@erlangms         hard    nproc       500000" >> /etc/security/limits.conf
	echo "@erlangms         soft    nproc       500000" >> /etc/security/limits.conf
	echo "" >> /etc/security/limits.conf
	sed -ri '/^# *End of file$/d;' /etc/security/limits.conf
	sed -i '$ a # End of file' /etc/security/limits.conf	 
  fi

  # Tunning fs.file-max. At least it should be 1000000
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
