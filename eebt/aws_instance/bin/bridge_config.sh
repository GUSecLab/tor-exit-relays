#!/bin/bash
# This part is for Get Certificate, used for ssl_relay_server.
eval homedir="~"
if [ $homedir == "/root" ]; then
   homedir='/home/ubuntu'
fi

cert_path=$homedir
# ec2 get public ip:
if [ `uname -a | grep raspberrypi | wc -l` -eq 0 ]
then
	pub_ip=`curl -s http://169.254.169.254/latest/meta-data/public-ipv4` 2>>/dev/null
	instance_id=`curl -s http://169.254.169.254/latest/meta-data/instance-id` 2>>/dev/null
else
	pub_ip=`curl -s https://api.ipify.org` 2>>/dev/null
	instance_id="raspberrypi" 
fi

# Other Configurations:

# mysql:
# db: radius
# db_user: radius
# db_password: radpass
# related files: bin/proxy_add_user bin/proxy_del_user
# this DB is only used for store freeradius username/password and quota.

# freeradius:
# See configurations at install.sh

# pam_radius_auth:
# See configurations at install.sh

# ssl_relay_server:

# usage_ctrl:
# This daemon will monitor data usage, terminate when used up

