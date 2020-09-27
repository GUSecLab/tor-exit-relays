#!/bin/bash
cadir=~/ca
# expand ~ to absolute path
eval cadir=$cadir
ca_subj=/C=US/ST=World/L=Internet/O=TorBroker/CN=www.example.com

sudo cp openssl.cnf /usr/lib/ssl/
# using + instead of / in sed since we are going to replace with a path
sudo sed -i "s+SEDREPLACEHERECADIR+${cadir}+" /usr/lib/ssl/openssl.cnf


cat << EOF | tee ca_env.sh
cadir=~/ca
eval cadir=$cadir
ca_subj=$ca_subj
EOF
chmod +x ca_env.sh


sudo cp ca_env.sh /usr/bin/
sudo cp sign_cert.sh /usr/bin
