#!/bin/bash
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



[ -f /tmp/relay_server_conf.json ]  || cat << EOF | tee /tmp/relay_server_conf.json
{
  "enable_ssl": true,
  "user": "test",
  "passwd": "123456",
  "bytes_max": 104857600,
  "valid_until": 0,
  "socket_timeout": 60,
  "recv_buffer_size": 4096,
  "relay_server_listen_addr": "0.0.0.0",
  "relay_server_listen_port": 10182,
  "socks5_server_conn_addr": "127.0.0.1",
  "socks5_server_conn_port": 10800,
  "pub_ip": "",
  "cert_dir": "",
  "key_file": "",
  "cert_file": ""
}
EOF

chmod 777 /tmp/relay_server_conf.json

tmp=$(mktemp)
jq ".cert_dir = \""$cert_path"\"" /tmp/relay_server_conf.json > "$tmp" && mv "$tmp" /tmp/relay_server_conf.json
tmp=$(mktemp)
jq ".key_file = \""$cert_path"/"$pub_ip"_key.pem\"" /tmp/relay_server_conf.json > "$tmp" && mv "$tmp" /tmp/relay_server_conf.json
tmp=$(mktemp)
jq ".cert_file = \""$cert_path"/"$pub_ip".pem\"" /tmp/relay_server_conf.json > "$tmp" && mv "$tmp" /tmp/relay_server_conf.json
tmp=$(mktemp)
jq ".pub_ip = \""$pub_ip"\"" /tmp/relay_server_conf.json > "$tmp" && mv "$tmp" /tmp/relay_server_conf.json
