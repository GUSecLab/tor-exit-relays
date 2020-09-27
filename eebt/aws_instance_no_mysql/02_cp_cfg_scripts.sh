#!/bin/bash
# next we need to copy our exe scripts to /usr/bin,
# then setup startup daemons
# finally put all configuration files into right places.

# Copy scripts
sudo cp bin/* /usr/bin/

# setup startup programs
echo "@reboot root sleep 5 && sockd" | sudo tee /etc/crontab

# Copy configs
# /etc/sockd.conf

cat << EOF | sudo tee /etc/sockd.conf
logoutput: /var/log/socks.log
logoutput: stdout
internal: lo port = 10800
external: eth0

user.privileged: root
user.notprivileged: nobody

#authentication methods
socksmethod: none

client pass {
        from: 0.0.0.0/0 to: 0.0.0.0/0
        log: error ioop # connect disconnect
        socksmethod: none
}

#bind/outgoing traffic, with authentication
socks pass {  
        from: 0.0.0.0/0 to: 0.0.0.0/0
        command: bind connect udpassociate
        log: error ioop # connect disconnect iooperation
        socksmethod: none
}
EOF
