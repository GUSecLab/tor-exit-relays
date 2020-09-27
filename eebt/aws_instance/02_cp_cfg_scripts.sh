#!/bin/bash
# next we need to copy our exe scripts to /usr/bin,
# then setup startup daemons
# finally put all configuration files into right places.

# Copy scripts
sudo cp bin/* /usr/bin/

# setup startup programs
sudo echo "@reboot root service freeradius start" >> /etc/crontab
sudo echo "@reboot root sleep 5 && sockd | usage_ctrl" >> /etc/crontab

# Copy configs, 4 files are involved
# /etc/freeradius/3.0/mods-available/sql
# /etc/sockd.conf
# /etc/pam.d/sockd
# /etc/pam_radius_auth.conf

sudo cp sql /etc/freeradius/3.0/mods-available/sql
pushd /etc/freeradius/3.0/mods-enabled/
ln -s ../mods-available/sql
popd

cat << EOF | sudo tee /etc/sockd.conf
logoutput: /var/log/socks.log
logoutput: stdout
internal: lo port = 10800
external: eth0

user.privileged: root
user.notprivileged: nobody

#authentication methods
socksmethod: pam.username

client pass {
        from: 0.0.0.0/0 to: 0.0.0.0/0
        log: error ioop # connect disconnect
        socksmethod: pam.username
}

#bind/outgoing traffic, with authentication
socks pass {  
        from: 0.0.0.0/0 to: 0.0.0.0/0
        command: bind connect udpassociate
        log: error ioop # connect disconnect iooperation
        socksmethod: pam.username
}
EOF

cat << EOF | sudo tee  /etc/pam.d/sockd
auth sufficient /lib/security/pam_radius_auth.so
account sufficient /lib/security/pam_radius_auth.so
EOF

cat << EOF | sudo tee /etc/pam_radius_auth.conf
#  pam_radius_auth configuration file.  Copy to: /etc/raddb/server
#
#  For proper security, this file SHOULD have permissions 0600,
#  that is readable by root, and NO ONE else.  If anyone other than
#  root can read this file, then they can spoof responses from the server!
#
#  There are 3 fields per line in this file.  There may be multiple
#  lines.  Blank lines or lines beginning with '#' are treated as
#  comments, and are ignored.  The fields are:
#
#  server[:port] secret [timeout]
#
#  the port name or number is optional.  The default port name is
#  "radius", and is looked up from /etc/services The timeout field is
#  optional.  The default timeout is 3 seconds.
#
#  If multiple RADIUS server lines exist, they are tried in order.  The
#  first server to return success or failure causes the module to return
#  success or failure.  Only if a server fails to response is it skipped,
#  and the next server in turn is used.
#
#  The timeout field controls how many seconds the module waits before
#  deciding that the server has failed to respond.
#
# server[:port]	shared_secret      timeout (s)
127.0.0.1	testing123             1
other-server    other-secret       3

#
# having localhost in your radius configuration is a Good Thing.
#
# See the INSTALL file for pam.conf hints.
EOF

