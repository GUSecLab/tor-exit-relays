Instance image part:

We will start from a fresh ubuntu 1804. Before start we need to upgrade the system first(a reboot may be required):

	sudo apt-get update
	sudo apt-get upgrade

After this we need to disable unattended upgrade, a new feature of ubuntu, if we leave it as enabled, each of our newly spawned instances may run a system upgrade weeks after image created. Instructions are listed in 00_block_unattended_upgrade.manual

In some cases, ubuntu 1804 doesn't use eth0 as the name of default wired interface( especaially as a VM ). Please run `ifconfig` to find out if the interface is named correctly, if not, please follow instructions listed in 99_rename_network_if_to_eth0.manual, then reboot to take effect.

then we can continue configuration by execuating 4 scripts in a row:
	cd to/this/directory
	sudo ./01_install.sh
	sudo ./02_cp_cfg_scripts.sh
	sudo ./03_create_db.sh
	sudo ./04_start_services.sh

This will install and configure dante socks server, mysql, freeradius, pam for radius as well as our bridge side ssl_relay. 
After this, tweak config shown as bin/bridge_config.py and bin/bridge_config.sh(will be installed at /usr/bin on ec2 machine after scripts running), then we can create AMI Image.

By default, dante will listen to interface lo at port 10800(local domain), and use eth0 as external interface, and use a plain text username/password pam to trigger freeradius for authentication(this is safe). mysql is served as a database for freeradius(should only contain one record since we only allow per instance per user).

The bridge ssl_relay will listen to connections from 0.0.0.0/0:10182 by default, which should come from ssl_relay on user's computer through tor circuit. All incoming connections are TLS/SSL encrypted, then ssl_relay will just repeat what it heard to dante, since connections between user's computer and bridge ssl_relay are TLS/SSL encrypted, plain text pam authentication is safe. ssl_relay will use a certificate signed by broker during instance spawn. csr and cert are sent from scp command initated on broker machine, so broker machine has full access to bridge instance. 

AWS console configuration:

Both port 22 and 10182 should be allowed by firewall rule of security group.
AmazonEC2RoleforSSM and AmazonSSMFullAccess should be added to IAM role.

Both security group and IAM role should be attached to AMI image when spawn instance.


Once all configurations are done, we can create an Image using aws ec2 console, at https://console.aws.amazon.com/ec2/v2,
with "no reboot" option selected.