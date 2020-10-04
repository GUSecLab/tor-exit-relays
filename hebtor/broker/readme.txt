
###### Initializing ##############

# when running on a ubuntu version, you may want to disable unattended-upgrades:

sudo dpkg-reconfigure -plow unattended-upgrades

# choose No

# install dependencies

sudo apt-get update
sudo apt-get upgrade
sudo apt-get install python3 python3-pip tor
sudo -H pip3 install Django pycryptodome



# Let's say you moved the broker folder to your home dir, so you should have 
# this file on this path: ~/broker/readme.txt


# generate Broker ECC Key, broker onion address, start Tor proxy for broker:

cd ~/broker/example1

python3 init.py

# the new broker onion address would be in path ~/.hebtor/onion_service


# init database

cd ~/broker/example1
python3 manage.py makemigrations
python3 manage.py migrate






###### Daily running: ############

tor -f ~/broker/example1/torrc

cd ~/broker/example1
python3 manage.py runserver 0:8000


##### features missing (TODO): ###

# enable csrf_token check, make sure back button will trigger new hCaptcha session.

# implement timeout events for restocking non-paid proxy, etc.
