
###### Initializing ##############

# when running on a ubuntu version:

sudo dpkg-reconfigure -plow unattended-upgrades

# choose No

# install dependencies

sudo apt-get update
sudo apt-get upgrade
sudo apt-get install python3 python3-pip
sudo -H pip3 install Django
sudo -H pip3 install pycryptodome

# install tor

sudo apt-get install tor

sudo rm /etc/tor/torrc
sudo service tor stop

# configure torrc, change HiddenServiceDir and HiddenServicePort accordingly, say:

HiddenServiceDir /home/username/onion_service
HiddenServicePort 80 127.0.0.1:8000


# start tor client for hidden service

tor -f torrc

# get onion address from /home/username/onion_service/hostname
# replace onion address in ALLOWED_HOSTS in exampl1/example1/settings.py


cd example1

# generate Broker ECC Key:

python3 key_generator.py

# init database

python3 manage.py makemigrations
python3 manage.py migrate






###### Daily running: ############

tor -f torrc

cd example1
python3 manage.py runserver 0:8000


# features missing (TODO):

# test pop verification, tag verification, reputation update.

# enable csrf_token check, make sure back button will trigger new hCaptcha session.

# implement timeout events for restocking non-paid proxy, etc.




