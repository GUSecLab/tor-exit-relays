#!/bin/bash
# what to do:
# 1, setup connection to broker vm

# 2, install lamp stack(only A and P)

sudo apt-get install -y apache2 php php-common php-gd php-json

# install python dependency for ws_server
sudo apt-get install python3 python3-pip
sudo -H pip3 install git+https://github.com/Pithikos/python-websocket-server
sudo -H pip3 install websocket-client

# 3, install tor

sudo apt-get install -y build-essential libevent-dev libssl-dev zlib1g-dev zlib1g
TORVER="0.3.4.8"
wget https://dist.torproject.org/tor-$TORVER.tar.gz
tar -xvf tor-$TORVER.tar.gz 
pushd tor-$TORVER/
./configure 
make -j8
sudo make install
popd
rm -rf tor-$TORVER/


# 4, setup ca

pushd broker_ca
sudo ./setup.sh
./create_ca.sh
popd


# 5, setup php site

pushd broker_site
sudo cp -r * /var/www/html/
sudo rm /var/www/html/index.html
popd


# 6, start onion service
GRP=`id -g -n $USER`
mkdir ~/onion_service
chown $USER:$GRP ~/onion_service
chmod 700 ~/onion_service
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# THIS HOSTNAME AND PRIVATE KEY IS JUST FOR EXAMPLE PURPOSE,
# REMEMBER TO CHANCE THE CONTENT TO YOUR REAL HOSTNAME AND PRIVATE KEY!!
cat << EOF | tee ~/onion_service/hostname
hqhmvkgyal54qx5h.onion
EOF
# THIS HOSTNAME AND PRIVATE KEY IS JUST FOR EXAMPLE PURPOSE,
# REMEMBER TO CHANCE THE CONTENT TO YOUR REAL HOSTNAME AND PRIVATE KEY!!
cat << EOF | tee ~/onion_service/private_key
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCmXhGl+jfUaPy8c3GngzJc9k5y2jQYX/xJ9fABPncSLXrg2GXd
wgGlICH/VbCPz6rUdVbQxWccLjdjirr0MtjG+00DDeFEOTKAVKz33lREcMC+nAfY
naSQpLwJAz5jbkFkd+p9yFteJgPOWeqIkwqFKEu3xaRFj+2MeF22ZOWFOQIDAQAB
AoGAeBudvihBOjZ5kEwAF6GeMIMZ680goyBY8cR+e0dvi04OUlmoYUr5CQ+Du+VP
TOPuPuhfvuVlJXEwR8sWYcp7uTIKXbs6cxFUhJT6YJlWMJqxIAM+FiGbKFHKWZtq
aoQabWvSSbOU2kSlrUH1wZHcr2wRevLdBUf7dheXYS+2tgECQQDT0WyMi12D3tMh
4aILrf53wAIZJ8kuJagORiiadcQV+71438z8qTozoMFANkN1D5OpMNu5nreDRjJV
jvUKqtQhAkEAyRGxEuGf34V80arwQWbGLc0zkL9k5Ka1s2Sero83OCCtrrd3Zm1L
xaFW1r9HHwHDwC3xX7mLjhrsZCkTnv0OGQJBAJw/6Crkw177iBN+NeMXvpbndKTJ
zIXWEVo2Ns16AeOVh/caYEQhMWXUN7n+TVSU4P/1oqASjJyxs3+ZrPjpewECQF53
sHFFjj6PUfiUTnL73WqReYOtWLLQ3JefU6qB4Ri+ybtHuZJnEW2WAt28WqbnxleZ
fklSPI4UejII1o4hKKkCQC5imlIH4GhKZ8wRd/2AtWcvAoD1WEwPezzVTU35iI2d
i9VI/7StxptwoGJOw2qgf5ACwQs+SxSzS1N83vuW02A=
-----END RSA PRIVATE KEY-----
EOF
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
chown $USER:$GRP ~/onion_service/hostname
chown $USER:$GRP ~/onion_service/private_key
chmod 600 ~/onion_service/hostname
chmod 600 ~/onion_service/private_key


eval homedir="~"
onion_service_name=`cat ~/onion_service/hostname`
sudo cp 000-default.conf /etc/apache2/sites-enabled/000-default.conf
sudo a2enmod rewrite
sudo a2enmod proxy_wstunnel
sudo service apache2 restart
cp torrc.default torrc

sudo sed -i "s+SEDREPLACEHSD+${homedir}+" torrc
