#!/bin/bash
sudo apt-get update

# install dante

sudo apt-get install -y gcc make libpam0g-dev libwrap0 libwrap0-dev libpam-radius-auth python3-pip

# install jq for shell json parsing
sudo apt-get install -y jq

wget http://www.inet.no/dante/files/dante-1.4.2.tar.gz
tar -xvf dante-1.4.2.tar.gz
pushd dante-1.4.2/
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
make
sudo make install
popd
