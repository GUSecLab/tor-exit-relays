#!/bin/bash
sudo apt-get update

# install mysql
sudo apt install -y mysql-server mysql-client libmysqlclient-dev libtalloc-dev libssl-dev openssl

# install freeradius
sudo apt-get install -y freeradius freeradius-mysql

# install dante

sudo apt-get install -y gcc make libpam0g-dev libwrap0 libwrap0-dev libpam-radius-auth python3-pip

wget http://www.inet.no/dante/files/dante-1.4.2.tar.gz
tar -xvf dante-1.4.2.tar.gz
pushd dante-1.4.2/
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
make
sudo make install
popd
