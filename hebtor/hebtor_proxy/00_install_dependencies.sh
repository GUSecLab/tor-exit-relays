#!/bin/bash
sudo apt install -y python3 python3-pip git tor
sudo -H pip3 install pycryptodome Django pysocks

git clone https://github.com/rofl0r/microsocks.git
pushd microsocks && make && sudo cp ./microsocks /usr/bin && popd || return





