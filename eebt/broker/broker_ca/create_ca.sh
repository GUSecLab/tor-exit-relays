#!/bin/bash
source ca_env.sh
mkdir $cadir
pushd $cadir
mkdir newcerts certs crl private requests
touch index.txt
echo 'unique_subject = no' > index.txt.attr
echo '1234' > serial
openssl genrsa -out private/cakey.pem 4096
openssl req -new -x509 -key ./private/cakey.pem \
-out cacert.pem -days 3650 -set_serial 0 \
-subj $ca_subj
popd