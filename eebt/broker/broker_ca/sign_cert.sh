#!/bin/bash
source ca_env.sh
cert_id=$1
[ -z "$cert_id" ] && exit
openssl ca -batch -in $cadir/requests/$cert_id.csr -out $cadir/certs/$cert_id.pem
rm $cadir/requests/$cert_id.csr