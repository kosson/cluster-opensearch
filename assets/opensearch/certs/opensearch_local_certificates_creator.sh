#!/bin/sh
OPENDISTRO_DN="/C=RO/ST=ILFOV/L=MAGURELE/O=NIPNE/OU=DFCTI"
# Root CA key creation
openssl genrsa -out root-ca-key.pem 2048
openssl req -new -x509 -sha256 -key root-ca-key.pem -subj "$OPENDISTRO_DN/CN=localrootca" -out root-ca.pem -days 730
# TSL certificate for administrator
openssl genrsa -out admin-key-temp.pem 2048
openssl pkcs8 -inform PEM -outform PEM -in admin-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out admin-key.pem
openssl req -new -key admin-key.pem -subj "$OPENDISTRO_DN/CN=admin" -out admin.csr
openssl x509 -req -in admin.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -out admin.pem -days 730
# TLS certificate for the nodes
for NODE_NAME in "os01" "os02" "os03" "os04" "os05" "client" "os-dashboards"
do
    openssl genrsa -out "$NODE_NAME-key-temp.pem" 2048
    openssl pkcs8 -inform PEM -outform PEM -in "$NODE_NAME-key-temp.pem" -topk8 -nocrypt -v1 PBE-SHA1-3DES -out "$NODE_NAME-key.pem"
    openssl req -new -key "$NODE_NAME-key.pem" -subj "$OPENDISTRO_DN/CN=$NODE_NAME" -out "$NODE_NAME.csr"
    echo "subjectAltName=DNS:$NODE_NAME" > $NODE_NAME.ext
    openssl x509 -req -in "$NODE_NAME.csr" -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -out "$NODE_NAME.pem" -days 730 -extfile $NODE_NAME.ext
    rm "$NODE_NAME-key-temp.pem" "$NODE_NAME.csr" "$NODE_NAME.ext"
    chown -R 1000:1000 $NODE_NAME-key.pem $NODE_NAME.pem
done
rm -f admin.csr root-ca.srl
