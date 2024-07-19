#!/bin/sh
OPENDISTRO_DN="/C=RO/ST=ILFOV/L=MAGURELE/O=NIPNE/OU=DFCTI"
# TLS certificate for the nodes
for NODE_NAME in "dashboards"
do
    openssl genrsa -out "$NODE_NAME-key-temp.pem" 2048
    openssl pkcs8 -inform PEM -outform PEM -in "$NODE_NAME-key-temp.pem" -topk8 -nocrypt -v1 PBE-SHA1-3DES -out "$NODE_NAME-key.pem"
    openssl req -new -key "$NODE_NAME-key.pem" -subj "$OPENDISTRO_DN/CN=$NODE_NAME" -out "$NODE_NAME.csr"
    echo "subjectAltName=DNS:$NODE_NAME" > $NODE_NAME.ext
    openssl x509 -req -in "$NODE_NAME.csr" -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -out "$NODE_NAME.pem" -days 730 -extfile $NODE_NAME.ext
    rm "$NODE_NAME-key-temp.pem" "$NODE_NAME.csr" "$NODE_NAME.ext"
done
