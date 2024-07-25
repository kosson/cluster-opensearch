#!/bin/sh
config_file="opensearch_installer_vars.cfg"

if [ -f "$config_file" ]; then
    source "$config_file"

    #CERT_DN="/C=RO/ST=ILFOV/L=MAGURELE/O=NIPNE/OU=DFCTI"
    # Root CA key creation
    openssl genrsa -out $OS_CERTS_PATH/root-ca-key.pem 2048
    openssl req -new -x509 -sha256 -key $OS_CERTS_PATH/root-ca-key.pem -subj "$CERT_DN/CN=$LOCAL_ROOT_CA" -out $OS_CERTS_PATH/root-ca.pem -days 730
    # TSL certificate for administrator
    openssl genrsa -out $OS_CERTS_PATH/$ADMIN_CA-key-temp.pem 2048
    openssl pkcs8 -inform PEM -outform PEM -in $OS_CERTS_PATH/$ADMIN_CA-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out $OS_CERTS_PATH/$ADMIN_CA-key.pem
    openssl req -new -key $OS_CERTS_PATH/$ADMIN_CA-key.pem -subj "$CERT_DN/CN=$ADMIN_CA" -out $OS_CERTS_PATH/$ADMIN_CA.csr
    openssl x509 -req -in $OS_CERTS_PATH/$ADMIN_CA.csr -CA $OS_CERTS_PATH/root-ca.pem -CAkey $OS_CERTS_PATH/root-ca-key.pem -CAcreateserial -sha256 -out $OS_CERTS_PATH/$ADMIN_CA.pem -days 730
    # TLS certificate for the nodes
    for NODE_NAME in "os01" "os02" "os03" "os04" "os05" "client" "dashboards"
    do
        openssl genrsa -out $OS_CERTS_PATH/$NODE_NAME-key-temp.pem 2048
        openssl pkcs8 -inform PEM -outform PEM -in $OS_CERTS_PATH/$NODE_NAME-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out $OS_CERTS_PATH/$NODE_NAME-key.pem
        openssl req -new -key $OS_CERTS_PATH/$NODE_NAME-key.pem -subj $CERT_DN/CN=$NODE_NAME -out $OS_CERTS_PATH/$NODE_NAME.csr
        echo "subjectAltName=DNS:$NODE_NAME" > $OS_CERTS_PATH/$NODE_NAME.ext
        openssl x509 -req -in $OS_CERTS_PATH/$NODE_NAME.csr -CA $OS_CERTS_PATH/root-ca.pem -CAkey $OS_CERTS_PATH/root-ca-key.pem -CAcreateserial -sha256 -out $OS_CERTS_PATH/$NODE_NAME.pem -days 730 -extfile $OS_CERTS_PATH/$NODE_NAME.ext
        rm $OS_CERTS_PATH/$NODE_NAME-key-temp.pem $OS_CERTS_PATH/$NODE_NAME.csr $OS_CERTS_PATH/$NODE_NAME.ext
        chown -R 1000:1000 $OS_CERTS_PATH/$NODE_NAME-key.pem $OS_CERTS_PATH/$NODE_NAME.pem
    done
else
    echo "$config_file not found."    
fi

rm -f $OS_CERTS_PATH/$ADMIN_CA.csr $OS_CERTS_PATH/$ADMIN_CA-key-temp.pem
# cp $OS_CERTS_PATH/admin.pem $DASHBOARDS_CERTS_PATH
# cp $OS_CERTS_PATH/admin-key.pem $DASHBOARDS_CERTS_PATH
# cp $OS_CERTS_PATH/root-ca.pem $DASHBOARDS_CERTS_PATH
# cp $OS_CERTS_PATH/root-ca-key.pem $DASHBOARDS_CERTS_PATH
# mv $OS_CERTS_PATH/dashboards.pem $DASHBOARDS_CERTS_PATH
# mv $OS_CERTS_PATH/dashboards-key.pem $DASHBOARDS_CERTS_PATH
# chmod -R 755 $DASHBOARDS_CERTS_PATH
rm -f $OS_CERTS_PATH/root-ca.srl