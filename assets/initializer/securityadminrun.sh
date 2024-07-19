#!/bin/bash
# chmod +x /usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh && \
# bash /usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh \
# -cd /usr/share/opensearch/config/opensearch-security/ \
# -cacert /usr/share/opensearch/config/root-ca.pem \
# -cert /usr/share/opensearch/config/admin.pem \
# -key /usr/share/opensearch/config/admin-key.pem \
# -icl \
# -nhnv \
# -t config \
# -h os01 \
# --accept-red-cluster
# First start the opensearch processs
# opensearch;
# Second run the initialization
ADMIN=/usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh;
# chmod +x $ADMIN;
# chown 1000:1000 $ADMIN;
echo '-----------------------------------------------------------------------';
echo '          /!\   Initial setting                                        ';
echo '-----------------------------------------------------------------------';
sleep 40;
until curl -k --cert /usr/share/opensearch/config/admin.pem --key /usr/share/opensearch/config/admin-key.pem -XGET https://0.0.0.0:9200 --silent;
    do
    echo 'Waiting to connect to the cluster (https://0.0.0.0:9200)'; 
    sleep 10;
done;
count=0;
until $ADMIN -cd /usr/share/opensearch/config/opensearch-security/ -cacert config/root-ca.pem -cert config/admin.pem -key config/admin-key.pem -icl -nhnv --accept-red-cluster -h os01 || (( count++>= 20 ));
    do
    echo 'Waiting execution completion '; 
    sleep 10;
done;