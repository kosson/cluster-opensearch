#!/bin/bash
# Adaug userul admin și dashboards
curl -k --cert assets/opensearch/certs/admin.pem --key assets/opensearch/certs/admin-key.pem -XPATCH https://0.0.0.0:9200/_plugins/_security/api/internalusers -H 'Content-Type: application/json' -d'
[
  {
    "op": "add", "path": "/admin", "value": { "password": "test@Cici24#ANA", "backend_roles": ["all_access","readall"], "opendistro_security_roles": ["all_access"] }
  }
]';
curl -k --cert assets/opensearch/certs/admin.pem --key assets/opensearch/certs/admin-key.pem -XPATCH https://0.0.0.0:9200/_plugins/_security/api/internalusers -H 'Content-Type: application/json' -d'
[
  {
    "op": "add", "path": "/dashboards", "value": { "password": "test@Cici24#ANA", "backend_roles": ["all_access","readall","kibana_server"], "opendistro_security_roles": ["all_access"] }
  }
]';
# Crează rolul dashboards
curl -k --cert assets/opensearch/certs/admin.pem --key assets/opensearch/certs/admin-key.pem -XPUT "https://0.0.0.0:9200/_plugins/_security/api/roles/dashboards" -H 'Content-Type: application/json' -d'
{
  "cluster_permissions": [
    "cluster_all",
    "indices_monitor"
  ],
  "index_permissions": [{
    "index_patterns": [
      "*"
    ],
    "dls": "",
    "fls": [],
    "masked_fields": [],
    "allowed_actions": [
      "crud"
    ]
  }],
  "tenant_permissions": [{
    "tenant_patterns": [
      "global"
    ],
    "allowed_actions": [
      "kibana_write"
    ]
  }]
}'
# Adaugarea mappingului pentru accesarea propriului index
curl -k --cert assets/opensearch/certs/admin.pem --key assets/opensearch/certs/admin-key.pem -XPUT "https://0.0.0.0:9200/_plugins/_security/api/rolesmapping/own_index" -H 'Content-Type: application/json' -d'
{
    "backend_roles": [],
    "hosts": [], 
    "users": ["*"],
    "description": "Allow full access to an index named like the username"
}';
# Adaug mappingul pentru kibana_server
curl -k --cert assets/opensearch/certs/admin.pem --key assets/opensearch/certs/admin-key.pem -XPUT "https://0.0.0.0:9200/_plugins/_security/api/rolesmapping/kibana_server" -H 'Content-Type: application/json' -d'
{
    "backend_roles": ["all_access","kibana_server","kibana_user"],
    "hosts": ["dashboards","os01"], 
    "users": ["dashboards","admin"]
}';
# Adaug mappingul și pentru all_access
curl -k --cert assets/opensearch/certs/admin.pem --key assets/opensearch/certs/admin-key.pem -XPUT "https://0.0.0.0:9200/_plugins/_security/api/rolesmapping/all_access" -H 'Content-Type: application/json' -d'
{
    "backend_roles": ["admin"],
    "hosts": ["dashboards","os01"], 
    "users": ["CN=admin,OU=DFCTI,O=NIPNE,L=MAGURELE,ST=ILFOV,C=RO"]
}';
# Adaug mappingul și pentru dashboards
curl -k --cert assets/opensearch/certs/admin.pem --key assets/opensearch/certs/admin-key.pem -XPUT "https://0.0.0.0:9200/_plugins/_security/api/rolesmapping/dashboards" -H 'Content-Type: application/json' -d'
{
    "backend_roles": ["all_access","kibana_server","dashboards","readall"],
    "hosts": ["dashboards","os01"], 
    "users": ["dashboards","admin"]
}';
# Refac mapping pentru readall (vezi https://opensearch.org/docs/latest/security/authentication-backends/client-auth/#assigning-roles-to-a-certificates-common-name)
curl -k --cert assets/opensearch/certs/admin.pem --key assets/opensearch/certs/admin-key.pem -XPUT "https://0.0.0.0:9200/_plugins/_security/api/rolesmapping/readall" -H 'Content-Type: application/json' -d'
{
    "backend_roles": ["all_access","readall","kibana_server"],
    "hosts": ["dashboards","os01","0.0.0.0"], 
    "users": ["dashboards","admin"]
}';