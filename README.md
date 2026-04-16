# OpenSearch Cluster

This repo is designed to realize an OpenSearch cluster with five nodes using Docker Compose. Initiatly it was necessary to build the cluster for Invenio RDM application. Now it aims to be independent starting with 3.6 version.
This project has been create on an Ubuntu 25.10. Docker and Java should be installed already.
All the subdirectories have their own README.

For this project every file dependancy for the nodes are found in an arbitrary subfolder named `assets`. This is the solution to creating a secure cluster, following the general indications of the original documentation - [Configuring basic security settings](https://docs.opensearch.org/latest/install-and-configure/install-opensearch/docker#configuring-basic-security-settings).
In this subfolder there are three separate subfoolders:

- `dashboards`,
- `opensearch`, and
- `ssl`.

One important note is that `Dockerfile` is found in the `assets/opensearch` subfolder. To install or remove plugins, see https://docs.opensearch.org/latest/install-and-configure/install-opensearch/docker#working-with-plugins.
In this dockerized version, all the nodes are named following the convention where `os` means OpenSearch, followed by the number of the node, like in the following: `os01` for the first node, and so on. Modifing this needs to trigger forther more modifications in scripts and configuration file. Pay attention to this if you want to adapt it to your naming conventions.

Here you will find all the necesary configuration files. Note that the ssl certificates are created using the `opensearch_local_certificates_creator.sh` script that uses the `opensearch_installer_vars.cfg` file. Running this script created a local signed certificates in the `assets/ssl` subdirectory. These certificates need to have an entry in the configuration files of every node. For example, for the `os01` node in `assets/opensearch/config/os01/opensearch.yml` you would have a section like:

```yml
plugins.security.ssl.http.enabled: true      
plugins.security.ssl_cert_reload_enabled: true      
plugins.security.ssl.transport.pemkey_filepath: /usr/share/opensearch/config/os01-key.pem # relative path
plugins.security.ssl.transport.pemcert_filepath: /usr/share/opensearch/config/os01.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /usr/share/opensearch/config/root-ca.pem
plugins.security.ssl.http.pemkey_filepath: /usr/share/opensearch/config/os01-key.pem
plugins.security.ssl.http.pemcert_filepath: /usr/share/opensearch/config/os01.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /usr/share/opensearch/config/root-ca.pem
```

The original documentation is to be found at [Configuring TLS certificates](https://docs.opensearch.org/latest/security/configuration/tls).