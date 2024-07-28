#!bin/bash
docker stop $(docker ps -aq);
docker container rm -f $(docker container ls -aq);
docker volume rm $(docker volume ls -q --filter dangling=true);
docker image rm cluster-opensearch-os01:latest;
rm -rf assets/opensearch/data/os01data/* assets/opensearch/data/os02data/* assets/opensearch/data/os03data/* assets/opensearch/data/os04data/* assets/opensearch/data/os05data/*;