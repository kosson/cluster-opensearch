FROM curlimages/curl
ADD assets/initializer/securityadminrun.sh /
# COPY --chmod=755 assets/opensearch/init.sh /usr/share/opensearch/config/
USER root
RUN chmod +x /securityadminrun.sh
USER 1000
# CMD ["/usr/share/opensearch/config/init.sh"]