FROM scratch
ENTRYPOINT ["/s3-vault-proxy"]
COPY s3-vault-proxy /