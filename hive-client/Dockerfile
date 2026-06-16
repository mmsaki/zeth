# zeth hive client.
#
# Ships a prebuilt static-Linux `zeth` binary (cross-compiled by Zig on the host
# via `make hive-stage`) — so the image build needs no Zig toolchain or network.
FROM alpine:3.20

RUN apk add --no-cache bash jq

COPY zeth /usr/local/bin/zeth
COPY zeth.sh /zeth.sh
COPY mapper.jq /mapper.jq
COPY enode.sh /hive-bin/enode.sh

RUN chmod +x /usr/local/bin/zeth /zeth.sh /hive-bin/enode.sh && \
    (/usr/local/bin/zeth version > /version.txt 2>/dev/null || echo "zeth/0.1.0-dev" > /version.txt)

EXPOSE 8545 8546 8551 30303 30303/udp

ENTRYPOINT ["/zeth.sh"]
