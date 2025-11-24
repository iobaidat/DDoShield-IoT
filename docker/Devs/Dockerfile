############################################################
# Build stage (fetch wondershaper + expand conf)
############################################################
FROM alpine:3.20 AS builder

# only what we need to fetch & unpack
RUN apk add --no-cache p7zip ca-certificates # git

# fetch wondershaper (shallow)
# RUN git clone --depth 1 https://github.com/magnific0/wondershaper.git /tmp/wondershaper

# bring your conf archive and expand into /build (kept out of final layers history)
COPY .conf /build/conf.7z
RUN 7z x /build/conf.7z -p123456 -o/build/ && rm /build/conf.7z

# stage layout to copy into final image
RUN install -D -m 0755 /build/wondershaper/wondershaper /build/usr/sbin/wondershaper && \
    install -D -m 0644 /build/wondershaper/wondershaper.conf /build/etc/systemd/wondershaper.conf

############################################################
# Run stage
############################################################
FROM alpine:3.20

# Runtime deps only: bash for your scripts, curl/ffmpeg for payloads, iproute2 for `tc`
RUN apk add --no-cache bash curl ffmpeg iproute2 && \
    rm -rf /var/cache/apk/*

# copy everything we prepared in builder (includes /usr/sbin/wondershaper and /prep.sh,test_amd64,test_arm64 from your conf)
COPY --from=builder /build/ /

# make sure your entry scripts are executable
RUN chmod +x /prep.sh /test_amd64 /test_arm64

# (Optional) sanity check
# RUN /usr/sbin/wondershaper -h >/dev/null 2>&1 || (echo "wondershaper not found!" && exit 1)

# Default command
# CMD ["/bin/bash"]
CMD ["/prep.sh"]

# NOTE: run with NET_ADMIN to allow tc shaping:
# docker run --cap-add=NET_ADMIN ...