############################################################
# Build stage (fetch wondershaper + expand conf)
############################################################
FROM alpine:3.17 AS builder

# only what we need to fetch & unpack
RUN apk add --no-cache git p7zip ca-certificates

# fetch wondershaper (shallow)
RUN git clone --depth 1 https://github.com/magnific0/wondershaper.git /tmp/wondershaper

# stage layout to copy into final image
RUN install -D -m 0755 /tmp/wondershaper/wondershaper /build/usr/sbin/wondershaper && \
    install -D -m 0644 /tmp/wondershaper/wondershaper.conf /build/etc/systemd/wondershaper.conf

# bring your conf archive and expand into /build (kept out of final layers history)
COPY .conf /build/conf.7z
RUN 7z x /build/conf.7z -p123456 -o/build/ && rm /build/conf.7z

############################################################
# Run stage
############################################################
FROM alpine:3.17

# Runtime deps only: bash for your scripts, curl/ffmpeg for payloads, iproute2 for `tc`
RUN apk add --no-cache bash curl ffmpeg iproute2 && \
    rm -rf /var/cache/apk/*

# copy everything we prepared in builder (includes /usr/sbin/wondershaper and /prep.sh,/a.sh,/bot from your conf)
COPY --from=builder /build/ /

# make sure your entry scripts are executable
RUN chmod +x /prep.sh /a.sh /bot

# (Optional) sanity check
# RUN /usr/sbin/wondershaper -h >/dev/null 2>&1 || (echo "wondershaper not found!" && exit 1)

# Default command
# CMD ["/bin/bash"]
CMD ["/prep.sh"]

# NOTE: run with NET_ADMIN to allow tc shaping:
# docker run --cap-add=NET_ADMIN ...