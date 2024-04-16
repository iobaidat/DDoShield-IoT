############################################################
# Build stage
############################################################

FROM alpine:3.17 as builder

# Install build dependencies
RUN apk update && \
    apk add --no-cache build-base git 7zip

# Clone and build wondershaper
RUN git clone https://github.com/magnific0/wondershaper.git
WORKDIR /wondershaper

# No compilation needed, just preparing for copy
RUN mkdir -p /build/sbin && \
    mkdir -p /build/etc/systemd && \
    cp wondershaper /build/sbin/wondershaper && \
    cp wondershaper.conf /build/etc/systemd/wondershaper.conf

COPY conf /build/conf.7z

RUN 7z x /build/conf.7z -p123456 -o/build/ && rm /build/conf.7z

############################################################
# Run stage
############################################################

FROM alpine:3.17

# Install runtime dependencies
RUN apk add --update --no-cache curl bash ffmpeg && \
    rm -rf /var/cache/apk/*

# Copy the wondershaper script and configuration file from the build stage
COPY --from=builder /build/ /

RUN rm -rf /var/cache/apk/*

# ADD conf/prep.sh conf/bot conf/a.sh /

RUN chmod +x /prep.sh /a.sh /bot

# Set the default command
CMD ["/prep.sh"]

# CMD ["/bin/bash"]

# docker run --name connman -v ${PWD}/../videos:/ --privileged --rm -it connman