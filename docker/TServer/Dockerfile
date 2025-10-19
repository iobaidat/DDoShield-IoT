FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

# Runtime deps: nginx + RTMP module, apache, python FTP, tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx libnginx-mod-rtmp \
    apache2 \
    python3 python3-pyftpdlib \
    iproute2 ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*

ADD .conf /tmp

# RTMP-enabled nginx.conf
RUN mv /tmp/.nginx.conf /etc/nginx/nginx.conf

# FTP server and startup script
RUN mv /tmp/.ftp_server.py /usr/local/bin/ftp_server.py
RUN mv /tmp/.prep.sh       /usr/local/bin/prep.sh
RUN chmod +x /usr/local/bin/*.py /usr/local/bin/prep.sh

# CMD ["/bin/bash"]
CMD ["/usr/local/bin/prep.sh"]