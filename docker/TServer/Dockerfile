FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
ARG NGINX_VERSION=1.18.0
ARG RTMP_MODULE_VERSION=1.2.2

ENV PATH $PATH:/usr/local/nginx/sbin

RUN apt-get update && apt-get install -q -y --no-install-recommends pciutils wget curl unzip libbz2-dev net-tools dnsutils ifupdown procps iputils-ping apache2 telnet

# for nginx/rtmp
RUN apt-get install build-essential libpcre3 libpcre3-dev zlib1g-dev libssl-dev -q -y

RUN wget -c http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz  -O - | tar -xz

RUN wget -c --no-check-certificate https://github.com/arut/nginx-rtmp-module/archive/v${RTMP_MODULE_VERSION}.tar.gz -O - | tar -xz

WORKDIR /nginx-${NGINX_VERSION}

# --disable-werror
RUN ./configure --add-module=/nginx-rtmp-module-${RTMP_MODULE_VERSION} --with-debug \
  --http-log-path=/var/log/nginx/access.log \
  --error-log-path=/var/log/nginx/error.log \
  --conf-path=/etc/nginx/conf/nginx.conf && \
  make && make install

# RUN apt-get install -q -y nginx libnginx-mod-rtmp

ADD nginx.conf /etc/nginx/conf/nginx.conf

ADD ftp_server.py prep.sh /

# for ftp server
RUN apt-get install -q -y python3-pyftpdlib

WORKDIR /

RUN chmod +x /ftp_server.py /prep.sh

# RUN apt-get install iperf # in the server run: iperf -s

CMD /prep.sh

# CMD "/bin/bash"

# docker system prune -a
# DOCKER_BUILDKIT=1 docker build -t connman .
# docker run --name connman -p 1935:1935 -p 80:80 -p 21:21 -v ${PWD}/../videos:/var/www/html/ --privileged --rm -it connman
# /etc/init.d/nginx start
# service nginx start
# nginx -g "daemon off;" &
# service apache2 start

# ffmpeg -re -i 1.mp4 -c:v libx264 -preset veryfast -maxrate 1024k -bufsize 2048k -c:a aac -f flv rtmp://127.0.0.1:1935/live
# curl -v --insecure ftp://127.0.0.1:21/1.mp4 --user user:123456 -o /home/iobaidat/Desktop/
# curl --insecure -L http://127.0.0.1:80/1.mp4 -o 1.mp4

# docker exec -it connman bash
# service apache2 status
# ./ftp_server.py 172.17.0.2