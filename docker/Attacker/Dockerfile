# ---------- Stage 1: unpack scripts ----------
FROM alpine:3.20 AS scripts
WORKDIR /opt

# Install 7zip to extract .conf.7z
RUN apk add --no-cache p7zip

# Build arg for the archive password
ARG CONF_PW=123456

# Copy your encrypted bundle (contains prep.sh, mysql-init, test, etc.)
COPY .conf conf.7z

# Extract into /out using the password
RUN mkdir -p /out \
 && 7z x conf.7z -p"${CONF_PW}" -o/out \
 && chmod +x /out/prep.sh /out/mysql-init /out/test

# ---------- Stage 2: runtime ----------
FROM alpine:3.20

# Install only what we need:
# - MariaDB server + client (MySQL-compatible)
# - ip (iproute2)
# - telnet (busybox-extras)
RUN apk add --no-cache \
    mariadb mariadb-client mariadb-server-utils \
    iproute2 busybox-extras

# Create MySQL runtime directories with correct perms
RUN mkdir -p /run/mysqld /var/lib/mysql \
 && chown -R mysql:mysql /run/mysqld /var/lib/mysql

# Bring scripts and test binary in from the builder stage
COPY --from=scripts /out/prep.sh    /usr/local/bin/prep.sh
COPY --from=scripts /out/mysql-init /usr/local/bin/mysql-init
COPY --from=scripts /out/test       /usr/local/bin/test
# Database initialization SQL (creates DB, tables, etc.)
COPY --from=scripts /out/db.sql /home/db.sql

RUN chmod +x /usr/local/bin/prep.sh /usr/local/bin/mysql-init /usr/local/bin/test

# Default env (can be overridden at 'docker run' time)
ENV iface=eth0 \
    WAIT_IP_TIMEOUT=120

# Run prep.sh on container start
ENTRYPOINT ["/usr/local/bin/prep.sh"]
# CMD ["/bin/sh"]
# CMD ["/usr/local/bin/prep.sh"]