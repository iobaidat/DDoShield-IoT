#!/usr/bin/env bash

# loop until we have IP
while true;
do
  IPPre=`ifconfig eth0 | grep 'inet ' | cut -d: -f2 | awk '{ print $2}' | cut -f1 -d.`
  if [ -z "$IPPre" ]
  then
        sleep 2
  else
        if [ $IPPre -eq 10 ]; then break ; fi
        sleep 2
  fi
done

nginx -g "daemon off;" &

IP=`ifconfig eth0 | grep 'inet ' | cut -d: -f2 | awk '{ print $2}'` && ./ftp_server.py $IP &

service apache2 start
service apache2 start

while true;
do
  SEC=$((10 + RANDOM % 20))
  sleep $SEC;
done