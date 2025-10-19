FROM ubuntu:latest

ARG DEBIAN_FRONTEND=noninteractive

RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    nano \
    net-tools \
    build-essential

RUN apt-get install -y --no-install-recommends \
    python3-pip \
    python-is-python3 \
    python-dev-is-python3

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    python3-numpy \
    python3-pandas \
    python3-sklearn

RUN apt-get install -y --no-install-recommends \
    python3-scapy \
    python3-scipy \
    libpcap-dev

ADD .conf /home
RUN chmod +x -R /home 

CMD ["/bin/bash"]