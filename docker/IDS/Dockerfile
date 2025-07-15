FROM ubuntu:23.10

ARG DEBIAN_FRONTEND=noninteractive

RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    nano \
    net-tools \
    python-is-python3

RUN apt-get install -y --no-install-recommends \
    python3-pandas \
    python3-sklearn \
    python3-scapy \
    python3-scipy

RUN apt-get install -y --no-install-recommends \
    python3-pip

RUN PIP_BREAK_SYSTEM_PACKAGES=1 pip3 install --upgrade tensorflow-cpu

COPY ids-online.py /ids-online.py
COPY kmeans_model.pkl /kmeans_model.pkl

RUN chmod +x /ids-online.py /kmeans_model.pkl

CMD ["/bin/bash"]