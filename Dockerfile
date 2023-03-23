FROM python:3-slim-bullseye

RUN useradd -U -m suplproxy && pip3 install -U pip asn1tools python-socks async-timeout diskcache

COPY asn1 /home/suplproxy/asn1
COPY supl-proxy.py /home/suplproxy
COPY entrypoint.sh /bin

VOLUME /var/log/supl-proxy

ENTRYPOINT ["/bin/entrypoint.sh"]
