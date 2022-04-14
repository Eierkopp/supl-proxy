#!/bin/bash

venv/bin/python3 ./supl-proxy.py -s localhost:7276 -p 7278 -t 7279 -l /tmp/supl-proxy.log -c tls/ssl-cert-snakeoil.pem -k tls/ssl-cert-snakeoil.key
# venv/bin/python3 ./supl-proxy.py -o socks5://eier:kopp@localhost:9050 -p 7278 -t 7279 -s localhost:7276 -l /tmp/supl-proxy.log
