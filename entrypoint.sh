#!/bin/bash

set -ex

if [ "${1:0:1}" = "/" ]; then

    exec "$@"
    
elif [ "${1:0:1}" = "-" ]; then

    cd ~suplproxy
    exec runuser -u suplproxy -- python3 /home/suplproxy/supl-proxy.py -g /home/suplproxy/asn1 "$@"

fi 

exec runuser -u suplproxy -- python3 /home/suplproxy/supl-proxy.py --help
