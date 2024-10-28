#!/bin/bash

# TLS     
# tail -f  traces/046.114.108.081.46104-084.176.237.197.07275|  openssl s_client -connect localhost:7279

# TCP

# SUPL V1
# nc localhost 7278 < traces/046.114.108.081.46104-084.176.237.197.07275

# SUPL V2
nc localhost 7278 < traces/094.019.228.143.07279-176.015.167.225.36797


