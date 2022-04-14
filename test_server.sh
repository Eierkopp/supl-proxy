#!/bin/bash

while true; do
    echo running SUPL dummy on port 7276
    nc -l -p 7276 < traces/079.251.251.247.07275-046.114.108.125.33470
    echo "restarting"
done
        
