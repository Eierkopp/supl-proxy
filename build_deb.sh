#!/bin/bash

dpkg-buildpackage -b --no-sign


dpkg -c ../supl-proxy_*_all.deb
