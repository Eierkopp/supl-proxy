#!/bin/bash

dpkg-buildpackage -b --no-sign

version=$(dpkg-parsechangelog -S version)

dpkg -c ../supl-proxy_${version}_all.deb
