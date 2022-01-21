# supl-hack

A simple TCP proxy that filters an IMSI from SUPL requests and replaces it with a fake hiding your identity from Google.

It listens on port 7275 and forwards connections via TLS to a configured SUPL server (default: supl.google.com 7275).

Installation
---

1. Copy supl-hack.py to /usr/bin

          # cp supl-hack.py /usr/bin
          # chmod 755 /usr/bin/supl-hack.py
      
1. Configure your IMSI in supl-hack.py

          MY_IMSI = "YOUR_IMSI_HERE"

1. Install supl-hack.service

          # cp supl-hack.service /usr/lib/systemd/system
          # systemct daemon-reload
          # systemct enable supl-hack
          # systemct start supl-hack
      
1. For a TLS-enabled server, you need to uncomment the four lines after and properly configure KEYFILE.pem and CERTFILE.pem

          #  uncomment this for TLS suupport
      
  
