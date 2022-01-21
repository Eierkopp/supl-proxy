# supl-hack

A simple TCP proxy that filters a IMSI from SUPL requests and replaces them with a fake hiding your identity from Google.

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
      
