# supl-proxy

A simple TCP proxy that logs SUPL communication between mobile phone
and SUPL server while spoofing the IMSI towards the server hiding your
true identity.

## Installation


### Debian

`build_deb.sh` builds a Debian package of the current version
(e.g. 1.6). If that fails, you probably need to install some
additional packages:

        # apt install debhelper dh-python python3-virtualenv \
          python3-prompt-toolkit

If `build_deb.sh` succeeds, install the package with e.g.

        # dpkg -i supl-proxy_1.6_all.deb
        
Start the service with 

        # systemctl start supl-proxy
        
Make it automatically start at boot time with

        # systemctl enable supl-proxy
        
Configuration options will be fetched from `/etc/default/supl-proxy`.
        

### RedHat

... to be added ...

### Docker

Build a image with 

       $ docker build -t supl-proxy .
       
Run it with e.g.

       $ docker run -it supl-proxy:latest -s supl.google.com:7276 -p 7276
       
to listen for unencrypted traffic on port 7276 and forward it to
Google's unencrypted SUPL service.
       
## Configuration

Options are passed on the command line. The following options are available:

    # supl-proxy.py --help
    usage: supl-proxy.py [-h] [-s SERVER] [-v] [--tls] [-c CERT] [-k KEY] 
    ... [-p TCP_PORT] [-t TLS_PORT] [-o SOCKS] [-g GRAMMAR] [-l LOGFILE]

    Supl Proxy

    options:
      -h, --help            show this help message and exit
      -s SERVER, --server SERVER
                            SUPL server (host:port)
      -v, --tls_ignore_errors
                            ignore server TLS error
      --tls                 server uses TLS
      -c CERT, --cert CERT  proxy TLS certificate
      -k KEY, --key KEY     proxy TLS keyfile
      -p TCP_PORT, --tcp_port TCP_PORT
                            TCP port
      -t TLS_PORT, --tls_port TLS_PORT
                            TLS port
      -o SOCKS, --socks SOCKS
                            socks proxy address, if any
      -g GRAMMAR, --grammar GRAMMAR
                            path to asn.1 grammar
      -l LOGFILE, --logfile LOGFILE
                            path to logfile

Options `--cert` and `--key` are required if you want to provide an
encrypted service, as Google does on port 7275. Beware that even if
you configure a valid certificate and validate it with e.g. 

    $ openssl s_client -connect YOUR_SERVER:YOUR-PORT
    
it might still get rejected by a mobile phone.

Option `--socks` can be used to route raffic to the parent server
through a socks proxy (e.g. `tor`) in order to also hide your IP.

`--tls` tells the proxy that connection to the parent server uses
TLS. Hence you will need it, if you configure `supl.google.com:7275`
as your parent, while for `supl.google.com:7276` it has to be
ommitted.

`--grammar` should point to the installation path of the ASN.1 files
needed to decode the SUPL traffic.

The Debian configuration file `/etc/default/supl-proxy` exports
`SUPL_HOST` for the parent server and `EXTRA_ARGS` for all other
configuration settings. 

Here is a sample configuration offering unencrypted service on port
7275 and TLS encrypted service on port 7276 using the TLS encrypted
Chinese `supl.qxwz.com:7275` as parent. Since `supl.qxwz.com` uses a
self-signed certificate, validation needs to be disabled.

    # cat /etc/default/supl-proxy
    SUPL_HOST=supl.qxwz.com:7275
    EXTRA_ARGS="--tls -v -p 7275 -t 7276 -c /tmp/my.crt -k /tmp/my.key"
    

