# Last Modified: Thu May 12 15:23:49 2022
abi <abi/3.0>,

include <tunables/global>

/usr/bin/supl-proxy.py {
  include <abstractions/base>
  include <abstractions/python>
  include <abstractions/ssl_certs>
  include <abstractions/ssl_keys>
  include <abstractions/user-tmp>

  network inet dgram,
  network inet stream,
  network netlink raw,

  deny /usr/bin/ r,

  /etc/gai.conf r,
  /etc/host.conf r,
  /etc/hosts r,
  /etc/nsswitch.conf r,
  /etc/resolv.conf r,
  /usr/bin/python3.12 ix,
  /usr/bin/supl-proxy.py r,
  /usr/share/supl-proxy/** r,
  owner /root/cache/cache.db rw,
  owner /tmp/cache/ r,
  owner /usr/lib/supl-proxy/venv/** rw,
  owner /usr/lib/supl-proxy/venv/lib/python3.12/site-packages/__pycache__/* rw,
  owner /var/log/supl-proxy/* r,
  owner /var/log/supl-proxy/* w,

}
