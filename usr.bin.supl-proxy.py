# Last Modified: Sun Feb  6 10:28:32 2022
abi <abi/3.0>,

include <tunables/global>

/usr/bin/supl-proxy.py flags=(complain) {
  include <abstractions/base>
  include <abstractions/python>

  network inet dgram,
  network inet stream,

  /etc/hosts r,
  /usr/bin/python3.9 ix,
  /usr/bin/supl-proxy.py r,

}
