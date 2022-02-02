# Last Modified: Wed Feb  2 10:53:35 2022
abi <abi/3.0>,

include <tunables/global>

/usr/bin/supl-proxy.py flags=(complain) {
  include <abstractions/base>
  include <abstractions/python>

  /usr/bin/python3.9 ix,
  /usr/bin/supl-proxy.py r,

}
