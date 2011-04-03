## Layer 2 network neighbourhood discovery tool ##

Tool to discover hosts in your network using ARP pings.
See also [this question on stackoverflow.com][3]

## Dependencies ##

* [scapy][1] for networking functions like [arping][2]

## Run ##

sudo ./neighbourhood.py

## TODO ##

* IPv6 support

## Known issues ##

* Scanning networks on non-primary interfaces is currently not supported with scapy. See [my scapy ticket][4]


[1]: http://www.secdev.org/projects/scapy/
[2]: http://en.wikipedia.org/wiki/Arping
[3]: http://stackoverflow.com/questions/207234/list-of-ip-addresses-hostnames-from-local-network-in-python/
[4]: http://trac.secdev.org/scapy/ticket/537
