#! /usr/bin/env python
# vim: set fenc=utf8 ts=4 sw=4 et :
#
# Layer 2 network neighbourhood discovery tool
# written by Benedikt Waldvogel (mail at bwaldvogel.de)

import scapy, sys, socket, math
import scapy.utils
import scapy.layers.l2
import scapy.route

def long2net(arg):
    if (arg <= 0 or arg >= 0xFFFFFFFF):
        raise ValueError("illegal netmask value", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))

def to_CIDR_notation(bytes_network, bytes_netmask):
    network = scapy.utils.ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = "%s/%s" % (network,netmask)
    if netmask < 22:
        print net, "is too big. skipping"
        return None

    return net

def scan_and_print_neighbors(net, interface):
    print "arping", net, "on", interface
    ans,unans = scapy.layers.l2.arping(net, iface=interface, timeout=1, verbose=True)
    for s,r in ans.res:
        hostname = socket.gethostbyaddr(r.psrc)
        print r.sprintf("%Ether.src%  %ARP.psrc%"),
        print " ", hostname[0]

for route in scapy.config.conf.route.routes:

    network = route[0]
    netmask = route[1]
    interface = route[3]

    # skip loopback network and default gw
    if network == 0 or interface=='lo' or route[4] == '127.0.0.1' or route[4]=='0.0.0.0':
        continue

    if netmask <= 0 or netmask == 0xFFFFFFFF:
        continue

    net = to_CIDR_notation(network, netmask)
    if net:
        scan_and_print_neighbors(net, interface)
