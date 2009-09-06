#! /usr/bin/env python
# vim: set fenc=utf8 ts=4 sw=4 et :

import scapy, sys, socket, math
import scapy.utils
import scapy.layers.l2
import scapy.route

def long2net(arg):
    net = 0
    for i in xrange(0, 4):
        if (arg % 256> 0):
            net += int(round(math.log(arg % 256, 2)))
        arg /= 256

    return net


def to_CIDR_notation(bytes_network, bytes_netmask):
    network = scapy.utils.ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = "%s/%s"%(network,netmask)
    return net

def scan_and_print_neighbors(net):
    print "arping", net
    ans,unans = scapy.layers.l2.arping(net, timeout=1, verbose=True)
    for s,r in ans.res:
        hostname = socket.gethostbyaddr(r.psrc)
        print r.sprintf("%Ether.src%  %ARP.psrc%"),
        print " ", hostname[0]

for r in scapy.config.conf.route.routes:
    if r[0] == 0 or r[3]=='lo' or r[4] == '127.0.0.1' or r[4]=='0.0.0.0':
        continue

    scan_and_print_neighbors(to_CIDR_notation(r[0], r[1]))
