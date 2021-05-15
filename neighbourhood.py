#! /usr/bin/env python
# vim: set fenc=utf8 ts=4 sw=4 et :
#
# Layer 2 network neighbourhood discovery tool
# written by Benedikt Waldvogel (mail at bwaldvogel.de)

from __future__ import absolute_import, division, print_function
import logging
import scapy.config
import scapy.layers.l2
import scapy.route
import socket
import math
import errno
import os
import getopt
import sys

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logger = logging.getLogger(__name__)


def long2net(arg):
    if (arg <= 0 or arg >= 0xFFFFFFFF):
        raise ValueError("illegal netmask value", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def to_CIDR_notation(bytes_network, bytes_netmask):
    network = scapy.utils.ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = "%s/%s" % (network, netmask)
    if netmask < 16:
        logger.warning("%s is too big. skipping" % net)
        return None

    return net


def scan_and_print_neighbors(net, interface, timeout=5):
    logger.info("arping %s on %s" % (net, interface))
    try:
        ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=timeout, verbose=True)
        for s, r in ans.res:
            line = r.sprintf("%Ether.src%  %ARP.psrc%")
            try:
                hostname = socket.gethostbyaddr(r.psrc)
                line += " " + hostname[0]
            except socket.herror:
                # failed to resolve
                pass
            logger.info(line)
    except socket.error as e:
        if e.errno == errno.EPERM:     # Operation not permitted
            logger.error("%s. Did you run as root?", e.strerror)
        else:
            raise


def main(interface_to_scan=None):
    if os.geteuid() != 0:
        print('You need to be root to run this script', file=sys.stderr)
        sys.exit(1)

    for network, netmask, _, interface, address, _ in scapy.config.conf.route.routes:

        if interface_to_scan and interface_to_scan != interface:
            continue

        # skip loopback network and default gw
        if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
            continue

        if netmask <= 0 or netmask == 0xFFFFFFFF:
            continue

        # skip docker interface
        if interface != interface_to_scan \
                and (interface.startswith('docker')
                     or interface.startswith('br-')
                     or interface.startswith('tun')):
            logger.warning("Skipping interface '%s'" % interface)
            continue

        net = to_CIDR_notation(network, netmask)

        if net:
            scan_and_print_neighbors(net, interface)


def usage():
    print("Usage: %s [-i <interface>]" % sys.argv[0])


if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hi:', ['help', 'interface='])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(2)

    interface = None

    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
            sys.exit()
        elif o in ('-i', '--interface'):
            interface = a
        else:
            assert False, 'unhandled option'

    main(interface_to_scan=interface)
