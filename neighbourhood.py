#! /usr/bin/env python
# vim: set fenc=utf8 ts=4 sw=4 et :
#
# Layer 2 network neighbourhood discovery tool
# written by Benedikt Waldvogel (mail at bwaldvogel.de)

import ctypes
import errno
import getopt
import logging
import math
import os
import socket
import sys

import scapy.config
import scapy.data
import scapy.interfaces
import scapy.layers.l2
import scapy.route
import scapy.utils

logging.basicConfig(
    format="%(asctime)s %(levelname)-5s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.DEBUG,
)
logger = logging.getLogger(__name__)


def long2net(arg: int) -> int:
    if arg <= 0 or arg >= 0xFFFFFFFF:
        raise ValueError("illegal netmask value", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def to_CIDR_notation(bytes_network: int, bytes_netmask: int) -> str | None:
    network = scapy.utils.ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = f"{network}/{netmask}"
    if netmask < 16:
        logger.warning("%s is too big. skipping", net)
        return None

    return net


def scan_and_print_neighbors(net: str, interface: str, timeout: float = 5) -> None:
    logger.info("arping %s on %s", net, interface)
    try:
        ans, unans = scapy.layers.l2.arping(
            net, iface=interface, timeout=timeout, verbose=True
        )
        for _s, r in ans.res:
            line = r.sprintf("%Ether.src%  %ARP.psrc%")
            try:
                hostname = socket.gethostbyaddr(r.psrc)
                line += " " + hostname[0]
            except socket.herror:
                # failed to resolve
                pass
            logger.info(line)
    except OSError as e:
        if e.errno == errno.EPERM:  # Operation not permitted
            logger.error("%s. Did you run as root?", e.strerror)
        else:
            raise


def is_admin() -> bool:
    """Check effective root privileges on Unix or administrator privileges on Windows."""
    if os.name == "nt":
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


def supports_arp(interface: str) -> bool:
    # Interface type and flag values are OS-specific; these are Linux checks.
    if sys.platform != "linux":
        return True
    device = scapy.interfaces.dev_from_networkname(interface)
    iff_noarp = 0x80
    return device.type == scapy.data.ARPHRD_ETHER and not (
        int(device.flags) & iff_noarp
    )


def main(interface_to_scan: str | None = None) -> None:
    if not is_admin():
        print("You need to be root/administrator to run this script", file=sys.stderr)
        sys.exit(1)

    route = scapy.config.conf.route
    assert route is not None  # Initialized by importing scapy.route.
    if interface_to_scan is not None:
        try:
            interface_to_scan = scapy.interfaces.resolve_iface(
                interface_to_scan
            ).network_name
        except ValueError:
            print(f"Unknown interface: {interface_to_scan}", file=sys.stderr)
            sys.exit(2)

    scanned: set[tuple[str, str]] = set()
    for network, netmask, gateway, interface, address, _ in route.routes:
        if interface_to_scan and interface_to_scan != interface:
            continue

        # ARP only discovers peers on directly connected networks.
        if gateway != "0.0.0.0":
            continue

        # skip loopback network and default gw
        if (
            network == 0
            or interface == "lo"
            or address == "127.0.0.1"
            or address == "0.0.0.0"
        ):
            continue

        if netmask <= 0 or netmask == 0xFFFFFFFF:
            continue

        # skip docker interface
        if interface != interface_to_scan and (
            interface.startswith("docker")
            or interface.startswith("br-")
            or interface.startswith("tun")
        ):
            logger.warning("Skipping interface '%s'", interface)
            continue

        net = to_CIDR_notation(network, netmask)

        if net and (net, interface) not in scanned:
            scanned.add((net, interface))
            if not supports_arp(interface):
                logger.warning(
                    "Skipping interface '%s': ARP is not supported", interface
                )
                continue
            scan_and_print_neighbors(net, interface)


def usage() -> None:
    print(f"Usage: {sys.argv[0]} [-i <interface>]")


if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:", ["help", "interface="])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(2)

    interface = None

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-i", "--interface"):
            interface = a
        else:
            raise AssertionError("unhandled option")

    main(interface_to_scan=interface)
