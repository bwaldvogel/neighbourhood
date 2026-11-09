#! /usr/bin/env python
# vim: set fenc=utf8 ts=4 sw=4 et :
#
# Layer 2 network neighbourhood discovery tool
# written by Benedikt Waldvogel (mail at bwaldvogel.de)

import argparse
import ctypes
import logging
import math
import os
import socket
import sys
from collections.abc import Iterable, Iterator
from ipaddress import IPv4Address, IPv4Network

import scapy.config
import scapy.data
import scapy.error
import scapy.interfaces
import scapy.layers.l2
import scapy.route

logging.basicConfig(
    format="%(asctime)s %(levelname)-5s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.DEBUG,
)
logger = logging.getLogger(__name__)


MIN_SCAN_PREFIX = 16
type Route = tuple[int, int, str, str, str, int]


def parse_scan_network(bytes_network: int, bytes_netmask: int) -> IPv4Network | None:
    try:
        network = IPv4Network((bytes_network, str(IPv4Address(bytes_netmask))))
        # ipaddress also accepts host masks; routing entries must use netmasks.
        if int(network.netmask) != bytes_netmask:
            raise ValueError("expected a netmask, not a host mask")
    except ValueError as exc:
        logger.warning(
            "Skipping invalid IPv4 route (network=%s, netmask=%s): %s",
            bytes_network,
            bytes_netmask,
            exc,
        )
        return None
    if network.prefixlen < MIN_SCAN_PREFIX:
        logger.warning("%s is too big. skipping", network)
        return None

    return network


def scan_and_print_neighbors(
    net: str, interface: str, timeout: float = 5, *, resolve: bool = True
) -> None:
    logger.info("arping %s on %s", net, interface)
    ans, unans = scapy.layers.l2.arping(
        net, iface=interface, timeout=timeout, verbose=True
    )
    for _s, r in ans.res:
        line = r.sprintf("%Ether.src%  %ARP.psrc%")
        if resolve:
            try:
                hostname = socket.gethostbyaddr(r.psrc)
                line += " " + hostname[0]
            except socket.herror:
                # failed to resolve
                pass
        logger.info(line)


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


def main(
    interface_to_scan: str | None = None, *, timeout: float = 5, resolve: bool = True
) -> None:
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

    failed = False
    for net, interface in iter_scan_targets(route.routes, interface_to_scan):
        try:
            scan_and_print_neighbors(
                str(net), interface, timeout=timeout, resolve=resolve
            )
        except (OSError, scapy.error.Scapy_Exception) as exc:
            logger.error("Failed to scan %s on %s: %s", net, interface, exc)
            failed = True
    if failed:
        sys.exit(1)


def iter_scan_targets(
    routes: Iterable[Route], interface_to_scan: str | None = None
) -> Iterator[tuple[IPv4Network, str]]:
    """Select distinct directly connected networks suitable for ARP discovery."""
    scanned: set[tuple[IPv4Network, str]] = set()
    for network, netmask, gateway, interface, address, _ in routes:
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
        if interface != interface_to_scan and interface.startswith(
            ("docker", "br-", "tun")
        ):
            logger.warning("Skipping interface '%s'", interface)
            continue

        net = parse_scan_network(network, netmask)
        if net is None:
            continue

        if IPv4Address(address) not in net:
            logger.warning(
                "Skipping %s on %s: source address %s is outside the subnet",
                net,
                interface,
                address,
            )
            continue

        if (net, interface) not in scanned:
            scanned.add((net, interface))
            if not supports_arp(interface):
                logger.warning(
                    "Skipping interface '%s': ARP is not supported", interface
                )
                continue
            yield net, interface


def positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "timeout must be a positive finite number"
        ) from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be a positive finite number")
    return timeout


def cli(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Discover hosts on directly connected IPv4 networks using ARP.",
        allow_abbrev=False,
    )
    parser.add_argument("-i", "--interface", help="scan only this interface")
    parser.add_argument(
        "--timeout",
        type=positive_timeout,
        default=5.0,
        metavar="SECONDS",
        help="ARP response timeout in seconds (default: %(default)s; excludes DNS lookup time)",
    )
    parser.add_argument(
        "--no-resolve", action="store_true", help="skip reverse-DNS hostname lookups"
    )
    args = parser.parse_args(argv)
    main(args.interface, timeout=args.timeout, resolve=not args.no_resolve)


if __name__ == "__main__":
    cli()
