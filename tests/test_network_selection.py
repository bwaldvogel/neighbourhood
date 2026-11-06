from ipaddress import IPv4Network
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

import neighbourhood

type Route = tuple[int, int, str, str, str, int]


def route(
    cidr: str,
    interface: str = "eth0",
    address: str = "192.168.1.10",
    gateway: str = "0.0.0.0",
    metric: int = 0,
) -> Route:
    network = IPv4Network(cidr)
    return (
        int(network.network_address),
        int(network.netmask),
        gateway,
        interface,
        address,
        metric,
    )


@pytest.fixture
def scan(monkeypatch: pytest.MonkeyPatch) -> Mock:
    monkeypatch.setattr(neighbourhood, "is_admin", lambda: True)
    monkeypatch.setattr(
        neighbourhood.scapy.config.conf.ifaces,
        "dev_from_networkname",
        Mock(return_value=SimpleNamespace(type=1, flags=0)),
    )
    scanner = Mock()
    monkeypatch.setattr(neighbourhood, "scan_and_print_neighbors", scanner)
    return scanner


def set_routes(monkeypatch: pytest.MonkeyPatch, routes: list[Route]) -> None:
    monkeypatch.setattr(
        neighbourhood.scapy.config.conf, "route", SimpleNamespace(routes=routes)
    )


def test_only_directly_connected_networks(
    monkeypatch: pytest.MonkeyPatch, scan: Mock
) -> None:
    set_routes(
        monkeypatch,
        [
            route("0.0.0.0/0", gateway="192.168.1.1"),
            route("10.0.0.0/24", gateway="192.168.1.1"),
            route("192.168.1.0/24"),
        ],
    )
    neighbourhood.main()
    scan.assert_called_once_with("192.168.1.0/24", "eth0", timeout=5, resolve=True)


def test_scan_options_reach_selected_network(
    monkeypatch: pytest.MonkeyPatch, scan: Mock
) -> None:
    set_routes(monkeypatch, [route("192.168.1.0/24")])
    neighbourhood.main(timeout=0.25, resolve=False)
    scan.assert_called_once_with("192.168.1.0/24", "eth0", timeout=0.25, resolve=False)


def test_duplicate_network_is_scanned_once_per_interface(
    monkeypatch: pytest.MonkeyPatch, scan: Mock
) -> None:
    set_routes(
        monkeypatch,
        [
            route("192.168.1.0/24"),
            route("192.168.1.0/24", address="192.168.1.11", metric=100),
            route("192.168.1.0/24", interface="eth1"),
            route("192.168.2.0/24", address="192.168.2.10"),
        ],
    )
    neighbourhood.main()
    assert scan.call_args_list == [
        call("192.168.1.0/24", "eth0", timeout=5, resolve=True),
        call("192.168.1.0/24", "eth1", timeout=5, resolve=True),
        call("192.168.2.0/24", "eth0", timeout=5, resolve=True),
    ]


def test_unrelated_link_local_route_is_skipped(
    monkeypatch: pytest.MonkeyPatch, scan: Mock, caplog: pytest.LogCaptureFixture
) -> None:
    set_routes(
        monkeypatch,
        [
            route("169.254.0.0/16", interface="wlan0"),
            route("192.168.1.0/24", interface="wlan0"),
        ],
    )
    neighbourhood.main()
    scan.assert_called_once_with("192.168.1.0/24", "wlan0", timeout=5, resolve=True)
    assert "source address 192.168.1.10 is outside the subnet" in caplog.text


@pytest.mark.parametrize(
    ("cidr", "address"),
    [
        ("169.254.0.0/16", "169.254.42.7"),
        ("10.42.0.0/16", "10.42.5.8"),
        ("192.168.0.0/23", "192.168.1.10"),
        ("192.168.1.128/25", "192.168.1.200"),
    ],
)
def test_valid_source_addresses_preserve_original_prefix(
    monkeypatch: pytest.MonkeyPatch, scan: Mock, cidr: str, address: str
) -> None:
    set_routes(monkeypatch, [route(cidr, address=address)])
    neighbourhood.main()
    scan.assert_called_once_with(cidr, "eth0", timeout=5, resolve=True)


def test_mismatched_source_does_not_hide_valid_route_to_same_network(
    monkeypatch: pytest.MonkeyPatch, scan: Mock
) -> None:
    set_routes(
        monkeypatch,
        [
            route("192.168.1.128/25", address="192.168.1.10"),
            route("192.168.1.128/25", address="192.168.1.200"),
        ],
    )
    neighbourhood.main()
    scan.assert_called_once_with("192.168.1.128/25", "eth0", timeout=5, resolve=True)


@pytest.mark.parametrize(
    "entry",
    [
        route("0.0.0.0/0"),
        route("127.0.0.0/8", interface="lo", address="127.0.0.1"),
        route("192.168.1.0/24", address="0.0.0.0"),
        route("192.168.1.10/32"),
        route("10.0.0.0/8", address="10.0.0.1"),
        route("172.17.0.0/16", interface="docker0"),
        route("172.18.0.0/16", interface="br-test"),
        route("10.1.0.0/24", interface="tun0"),
    ],
)
def test_excluded_routes_are_not_scanned(
    monkeypatch: pytest.MonkeyPatch, scan: Mock, entry: Route
) -> None:
    set_routes(monkeypatch, [entry])
    neighbourhood.main()
    scan.assert_not_called()


@pytest.mark.parametrize(("device_type", "flags"), [(65534, 0x91), (1, 0x80)])
@pytest.mark.parametrize("explicit", [False, True])
def test_linux_interfaces_without_arp_are_skipped(
    monkeypatch: pytest.MonkeyPatch,
    scan: Mock,
    device_type: int,
    flags: int,
    explicit: bool,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(neighbourhood, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(
        neighbourhood.scapy.config.conf.ifaces,
        "dev_from_networkname",
        lambda name: SimpleNamespace(
            type=device_type if name == "wt0" else 1,
            flags=flags if name == "wt0" else 0,
        ),
    )
    monkeypatch.setattr(
        neighbourhood.scapy.interfaces,
        "resolve_iface",
        Mock(return_value=SimpleNamespace(network_name="wt0")),
    )
    set_routes(
        monkeypatch,
        [
            route("100.118.0.0/16", interface="wt0", address="100.118.0.1"),
            route("192.168.1.0/24"),
        ],
    )
    neighbourhood.main("wt0" if explicit else None)
    if explicit:
        scan.assert_not_called()
    else:
        scan.assert_called_once_with("192.168.1.0/24", "eth0", timeout=5, resolve=True)
    assert "ARP is not supported" in caplog.text


def test_linux_interface_flags_are_not_applied_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(neighbourhood, "sys", SimpleNamespace(platform="win32"))
    lookup = Mock(side_effect=AssertionError("Linux flags must not be read"))
    monkeypatch.setattr(
        neighbourhood.scapy.config.conf.ifaces, "dev_from_networkname", lookup
    )
    assert neighbourhood.supports_arp("Ethernet")
    lookup.assert_not_called()


def test_explicit_interface_resolves_name_and_allows_virtual_interface(
    monkeypatch: pytest.MonkeyPatch, scan: Mock
) -> None:
    resolver = Mock(return_value=SimpleNamespace(network_name="docker0"))
    monkeypatch.setattr(neighbourhood.scapy.interfaces, "resolve_iface", resolver)
    set_routes(
        monkeypatch,
        [
            route("192.168.1.0/24"),
            route("172.17.0.0/16", interface="docker0", address="172.17.0.1"),
            route("10.0.0.0/24", interface="docker0", gateway="172.17.0.2"),
        ],
    )
    neighbourhood.main("friendly name")
    resolver.assert_called_once_with("friendly name")
    scan.assert_called_once_with("172.17.0.0/16", "docker0", timeout=5, resolve=True)


def test_unknown_interface_fails_before_scanning(
    monkeypatch: pytest.MonkeyPatch, scan: Mock, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        neighbourhood.scapy.interfaces, "resolve_iface", Mock(side_effect=ValueError)
    )
    set_routes(monkeypatch, [route("192.168.1.0/24")])
    with pytest.raises(SystemExit) as exc:
        neighbourhood.main("missing0")
    assert exc.value.code == 2
    assert "Unknown interface: missing0" in capsys.readouterr().err
    scan.assert_not_called()


def test_existing_interface_without_ipv4_routes_is_not_unknown(
    monkeypatch: pytest.MonkeyPatch, scan: Mock
) -> None:
    monkeypatch.setattr(
        neighbourhood.scapy.interfaces,
        "resolve_iface",
        Mock(return_value=SimpleNamespace(network_name="eth2")),
    )
    set_routes(monkeypatch, [route("192.168.1.0/24")])
    neighbourhood.main("eth2")
    scan.assert_not_called()
