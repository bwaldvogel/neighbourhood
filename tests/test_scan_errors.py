import errno
from ipaddress import IPv4Network
from unittest.mock import Mock, call

import pytest
from scapy.error import Scapy_Exception

import neighbourhood


@pytest.mark.parametrize(
    "outcomes",
    [
        [None, None],
        [PermissionError(errno.EPERM, "Operation not permitted"), None],
        [None, Scapy_Exception("Cannot set filter")],
        [OSError(errno.ENODEV, "No such device"), Scapy_Exception("No packet driver")],
    ],
)
def test_scan_status_and_continuation(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    outcomes: list[Exception | None],
) -> None:
    monkeypatch.setattr(neighbourhood, "is_admin", lambda: True)
    targets = [
        (IPv4Network("192.168.1.0/24"), "eth0"),
        (IPv4Network("192.168.2.0/24"), "eth1"),
    ]
    monkeypatch.setattr(neighbourhood, "iter_scan_targets", lambda *_: iter(targets))
    scanner = Mock(side_effect=outcomes)
    monkeypatch.setattr(neighbourhood, "scan_and_print_neighbors", scanner)
    if any(outcomes):
        with pytest.raises(SystemExit) as exc:
            neighbourhood.cli(["--no-resolve", "--timeout", "1"])
        assert exc.value.code == 1
    else:
        neighbourhood.cli(["--no-resolve", "--timeout", "1"])
    assert scanner.call_args_list == [
        call(str(net), iface, timeout=1, resolve=False) for net, iface in targets
    ]
    for (net, iface), outcome in zip(targets, outcomes, strict=True):
        if outcome is not None:
            assert f"Failed to scan {net} on {iface}: {outcome}" in caplog.text
    assert "Traceback" not in caplog.text


def test_empty_scan_is_successful(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(neighbourhood, "is_admin", lambda: True)
    monkeypatch.setattr(neighbourhood, "iter_scan_targets", lambda *_: iter(()))
    scanner = Mock()
    monkeypatch.setattr(neighbourhood, "scan_and_print_neighbors", scanner)
    neighbourhood.cli([])
    scanner.assert_not_called()


@pytest.mark.parametrize(
    "error",
    [
        PermissionError(errno.EPERM, "Operation not permitted"),
        Scapy_Exception("No driver"),
    ],
)
def test_arp_errors_reach_the_caller(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    monkeypatch.setattr(
        neighbourhood.scapy.layers.l2, "arping", Mock(side_effect=error)
    )
    with pytest.raises(type(error)):
        neighbourhood.scan_and_print_neighbors("192.168.1.0/24", "eth0")


def test_programming_errors_are_not_hidden(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(neighbourhood, "is_admin", lambda: True)
    monkeypatch.setattr(
        neighbourhood,
        "iter_scan_targets",
        lambda *_: iter([(IPv4Network("192.168.1.0/24"), "eth0")]),
    )
    monkeypatch.setattr(
        neighbourhood, "scan_and_print_neighbors", Mock(side_effect=TypeError("bug"))
    )
    with pytest.raises(TypeError, match="bug"):
        neighbourhood.main()
