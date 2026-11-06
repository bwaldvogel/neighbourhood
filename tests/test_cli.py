import logging
import socket
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import neighbourhood


@pytest.mark.parametrize(
    ("argv", "interface", "timeout", "resolve"),
    [
        ([], None, 5.0, True),
        (["-i", "eth0"], "eth0", 5.0, True),
        (["--interface=Ethernet"], "Ethernet", 5.0, True),
        (["--timeout", "0.25", "--no-resolve"], None, 0.25, False),
    ],
)
def test_cli_passes_options(
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
    interface: str | None,
    timeout: float,
    resolve: bool,
) -> None:
    main = Mock()
    monkeypatch.setattr(neighbourhood, "main", main)
    neighbourhood.cli(argv)
    main.assert_called_once_with(interface, timeout=timeout, resolve=resolve)


@pytest.mark.parametrize(
    "argv",
    [
        ["--timeout", value]
        for value in ("0", "-1", "nan", "inf", "-inf", "1e999", "invalid")
    ]
    + [["--timeout"], ["-i"], ["--unknown"], ["unexpected-positional"]],
)
def test_invalid_arguments_fail_before_main(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    main = Mock()
    monkeypatch.setattr(neighbourhood, "main", main)
    with pytest.raises(SystemExit) as exc:
        neighbourhood.cli(argv)
    assert exc.value.code == 2
    assert "error:" in capsys.readouterr().err
    main.assert_not_called()


def test_help_does_not_require_privileges(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    admin = Mock(side_effect=AssertionError("Must not check privileges for help"))
    monkeypatch.setattr(neighbourhood, "is_admin", admin)
    with pytest.raises(SystemExit) as exc:
        neighbourhood.cli(["--help"])
    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "--timeout" in output
    assert "--no-resolve" in output
    admin.assert_not_called()


@pytest.mark.parametrize("resolve", [True, False])
@pytest.mark.parametrize("dns_failure", [False, True])
def test_scan_timeout_and_dns_resolution(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    resolve: bool,
    dns_failure: bool,
) -> None:
    reply = Mock(psrc="192.168.1.2")
    reply.sprintf.return_value = "aa:bb:cc:dd:ee:ff  192.168.1.2"
    arping = Mock(return_value=(SimpleNamespace(res=[(None, reply)]), []))
    monkeypatch.setattr(neighbourhood.scapy.layers.l2, "arping", arping)
    lookup = Mock(return_value=("peer.local", [], ["192.168.1.2"]))
    if dns_failure:
        lookup.side_effect = socket.herror("No hostname")
    monkeypatch.setattr(neighbourhood.socket, "gethostbyaddr", lookup)
    caplog.set_level(logging.INFO, logger="neighbourhood")
    neighbourhood.scan_and_print_neighbors(
        "192.168.1.0/24", "eth0", timeout=0.25, resolve=resolve
    )
    arping.assert_called_once_with(
        "192.168.1.0/24", iface="eth0", timeout=0.25, verbose=True
    )
    assert "aa:bb:cc:dd:ee:ff  192.168.1.2" in caplog.text
    assert ("peer.local" in caplog.text) is (resolve and not dns_failure)
    if resolve:
        lookup.assert_called_once_with("192.168.1.2")
    else:
        lookup.assert_not_called()
