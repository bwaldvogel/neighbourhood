import ctypes
import os
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import neighbourhood


@pytest.mark.parametrize(
    ("real_uid", "effective_uid", "expected"),
    [(1000, 0, True), (0, 1000, False), (0, 0, True), (1000, 1000, False)],
)
def test_unix_uses_effective_uid(
    monkeypatch: pytest.MonkeyPatch, real_uid: int, effective_uid: int, expected: bool
) -> None:
    fake_os = SimpleNamespace(
        name="posix",
        getuid=Mock(return_value=real_uid),
        geteuid=Mock(return_value=effective_uid),
    )
    monkeypatch.setattr(neighbourhood, "os", fake_os)
    assert neighbourhood.is_admin() is expected
    fake_os.getuid.assert_not_called()


@pytest.mark.parametrize(("result", "expected"), [(0, False), (1, True)])
def test_windows_admin_check(
    monkeypatch: pytest.MonkeyPatch, result: int, expected: bool
) -> None:
    admin_check = Mock(return_value=result)
    # No Unix UID functions exist on Windows.
    monkeypatch.setattr(neighbourhood, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        neighbourhood,
        "ctypes",
        SimpleNamespace(
            windll=SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=admin_check))
        ),
    )
    assert neighbourhood.is_admin() is expected
    admin_check.assert_called_once_with()


def test_unprivileged_user_exits_before_scanning(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(neighbourhood, "is_admin", lambda: False)
    scan = Mock()
    monkeypatch.setattr(neighbourhood, "scan_and_print_neighbors", scan)
    with pytest.raises(SystemExit) as exc:
        neighbourhood.main()
    assert exc.value.code == 1
    assert "root/administrator" in capsys.readouterr().err
    scan.assert_not_called()


def test_native_admin_check() -> None:
    """Exercise the real OS API as well as the simulated branches above."""
    if os.name == "nt":
        expected = bool(ctypes.windll.shell32.IsUserAnAdmin())
    else:
        expected = os.geteuid() == 0
    assert neighbourhood.is_admin() is expected
