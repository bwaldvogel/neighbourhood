from ipaddress import IPv4Address, IPv4Network

import pytest

import neighbourhood


@pytest.mark.parametrize("prefix", range(16, 33))
def test_valid_netmasks(prefix: int) -> None:
    network = IPv4Network(f"192.168.0.0/{prefix}")
    assert neighbourhood.to_CIDR_notation(
        int(network.network_address), int(network.netmask)
    ) == str(network)


@pytest.mark.parametrize("prefix", range(16))
def test_large_networks_are_skipped(prefix: int) -> None:
    network = IPv4Network(f"0.0.0.0/{prefix}")
    assert neighbourhood.to_CIDR_notation(0, int(network.netmask)) is None


@pytest.mark.parametrize(
    "mask", ["255.0.255.0", "255.255.255.1", "0.0.0.255", "0.0.255.255"]
)
def test_invalid_netmasks_and_host_masks_are_skipped(
    mask: str, caplog: pytest.LogCaptureFixture
) -> None:
    assert (
        neighbourhood.to_CIDR_notation(
            int(IPv4Address("192.168.0.0")), int(IPv4Address(mask))
        )
        is None
    )
    assert "Skipping invalid IPv4 route" in caplog.text


@pytest.mark.parametrize(
    ("network", "mask"),
    [(-1, 0xFFFFFF00), (1 << 32, 0xFFFFFF00), (0, -1), (0, 1 << 32)],
)
def test_out_of_range_values_are_skipped(network: int, mask: int) -> None:
    assert neighbourhood.to_CIDR_notation(network, mask) is None


def test_network_with_host_bits_is_skipped() -> None:
    assert (
        neighbourhood.to_CIDR_notation(int(IPv4Address("192.168.1.42")), 0xFFFFFF00)
        is None
    )
