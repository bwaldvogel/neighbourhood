## Layer 2 Network Neighbourhood Discovery Tool ##

[![Checks](https://github.com/bwaldvogel/neighbourhood/actions/workflows/checks.yml/badge.svg)](https://github.com/bwaldvogel/neighbourhood/actions/workflows/checks.yml)
[![PyPI](https://img.shields.io/pypi/v/neighbourhood)](https://pypi.org/project/neighbourhood/)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](#dependencies)
[![License: GPL v2](https://img.shields.io/badge/license-GPL_v2-blue)](LICENSE)

Easily detect hosts on your local network by sending ARP pings.
For additional information, see [this Stack Overflow question][3].

## Dependencies ##

* Python 3.12+ (development uses Python 3.14)
* [scapy][1] for networking functions like [arping][2] (installed automatically by uvx or pip)

## Installation and Usage ##

Run directly from PyPI with [uv][4]:

```sh
sudo uvx --from neighbourhood neighbourhood
```

Alternatively, install into a virtual environment with pip:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install neighbourhood
sudo .venv/bin/neighbourhood
```

Pass `--interface`, `--timeout`, or `--no-resolve` as needed. See
`uvx neighbourhood --help` for all options. On Windows, install Npcap, then run
`uvx neighbourhood` from an Administrator terminal (see below).

Only directly connected IPv4 networks are scanned; routes through gateways are
skipped. Each network is scanned once per interface. By default, Docker, bridge
(`br-`), and tunnel (`tun`) interfaces are skipped; select one explicitly with
`-i` to include it. Unknown interfaces produce an error with exit code 2.
On Linux, interfaces without Ethernet framing or with the `NOARP` flag are
skipped even when explicitly selected, since they cannot perform this ARP scan.
Routes whose source IPv4 address is outside the destination subnet are skipped
with a warning. For example, a `169.254.0.0/16` route with source address
`192.168.1.10` is not scanned. Valid link-local networks are still scanned when
the source address belongs to them; subnet sizes are taken from the routing table.

Use `--timeout SECONDS` to set the ARP response timeout (default: 5 seconds) and
`--no-resolve` to skip reverse-DNS hostname lookups:

```sh
sudo uvx neighbourhood -i eth0 --timeout 2 --no-resolve
```

The timeout applies to ARP responses, not DNS lookups or the total runtime.
Run `uvx neighbourhood --help` to see all options without root privileges.

Failed scans are reported while remaining targets are still attempted; the program
exits with status 1 if any scan fails.

### Windows ###

Install [Npcap](https://npcap.com/#download) for Scapy's packet capture and
transmission support. From a PowerShell window opened as Administrator, run:

```powershell
uvx neighbourhood
```

The permission check supports Windows, but a complete ARP scan on Windows has
not yet been verified on a real network.

## Development ##

Install development dependencies with `uv sync --locked`, then run:

```sh
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked ty check --error-on-warning
uv run --locked python -m pytest
uv run --locked python neighbourhood.py --help
```

GitHub Actions runs these checks on Linux and Windows with Python 3.12, 3.13,
and 3.14 for pushes and pull requests. pytest covers both permission-check branches
with simulated identities, verifies rejection before scanning, and calls the real
permission API of the runner's OS. Routing tests use simulated tables to check
network selection, duplicate targets, and interface validation. The smoke test
only displays help.

CI does not perform ARP scans or validate Npcap installation. A complete Windows
scan needs a separate integration test on a machine with Npcap and a known peer
on the same local network.

## TODO ##

* IPv6 support


[1]: https://scapy.net/
[2]: http://en.wikipedia.org/wiki/Arping
[3]: http://stackoverflow.com/questions/207234/list-of-ip-addresses-hostnames-from-local-network-in-python/
[4]: https://github.com/astral-sh/uv
