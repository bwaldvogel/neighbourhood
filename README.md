## Layer 2 Network Neighbourhood Discovery Tool ##

Easily detect hosts on your local network by sending ARP pings.
For additional information, see [this Stack Overflow question][3].

## Dependencies ##

* Python 3.12+ (development uses Python 3.14)
* [scapy][1] for networking functions like [arping][2]

## Installation and Usage ##

When [scapy][1] is installed as system library, simply run:

```
$ sudo ./neighbourhood.py [-i <interface>]
```

Alternatively, you can use [uv][4]:

```
$ uv sync
$ sudo .venv/bin/python neighbourhood.py [-i <interface>]
```

### Windows ###

Install [Npcap](https://npcap.com/#download) for Scapy's packet capture and
transmission support. In PowerShell, install dependencies with `uv sync`, then
run the script from a PowerShell window opened as Administrator:

```powershell
uv run neighbourhood.py [-i <interface>]
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
permission API of the runner's OS. The smoke test only displays help.

CI does not perform ARP scans or validate Npcap installation. A complete Windows
scan needs a separate integration test on a machine with Npcap and a known peer
on the same local network.

## TODO ##

* IPv6 support


[1]: https://scapy.net/
[2]: http://en.wikipedia.org/wiki/Arping
[3]: http://stackoverflow.com/questions/207234/list-of-ip-addresses-hostnames-from-local-network-in-python/
[4]: https://github.com/astral-sh/uv
