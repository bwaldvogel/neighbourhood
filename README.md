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

## Development ##

Install development dependencies with `uv sync --locked`, then run:

```sh
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked ty check --error-on-warning
uv run --locked python neighbourhood.py --help
```

GitHub Actions runs these checks on Python 3.12, 3.13, and 3.14 for pushes
and pull requests. The smoke test only displays help; it does not scan the network
or require root privileges.

## TODO ##

* IPv6 support


[1]: https://scapy.net/
[2]: http://en.wikipedia.org/wiki/Arping
[3]: http://stackoverflow.com/questions/207234/list-of-ip-addresses-hostnames-from-local-network-in-python/
[4]: https://github.com/astral-sh/uv
