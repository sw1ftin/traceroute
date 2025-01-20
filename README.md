
# Traceroute

## Installation

To install the required dependencies, run:

```sh
pip install -r requirements.txt
```

## Usage

To run the traceroute, use the following command:

```sh
python traceroute.py <target> [options]
```

### Options

- `-p, --protocol`: Protocol to use (default: icmp). Choices: `tcp`, `udp`, `icmp`.
- `-P, --port`: Port number for TCP/UDP.
- `-t, --timeout`: Timeout in seconds (default: 2).
- `-m, --max-hops`: Maximum number of hops (default: 30).
- `-q, --queries`: Number of queries per hop (default: 3).
- `-i, --interval`: Interval between queries (default: 0).
- `-s, --packet-size`: Packet size in bytes (default: 40).
- `-n, --no-dns`: Do not resolve IP addresses.
- `-v, --verbose`: Show AS numbers.
- `-6, --ipv6`: Use IPv6.
- `--no-rich`: Disable rich output.

## Example

To run a traceroute to `example.com` using ICMP protocol:

```sh
python traceroute.py example.com
```

To run a traceroute to `example.com` using TCP protocol on port 80:

```sh
python traceroute.py example.com -p tcp -P 80
```

To run a traceroute to `example.com` using UDP protocol on port 33434:

```sh
python traceroute.py example.com -p udp -P 33434
```

## Testing

To run the tests, use the following command:

```sh
pytest
```