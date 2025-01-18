#!/usr/bin/env python3
from scapy.all import IP, IPv6, ICMP, ICMPv6EchoRequest, ICMPv6TimeExceeded, ICMPv6EchoReply, TCP, UDP, Raw, sr1
import argparse
import socket
import time
import re
from abc import ABC, abstractmethod
from typing import Tuple, Optional, List
from formatters import TraceHop, StandardFormatter, RichFormatter

class TracerouteProbe(ABC):
    def __init__(self, packet_size: int = 40, ipv6: bool = False):
        self.packet_size = max(40, packet_size)
        self.ipv6 = ipv6

    @abstractmethod
    def create_probe(self, dst: str, ttl: int, seq: int) -> IP:
        pass

class ICMPProbe(TracerouteProbe):
    def create_probe(self, dst: str, ttl: int, seq: int) -> IP:
        payload = "X" * (self.packet_size - (48 if self.ipv6 else 28))
        if self.ipv6:
            return IPv6(dst=dst, hlim=ttl) / ICMPv6EchoRequest(seq=seq) / Raw(load=payload)
        return IP(dst=dst, ttl=ttl) / ICMP(seq=seq) / Raw(load=payload)

class TCPProbe(TracerouteProbe):
    def __init__(self, port: int = 80, packet_size: int = 40, ipv6: bool = False):
        super().__init__(packet_size, ipv6)
        self.port = port

    def create_probe(self, dst: str, ttl: int, seq: int) -> IP:
        payload = "X" * (self.packet_size - (60 if self.ipv6 else 40))
        if self.ipv6:
            return IPv6(dst=dst, hlim=ttl) / TCP(dport=self.port, seq=seq, flags='S') / Raw(load=payload)
        return IP(dst=dst, ttl=ttl) / TCP(dport=self.port, seq=seq, flags='S') / Raw(load=payload)

class UDPProbe(TracerouteProbe):
    def __init__(self, port: int = 33434, packet_size: int = 40, ipv6: bool = False):
        super().__init__(packet_size, ipv6)
        self.port = port

    def create_probe(self, dst: str, ttl: int, seq: int) -> IP:
        payload = "X" * (self.packet_size - (48 if self.ipv6 else 28))
        if self.ipv6:
            return IPv6(dst=dst, hlim=ttl) / UDP(dport=self.port, sport=seq) / Raw(load=payload)
        return IP(dst=dst, ttl=ttl) / UDP(dport=self.port, sport=seq) / Raw(load=payload)

class TraceResult:
    def __init__(self, hop: int, ip: str, rtts: List[float], as_number: str = None, hostname: str = None):
        self.hop = hop
        self.ip = ip
        self.rtts = rtts
        self.as_number = as_number
        self.hostname = hostname

    def __str__(self):
        if self.ip == '*':
            return f"{self.hop:2d}  {'*':15s}  {'*':7s}  {'*':7s}  {'*':7s}"
        
        rtt_values = []
        for rtt in self.rtts:
            if rtt is None:
                rtt_values.append("*".center(7))
            else:
                rtt_values.append(f"{rtt:6.2f}".ljust(7))
        
        base = f"{self.hop:2d}  "
        
        if self.hostname and len(self.hostname) <= 40:
            base += f"{self.hostname:40s}  "
        else:
            ip_field = self.ip
            if ':' in self.ip:
                ip_field = socket.inet_ntop(socket.AF_INET6, 
                                          socket.inet_pton(socket.AF_INET6, self.ip))
            base += f"{ip_field:40s}  "
        
        base += "  ".join(rtt_values)
        
        if self.as_number and self.as_number != "NA":
            base += f"  [AS{self.as_number}]"
            
        return base

class Traceroute:
    def __init__(self, target: str, probe: TracerouteProbe, 
                 timeout: float = 2, max_hops: int = 30, 
                 queries: int = 3, probe_interval: float = 0.0,
                 resolve_dns: bool = False, verbose: bool = False,
                 use_rich: bool = True):
        self.target = target
        self.probe = probe
        self.timeout = timeout
        self.max_hops = max_hops
        self.queries = queries
        self.probe_interval = probe_interval
        self.resolve_dns = resolve_dns
        self.verbose = verbose
        self.formatter = RichFormatter() if use_rich and RichFormatter else StandardFormatter()

        try:
            if ':' in target:
                self.target_ip = socket.getaddrinfo(target, None, socket.AF_INET6)[0][4][0]
                self.ip_version = 6
            else:
                self.target_ip = socket.getaddrinfo(target, None, socket.AF_INET)[0][4][0]
                self.ip_version = 4
        except socket.gaierror:
            self.target_ip = target
            self.ip_version = 6 if ':' in target else 4

    def resolve_hostname(self, ip: str) -> Optional[str]:
        if not self.resolve_dns:
            return None
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None

    def get_as_number(self, ip: str) -> str:
        whois_servers = {
            'whois.arin.net': 'n + {}\n',
            'whois.ripe.net': '-T + {}\n',
            'whois.apnic.net': '-V Md5.5.7 {}\n',
            'whois.lacnic.net': '{}\n',
            'whois.afrinic.net': '{}\n'
        }
        
        for server, query_format in whois_servers.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(5)
                    s.connect((server, 43))
                    s.send(query_format.format(ip).encode())
                    
                    response = ""
                    while True:
                        data = s.recv(4096)
                        if not data:
                            break
                        response += data.decode(errors='ignore')
                    
                    as_match = re.search(r'AS(\d+)', response)
                    if as_match:
                        return as_match.group(1)
            except:
                continue
        return "NA"

    def send_probe(self, ttl: int, seq: int) -> Tuple[str, Optional[float]]:
        pkt = self.probe.create_probe(self.target, ttl, seq)
        
        try:
            start_time = time.time()
            reply = sr1(pkt, timeout=self.timeout, verbose=0)
            rtt = (time.time() - start_time) * 1000 if reply else None

            if reply is None:
                return '*', None

            if self.ip_version == 6:
                if reply.haslayer(ICMPv6TimeExceeded) or reply.haslayer(ICMPv6EchoReply):
                    return reply.src, rtt
            else:
                if reply.haslayer(ICMP) and (reply.type == 11 or reply.type == 0):
                    return reply.src, rtt
                elif reply.haslayer(TCP) and (reply[TCP].flags & 0x12):
                    return reply.src, rtt
            
            return reply.src, rtt
        except Exception as e:
            return '*', None

    def probe_hop(self, ttl: int) -> TraceHop:
        rtts = []
        ip = '*'

        for seq in range(self.queries):
            if seq > 0 and self.probe_interval > 0:
                time.sleep(self.probe_interval)
            
            curr_ip, rtt = self.send_probe(ttl, seq)
            if curr_ip != '*':
                ip = curr_ip
            rtts.append(rtt)

        hostname = self.resolve_hostname(ip) if ip != '*' else None
        as_number = self.get_as_number(ip) if ip != '*' and self.verbose else None
        
        return TraceHop(ttl, ip, rtts, as_number, hostname)

    def trace(self):
        proto_name = type(self.probe).__name__.replace('Probe', '').upper()
        port = getattr(self.probe, 'port', None)
        
        self.formatter.print_header(
            self.target, self.target_ip, proto_name, port,
            self.max_hops, self.probe.packet_size, self.queries,
            self.timeout, self.probe_interval,
            self.resolve_dns, self.verbose
        )
        
        prev_result = None
        reached_target = False
        
        for ttl in range(1, self.max_hops + 1):
            result = self.probe_hop(ttl)
            self.formatter.print_hop(result)
            
            if result.ip == self.target_ip:
                reached_target = True
                break
                
            if ttl > 1 and result.ip != '*' and result.ip == prev_result.ip:
                print("\nRoute appears to be looping, stopping trace.")
                break
                
            prev_result = result
        
        self.formatter.print_footer(reached_target, self.max_hops)

def main():
    parser = argparse.ArgumentParser(description='Advanced Traceroute implementation')
    parser.add_argument('target', help='Target IP/hostname')
    parser.add_argument('-p', '--protocol', choices=['tcp', 'udp', 'icmp'], default='icmp',
                        help='Protocol to use (default: icmp)')
    parser.add_argument('-P', '--port', type=int, help='Port number for TCP/UDP')
    parser.add_argument('-t', '--timeout', type=float, default=2, help='Timeout in seconds')
    parser.add_argument('-m', '--max-hops', type=int, default=30, help='Maximum number of hops')
    parser.add_argument('-q', '--queries', type=int, default=3, help='Number of queries per hop')
    parser.add_argument('-i', '--interval', type=float, default=0, help='Interval between queries')
    parser.add_argument('-s', '--packet-size', type=int, default=40, help='Packet size in bytes')
    parser.add_argument('-n', '--no-dns', action='store_true', help='Do not resolve IP addresses')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show AS numbers')
    parser.add_argument('-6', '--ipv6', action='store_true', help='Use IPv6')
    parser.add_argument('--no-rich', action='store_true', help='Disable rich output')
    
    args = parser.parse_args()
    
    if args.ipv6:
        if args.protocol == 'udp':
            default_port = 33434
        else:
            default_port = 80
    else:
        if args.protocol == 'udp':
            default_port = 33434
        else:
            default_port = 80

    if args.protocol == 'tcp':
        probe = TCPProbe(args.port or default_port, args.packet_size, args.ipv6)
    elif args.protocol == 'udp':
        probe = UDPProbe(args.port or default_port, args.packet_size, args.ipv6)
    else:
        probe = ICMPProbe(args.packet_size, args.ipv6)
    
    tracer = Traceroute(
        args.target,
        probe,
        timeout=args.timeout,
        max_hops=args.max_hops,
        queries=args.queries,
        probe_interval=args.interval,
        resolve_dns=not args.no_dns,
        verbose=args.verbose,
        use_rich=not args.no_rich
    )
    
    tracer.trace()

if __name__ == '__main__':
    main()
