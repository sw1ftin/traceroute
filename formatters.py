from abc import ABC, abstractmethod
from typing import List, Optional
from dataclasses import dataclass

@dataclass
class TraceHop:
    hop: int
    ip: str
    rtts: List[float]
    as_number: Optional[str] = None
    hostname: Optional[str] = None

class OutputFormatter(ABC):
    @abstractmethod
    def print_header(self, target: str, ip: str, proto: str, port: Optional[int],
                    max_hops: int, packet_size: int, queries: int,
                    timeout: float, interval: float, dns: bool, asn: bool) -> None:
        pass

    @abstractmethod
    def print_hop(self, hop: TraceHop) -> None:
        pass

    @abstractmethod
    def print_footer(self, reached: bool, max_hops: int) -> None:
        pass

class StandardFormatter(OutputFormatter):
    def print_header(self, target: str, ip: str, proto: str, port: Optional[int],
                    max_hops: int, packet_size: int, queries: int,
                    timeout: float, interval: float, dns: bool, asn: bool) -> None:
        port_info = f" (port {port})" if port else ""
        print(f"traceroute to {target} ({ip})")
        print(f"using {proto}{port_info}, {max_hops} hops max")
        print(f"{queries} probes per hop, {packet_size} byte packets")
        print(f"timeout: {timeout:.1f}s, interval: {interval:.1f}s")
        if dns:
            print("DNS resolution enabled")
        if asn:
            print("AS number lookup enabled")
        print()
        headers = ["HOP", "HOST/IP"] + [f"RTT{i+1}" for i in range(queries)]
        print(f"{headers[0]:2s}  {headers[1]:40s}  " + "  ".join(f"{h:7s}" for h in headers[2:]))
        print("-" * 70)

    def print_hop(self, hop: TraceHop) -> None:
        if hop.ip == '*':
            asterisks = "  ".join("*" for _ in range(len(hop.rtts) + 1))
            print(f"{hop.hop:2d}  {asterisks}")
            return

        rtt_values = [f"{rtt:6.2f}".ljust(7) if rtt else "*" for rtt in hop.rtts]
        base = f"{hop.hop:2d}  "
        
        if hop.hostname:
            base += f"{hop.hostname[:40]:40s}  "
        else:
            base += f"{hop.ip:40s}  "
        
        base += "  ".join(rtt_values)
        
        if hop.as_number and hop.as_number != "NA":
            base += f"  [AS{hop.as_number}]"
        
        print(base)

    def print_footer(self, reached: bool, max_hops: int) -> None:
        if not reached:
            print(f"\nReached maximum hop count ({max_hops}) without reaching target.")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text

    class RichFormatter(OutputFormatter):
        def __init__(self):
            self.console = Console()

        def print_header(self, target: str, ip: str, proto: str, port: Optional[int],
                        max_hops: int, packet_size: int, queries: int,
                        timeout: float, interval: float, dns: bool, asn: bool) -> None:
            self.console.print(f"[bold cyan]Traceroute[/] to {target} ({ip})")
            
            info = Table.grid(padding=(0, 2))
            info.add_row("Protocol:", f"{proto}" + (f" (port {port})" if port else ""))
            info.add_row("Max hops:", str(max_hops))
            info.add_row("Packet size:", f"{packet_size} bytes")
            info.add_row("Queries:", str(queries))
            info.add_row("Timeout:", f"{timeout:.1f}s")
            info.add_row("Interval:", f"{interval:.1f}s")
            info.add_row("DNS lookup:", "✓" if dns else "✗")
            info.add_row("AS lookup:", "✓" if asn else "✗")
            
            self.console.print(info)
            print()

            table = Table(show_header=True, header_style="bold")
            table.add_column("HOP", justify="right", style="dim")
            table.add_column("HOST/IP", style="cyan")
            for i in range(queries):
                table.add_column(f"RTT{i+1}", justify="right", style="green")
            table.add_column("AS", style="yellow")
            self.current_table = table

        def print_hop(self, hop: TraceHop) -> None:
            if not hasattr(self, 'current_table'):
                return

            if hop.ip == '*':
                self.current_table.add_row(
                    str(hop.hop), "*", *["*" for _ in hop.rtts], ""
                )
                return

            rtt_values = [f"{rtt:.2f}" if rtt else "*" for rtt in hop.rtts]
            as_info = f"AS{hop.as_number}" if hop.as_number and hop.as_number != "NA" else ""
            
            self.current_table.add_row(
                str(hop.hop),
                hop.hostname or hop.ip,
                *rtt_values,
                as_info
            )

        def print_footer(self, reached: bool, max_hops: int) -> None:
            if hasattr(self, 'current_table'):
                self.console.print(self.current_table)
            
            if not reached:
                self.console.print(f"\n[yellow]Reached maximum hop count ({max_hops}) without reaching target.[/]")

except ImportError:
    RichFormatter = None
