import unittest
import os
import sys
from scapy.all import IP, ICMP, TCP, UDP
from io import StringIO

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from traceroute import ICMPProbe, TCPProbe, UDPProbe
from formatters import TraceHop, StandardFormatter

class TestProbes(unittest.TestCase):
    def test_icmp_probe(self):
        probe = ICMPProbe(packet_size=60)
        pkt = probe.create_probe("8.8.8.8", ttl=1, seq=1)
        
        self.assertIsInstance(pkt, IP)
        self.assertEqual(pkt[IP].ttl, 1)
        self.assertEqual(pkt[ICMP].seq, 1)
        self.assertEqual(len(pkt), 60)

    def test_tcp_probe(self):
        probe = TCPProbe(port=80, packet_size=60)
        pkt = probe.create_probe("8.8.8.8", ttl=1, seq=1)
        
        self.assertIsInstance(pkt, IP)
        self.assertEqual(pkt[IP].ttl, 1)
        self.assertEqual(pkt[TCP].dport, 80)
        self.assertEqual(pkt[TCP].seq, 1)
        self.assertEqual(len(pkt), 60)

    def test_udp_probe(self):
        probe = UDPProbe(port=33434, packet_size=60)
        pkt = probe.create_probe("8.8.8.8", ttl=1, seq=1)
        
        self.assertIsInstance(pkt, IP)
        self.assertEqual(pkt[IP].ttl, 1)
        self.assertEqual(pkt[UDP].dport, 33434)
        self.assertEqual(len(pkt), 60)

class TestTraceHop(unittest.TestCase):
    def setUp(self):
        self.formatter = StandardFormatter()
        self.stdout = StringIO()
        self.old_stdout = sys.stdout
        sys.stdout = self.stdout

    def tearDown(self):
        sys.stdout = self.old_stdout

    def get_formatted_output(self, hop):
        self.stdout.seek(0)
        self.stdout.truncate()
        self.formatter.print_hop(hop)
        return self.stdout.getvalue().strip()

    def test_trace_hop_with_hostname(self):
        hop = TraceHop(1, "192.168.1.1", [10.5, None, 11.2], "12345", "router.local")
        output = self.get_formatted_output(hop)
        
        self.assertIn("router.local", output)
        self.assertIn("10.50", output)
        self.assertIn("*", output)
        self.assertIn("11.20", output)
        self.assertIn("[AS12345]", output)

    def test_trace_hop_without_hostname(self):
        hop = TraceHop(1, "192.168.1.1", [10.5, None, 11.2], "12345", None)
        output = self.get_formatted_output(hop)
        
        self.assertIn("192.168.1.1", output)
        self.assertIn("10.50", output)
        self.assertIn("*", output)
        self.assertIn("11.20", output)
        self.assertIn("[AS12345]", output)

    def test_trace_hop_timeout(self):
        hop = TraceHop(1, "*", [None, None, None], None, None)
        output = self.get_formatted_output(hop)
        
        self.assertEqual(output, "1  *  *  *  *")

    def test_hop_format(self):
        hop = TraceHop(1, "192.168.1.1", [10.5, None, 11.2], "12345", "router.local")
        output = self.get_formatted_output(hop)
        
        expected_parts = [
            "1",
            "router.local",
            "10.50",
            "*",
            "11.20",
            "AS12345"
        ]
        
        for part in expected_parts:
            self.assertIn(part, output)

    def test_timeout_format(self):
        hop = TraceHop(1, "*", [None, None, None], None, None)
        output = self.get_formatted_output(hop)
        self.assertIn("*", output)
        self.assertEqual(output.count("*"), 4)  # hop number + 3 timeouts

if __name__ == '__main__':
    unittest.main()
