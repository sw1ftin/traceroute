import unittest
import sys
import os
from io import StringIO

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from formatters import TraceHop, StandardFormatter

class TestStandardFormatter(unittest.TestCase):
    def setUp(self):
        self.formatter = StandardFormatter()
        self.stdout = StringIO()
        self.old_stdout = sys.stdout
        sys.stdout = self.stdout

    def tearDown(self):
        sys.stdout = self.old_stdout

    def test_header_format(self):
        self.formatter.print_header(
            "test.com", "1.1.1.1", "ICMP", None,
            30, 40, 3, 2.0, 0.0, True, True
        )
        output = self.stdout.getvalue()
        
        expected_parts = [
            "traceroute to test.com",
            "1.1.1.1",
            "ICMP",
            "30 hops max",
            "3 probes",
            "40 byte packets"
        ]
        
        for part in expected_parts:
            self.assertIn(part, output)

    def test_hop_format(self):
        hop = TraceHop(1, "192.168.1.1", [10.5, None, 11.2], "12345", "router.local")
        self.formatter.print_hop(hop)
        output = self.stdout.getvalue()
        
        expected_parts = [
            "router.local",
            "10.50",
            "*",
            "11.20",
            "[AS12345]"
        ]
        
        for part in expected_parts:
            self.assertIn(part, output)

if __name__ == '__main__':
    unittest.main()

