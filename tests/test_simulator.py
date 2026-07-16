"""정책 시뮬레이터(first-match) 및 로그 분석 테스트."""

import unittest

from policygate.analysis.logscan import analyze_usage, parse_log_line
from policygate.analysis.simulator import Packet, first_match, rule_matches_packet
from policygate.rule import FirewallRule


def make_rule(rule_id, priority, src="10.0.0.0/24", dst="10.1.0.10/32",
              protocol="tcp", dst_ports="443", action="allow"):
    return FirewallRule.create(
        rule_id=rule_id, src=src, dst=dst, protocol=protocol,
        dst_ports=dst_ports, action=action, priority=priority,
        owner="t", description="d",
    )


class PacketTest(unittest.TestCase):
    def test_invalid_ip_rejected(self):
        with self.assertRaises(ValueError):
            Packet(src_ip="10.0.0.999", dst_ip="10.1.0.10",
                   protocol="tcp", dst_port=443)

    def test_tcp_requires_port(self):
        with self.assertRaises(ValueError):
            Packet(src_ip="10.0.0.1", dst_ip="10.1.0.10", protocol="tcp")

    def test_icmp_drops_port(self):
        p = Packet(src_ip="10.0.0.1", dst_ip="10.1.0.10",
                   protocol="icmp", dst_port=443)
        self.assertIsNone(p.dst_port)


class MatchTest(unittest.TestCase):
    def test_basic_match(self):
        rule = make_rule("R1", 10)
        pkt = Packet(src_ip="10.0.0.5", dst_ip="10.1.0.10",
                     protocol="tcp", dst_port=443)
        self.assertTrue(rule_matches_packet(rule, pkt))

    def test_port_mismatch(self):
        rule = make_rule("R1", 10)
        pkt = Packet(src_ip="10.0.0.5", dst_ip="10.1.0.10",
                     protocol="tcp", dst_port=444)
        self.assertFalse(rule_matches_packet(rule, pkt))

    def test_first_match_respects_priority(self):
        # deny(우선순위 10)가 allow(우선순위 20)보다 먼저 평가되어야 함
        rules = [
            make_rule("ALLOW-WIDE", 20, src="10.0.0.0/16", action="allow"),
            make_rule("DENY-NARROW", 10, src="10.0.0.0/24", action="deny"),
        ]
        pkt = Packet(src_ip="10.0.0.5", dst_ip="10.1.0.10",
                     protocol="tcp", dst_port=443)
        result = first_match(rules, pkt)
        self.assertEqual(result.matched_rule.rule_id, "DENY-NARROW")
        self.assertFalse(result.allowed)

    def test_default_deny(self):
        rules = [make_rule("R1", 10)]
        pkt = Packet(src_ip="192.0.2.1", dst_ip="10.1.0.10",
                     protocol="tcp", dst_port=443)
        result = first_match(rules, pkt)
        self.assertIsNone(result.matched_rule)
        self.assertFalse(result.allowed)  # 어댑터의 deny-by-default와 일치

    def test_icmp_match(self):
        rules = [make_rule("PING", 10, protocol="icmp", dst_ports="any")]
        pkt = Packet(src_ip="10.0.0.5", dst_ip="10.1.0.10", protocol="icmp")
        self.assertTrue(first_match(rules, pkt).allowed)


class LogParseTest(unittest.TestCase):
    def test_parse_valid_tcp_line(self):
        line = ("Jul 12 03:22:01 fw1 kernel: PGATE SRC=10.0.1.5 DST=10.20.0.10 "
                "LEN=60 TTL=63 PROTO=TCP SPT=51514 DPT=443 WINDOW=64240")
        pkt = parse_log_line(line)
        self.assertEqual(pkt.src_ip, "10.0.1.5")
        self.assertEqual(pkt.dst_ip, "10.20.0.10")
        self.assertEqual(pkt.protocol, "tcp")
        self.assertEqual(pkt.dst_port, 443)

    def test_parse_icmp_line_without_dpt(self):
        line = ("Jul 12 03:31:00 fw1 kernel: PGATE SRC=10.0.0.8 DST=10.99.0.1 "
                "LEN=84 TTL=63 PROTO=ICMP TYPE=8 CODE=0")
        pkt = parse_log_line(line)
        self.assertEqual(pkt.protocol, "icmp")
        self.assertIsNone(pkt.dst_port)

    def test_broken_line_returns_none(self):
        self.assertIsNone(parse_log_line("Jul 12 fw1 kernel: broken line"))
        self.assertIsNone(parse_log_line(""))


class UsageAnalysisTest(unittest.TestCase):
    def setUp(self):
        self.rules = [
            make_rule("HOT", 10, src="10.0.0.0/24", dst="10.1.0.10/32",
                      dst_ports="443"),
            make_rule("COLD", 20, src="10.8.0.0/24", dst="10.1.0.20/32",
                      dst_ports="8080"),
        ]
        self.logs = [
            "PGATE SRC=10.0.0.5 DST=10.1.0.10 PROTO=TCP SPT=1 DPT=443",
            "PGATE SRC=10.0.0.6 DST=10.1.0.10 PROTO=TCP SPT=2 DPT=443",
            "PGATE SRC=192.0.2.9 DST=10.1.0.10 PROTO=TCP SPT=3 DPT=22",
            "broken line",
        ]

    def test_hit_counts(self):
        report = analyze_usage(self.rules, self.logs)
        self.assertEqual(report.hit_counts["HOT"], 2)
        self.assertEqual(report.hit_counts["COLD"], 0)

    def test_unused_allow_detected(self):
        report = analyze_usage(self.rules, self.logs)
        self.assertIn("COLD", report.unused_allow_rules)
        self.assertNotIn("HOT", report.unused_allow_rules)

    def test_default_denied_counted(self):
        report = analyze_usage(self.rules, self.logs)
        flows = list(report.default_denied)
        self.assertEqual(len(flows), 1)
        self.assertIn("192.0.2.9", flows[0])

    def test_broken_lines_skipped_not_fatal(self):
        report = analyze_usage(self.rules, self.logs)
        self.assertEqual(report.total_lines, 4)
        self.assertEqual(report.parsed_packets, 3)

    def test_deny_rule_not_reported_as_unused(self):
        # deny 정책은 hit=0이어도 '미사용 회수 대상'이 아님 (안전장치이므로)
        rules = self.rules + [
            make_rule("GUARD", 5, src="192.0.2.0/24", action="deny",
                      dst="10.1.0.10/32", dst_ports="any"),
        ]
        report = analyze_usage(rules, self.logs[:2])
        self.assertNotIn("GUARD", report.unused_allow_rules)


if __name__ == "__main__":
    unittest.main()
