"""Rule 모델의 포함/중첩 판정 정확성 테스트.

분석 엔진의 모든 판정이 이 연산 위에 서 있으므로,
경계 조건(포트 경계, CIDR 경계, any 처리)을 집중적으로 검증합니다.
"""

import unittest

from policygate.rule import (
    ANY_PORTS,
    FirewallRule,
    parse_ports,
    ports_cover,
    ports_overlap,
)


def make_rule(rule_id="R1", src="10.0.0.0/24", dst="10.1.0.0/24",
              protocol="tcp", dst_ports="443", action="allow", priority=100):
    return FirewallRule.create(
        rule_id=rule_id, src=src, dst=dst, protocol=protocol,
        dst_ports=dst_ports, action=action, priority=priority,
    )


class ParsePortsTest(unittest.TestCase):
    def test_any(self):
        self.assertEqual(parse_ports("any"), ANY_PORTS)
        self.assertEqual(parse_ports(""), ANY_PORTS)
        self.assertEqual(parse_ports("*"), ANY_PORTS)

    def test_single_and_list(self):
        self.assertEqual(parse_ports("443"), ((443, 443),))
        self.assertEqual(parse_ports("80,443"), ((80, 80), (443, 443)))

    def test_range(self):
        self.assertEqual(parse_ports("8000-8100"), ((8000, 8100),))

    def test_merge_overlapping(self):
        # 겹치는 구간은 정규형으로 병합되어야 함
        self.assertEqual(parse_ports("80-90,85-100"), ((80, 100),))

    def test_merge_adjacent(self):
        # 인접 구간(80-81, 82-90)도 하나로 병합
        self.assertEqual(parse_ports("80-81,82-90"), ((80, 90),))

    def test_invalid(self):
        with self.assertRaises(ValueError):
            parse_ports("0")          # 최소 포트는 1
        with self.assertRaises(ValueError):
            parse_ports("70000")      # 최대 포트는 65535
        with self.assertRaises(ValueError):
            parse_ports("100-50")     # 역전된 범위


class PortSetOpsTest(unittest.TestCase):
    def test_cover_exact(self):
        self.assertTrue(ports_cover(((80, 90),), ((80, 90),)))

    def test_cover_subset(self):
        self.assertTrue(ports_cover(((1, 65535),), ((443, 443),)))
        self.assertTrue(ports_cover(((80, 90),), ((85, 88),)))

    def test_not_cover_boundary(self):
        # 경계 1 차이도 놓치면 안 됨
        self.assertFalse(ports_cover(((80, 90),), ((80, 91),)))
        self.assertFalse(ports_cover(((80, 90),), ((79, 90),)))

    def test_cover_multi_interval(self):
        a = ((22, 22), (80, 90))
        self.assertTrue(ports_cover(a, ((22, 22), (85, 88))))
        # 두 구간에 걸친 요청은 커버 불가
        self.assertFalse(ports_cover(a, ((22, 80),)))

    def test_overlap(self):
        self.assertTrue(ports_overlap(((80, 90),), ((90, 100),)))   # 경계 접점
        self.assertFalse(ports_overlap(((80, 90),), ((91, 100),)))  # 1 차이


class CidrNormalizeTest(unittest.TestCase):
    def test_any_aliases(self):
        for alias in ("any", "*", "", "0.0.0.0/0"):
            self.assertEqual(FirewallRule.normalize_cidr(alias), "0.0.0.0/0")

    def test_host_ip_to_slash32(self):
        self.assertEqual(FirewallRule.normalize_cidr("10.1.2.3"), "10.1.2.3/32")

    def test_non_strict_network(self):
        # 호스트 비트가 켜진 입력도 네트워크 주소로 정규화
        self.assertEqual(FirewallRule.normalize_cidr("10.1.2.3/24"), "10.1.2.0/24")


class RuleRelationTest(unittest.TestCase):
    def test_covers_identical(self):
        a, b = make_rule("A"), make_rule("B")
        self.assertTrue(a.covers(b))
        self.assertTrue(b.covers(a))

    def test_covers_subnet(self):
        wide = make_rule("W", src="10.0.0.0/16")
        narrow = make_rule("N", src="10.0.5.0/24")
        self.assertTrue(wide.covers(narrow))
        self.assertFalse(narrow.covers(wide))

    def test_any_protocol_covers_tcp(self):
        any_p = make_rule("A", protocol="any", dst_ports="443")
        tcp_p = make_rule("T", protocol="tcp", dst_ports="443")
        self.assertTrue(any_p.covers(tcp_p))
        self.assertFalse(tcp_p.covers(any_p))

    def test_tcp_udp_disjoint(self):
        tcp_p = make_rule("T", protocol="tcp")
        udp_p = make_rule("U", protocol="udp")
        self.assertFalse(tcp_p.overlaps(udp_p))
        self.assertFalse(tcp_p.covers(udp_p))

    def test_disjoint_networks_no_overlap(self):
        a = make_rule("A", src="10.0.0.0/24")
        b = make_rule("B", src="10.9.0.0/24")
        self.assertFalse(a.overlaps(b))

    def test_partial_overlap_not_cover(self):
        a = make_rule("A", dst_ports="80-100")
        b = make_rule("B", dst_ports="90-200")
        self.assertTrue(a.overlaps(b))
        self.assertFalse(a.covers(b))
        self.assertFalse(b.covers(a))

    def test_icmp_ignores_ports(self):
        wide = make_rule("W", protocol="any", dst_ports="443")
        icmp = make_rule("I", protocol="icmp", dst_ports="any")
        # ICMP에는 포트 개념이 없으므로 포트 조건 무시하고 포함 판정
        self.assertTrue(wide.covers(icmp))

    def test_icmp_with_ports_rejected(self):
        with self.assertRaises(ValueError):
            make_rule("X", protocol="icmp", dst_ports="443")


if __name__ == "__main__":
    unittest.main()
