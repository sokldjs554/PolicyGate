"""어댑터 출력(벤더 설정 생성) 정확성 테스트."""

import unittest

from policygate.adapters import IptablesAdapter, NftablesAdapter
from policygate.rule import FirewallRule


def make_rule(rule_id="R1", src="10.0.0.0/24", dst="10.1.0.10/32",
              protocol="tcp", dst_ports="443", action="allow", priority=100):
    return FirewallRule.create(
        rule_id=rule_id, src=src, dst=dst, protocol=protocol,
        dst_ports=dst_ports, action=action, priority=priority,
    )


class IptablesRenderTest(unittest.TestCase):
    def setUp(self):
        self.adapter = IptablesAdapter()

    def test_deny_by_default(self):
        out = self.adapter.render([])
        self.assertIn(":FORWARD DROP", out)          # 기본 차단
        self.assertIn("ESTABLISHED,RELATED", out)    # 세션 응답 허용
        self.assertIn("COMMIT", out)

    def test_basic_allow_rule(self):
        out = self.adapter.render([make_rule()])
        self.assertIn("-s 10.0.0.0/24", out)
        self.assertIn("-d 10.1.0.10/32", out)
        self.assertIn("-p tcp", out)
        self.assertIn("--dports 443", out)
        self.assertIn("-j ACCEPT", out)
        self.assertIn('--comment "R1"', out)  # 추적성: rule_id가 장비에 남음

    def test_deny_rule(self):
        out = self.adapter.render([make_rule(action="deny")])
        self.assertIn("-j DROP", out)

    def test_any_src_omitted(self):
        out = self.adapter.render([make_rule(src="any")])
        self.assertNotIn("-s 0.0.0.0/0", out)  # any는 조건 생략이 관례

    def test_port_range_syntax(self):
        out = self.adapter.render([make_rule(dst_ports="8000-8100")])
        self.assertIn("--dports 8000:8100", out)  # iptables는 콜론 문법

    def test_priority_order_preserved(self):
        r_low = make_rule("LOW", priority=200, dst_ports="80")
        r_high = make_rule("HIGH", priority=10, dst_ports="443")
        out = self.adapter.render([r_low, r_high])
        self.assertLess(out.index('"HIGH"'), out.index('"LOW"'))

    def test_any_proto_with_ports_expands_to_tcp_udp(self):
        out = self.adapter.render([make_rule(protocol="any", dst_ports="53")])
        self.assertIn("-p tcp", out)
        self.assertIn("-p udp", out)

    def test_deploy_without_runner_is_safe(self):
        # 러너가 없으면 시스템에 손대지 않고 설정 문자열만 반환해야 함
        out = self.adapter.deploy([make_rule()])
        self.assertIn("*filter", out)


class NftablesRenderTest(unittest.TestCase):
    def setUp(self):
        self.adapter = NftablesAdapter()

    def test_deny_by_default(self):
        out = self.adapter.render([])
        self.assertIn("policy drop", out)
        self.assertIn("ct state established,related accept", out)

    def test_basic_allow_rule(self):
        out = self.adapter.render([make_rule()])
        self.assertIn("ip saddr 10.0.0.0/24", out)
        self.assertIn("ip daddr 10.1.0.10/32", out)
        self.assertIn("tcp dport 443", out)
        self.assertIn('accept comment "R1"', out)

    def test_multi_port_set_syntax(self):
        out = self.adapter.render([make_rule(dst_ports="80,443")])
        self.assertIn("{ 80, 443 }", out)

    def test_icmp_rule(self):
        out = self.adapter.render([make_rule(protocol="icmp", dst_ports="any")])
        self.assertIn("ip protocol icmp", out)

    def test_declarative_flush(self):
        # 선언형 전체 교체: 항상 flush로 시작해야 드리프트가 없음
        out = self.adapter.render([make_rule()])
        self.assertTrue(out.splitlines()[1].startswith("flush table"))


class CrossVendorConsistencyTest(unittest.TestCase):
    """같은 정책 모델이 두 벤더에서 의미적으로 동일하게 표현되는지 검증."""

    def test_same_rule_both_vendors(self):
        rule = make_rule(dst_ports="443", action="deny")
        ipt = IptablesAdapter().render([rule])
        nft = NftablesAdapter().render([rule])
        self.assertIn("-j DROP", ipt)
        self.assertIn("drop", nft)
        for out in (ipt, nft):
            self.assertIn("443", out)
            self.assertIn("R1", out)


if __name__ == "__main__":
    unittest.main()
