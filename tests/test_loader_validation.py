"""입력 검증 테스트 — 잘못된 CIDR, 중복 rule_id, 깨진 CSV.

정책 대장은 사람이 편집하는 파일이므로 모든 오류가 '몇 번째 줄이 왜'
잘못됐는지 알려줘야 합니다.
"""

import tempfile
import unittest
from pathlib import Path

from policygate.loader import load_rules_csv
from policygate.rule import FirewallRule

HEADER = "rule_id,src,dst,protocol,dst_ports,action,priority,description,owner,expires_at\n"


def write_csv(content: str) -> str:
    f = tempfile.NamedTemporaryFile(
        "w", suffix=".csv", delete=False, encoding="utf-8"
    )
    f.write(content)
    f.close()
    return f.name


class LoaderValidationTest(unittest.TestCase):
    def tearDown(self):
        for p in Path(tempfile.gettempdir()).glob("tmp*.csv"):
            p.unlink(missing_ok=True)

    def test_valid_csv_loads(self):
        path = write_csv(
            HEADER + "R1,10.0.0.0/24,10.1.0.10/32,tcp,443,allow,10,d,team,\n"
        )
        rules = load_rules_csv(path)
        self.assertEqual(len(rules), 1)

    def test_invalid_cidr_reports_line_number(self):
        path = write_csv(
            HEADER
            + "R1,10.0.0.0/24,10.1.0.10/32,tcp,443,allow,10,d,team,\n"
            + "R2,10.0.0.999/24,10.1.0.10/32,tcp,443,allow,20,d,team,\n"
        )
        with self.assertRaises(ValueError) as ctx:
            load_rules_csv(path)
        self.assertIn(":3:", str(ctx.exception))  # 3번째 줄(헤더 포함)이 문제

    def test_invalid_prefix_length_rejected(self):
        path = write_csv(HEADER + "R1,10.0.0.0/33,10.1.0.10/32,tcp,443,allow,10,d,t,\n")
        with self.assertRaises(ValueError):
            load_rules_csv(path)

    def test_ipv6_rejected_for_now(self):
        # IPv6는 아직 미지원 — 조용히 통과하지 않고 명시적으로 실패해야 함
        path = write_csv(HEADER + "R1,2001:db8::/32,10.1.0.10/32,tcp,443,allow,10,d,t,\n")
        with self.assertRaises(ValueError):
            load_rules_csv(path)

    def test_duplicate_rule_id_rejected(self):
        path = write_csv(
            HEADER
            + "R1,10.0.0.0/24,10.1.0.10/32,tcp,443,allow,10,d,t,\n"
            + "R1,10.0.1.0/24,10.1.0.11/32,tcp,80,allow,20,d,t,\n"
        )
        with self.assertRaises(ValueError) as ctx:
            load_rules_csv(path)
        self.assertIn("중복", str(ctx.exception))

    def test_empty_rule_id_rejected(self):
        path = write_csv(HEADER + ",10.0.0.0/24,10.1.0.10/32,tcp,443,allow,10,d,t,\n")
        with self.assertRaises(ValueError):
            load_rules_csv(path)

    def test_invalid_port_reports_line(self):
        path = write_csv(HEADER + "R1,10.0.0.0/24,10.1.0.10/32,tcp,99999,allow,10,d,t,\n")
        with self.assertRaises(ValueError):
            load_rules_csv(path)

    def test_invalid_action_rejected(self):
        path = write_csv(HEADER + "R1,10.0.0.0/24,10.1.0.10/32,tcp,443,permit,10,d,t,\n")
        with self.assertRaises(ValueError):
            load_rules_csv(path)

    def test_invalid_expiry_rejected(self):
        path = write_csv(
            HEADER + "R1,10.0.0.0/24,10.1.0.10/32,tcp,443,allow,10,d,t,어제\n"
        )
        with self.assertRaises(ValueError):
            load_rules_csv(path)

    def test_direct_factory_invalid_inputs(self):
        # 팩토리 자체의 방어선도 확인 (API 입력 경로)
        with self.assertRaises(ValueError):
            FirewallRule.create("R1", src="not-an-ip", dst="10.1.0.1")
        with self.assertRaises(ValueError):
            FirewallRule.create("R1", src="10.0.0.0/24", dst="10.1.0.1",
                                protocol="gre")  # 미지원 프로토콜
        with self.assertRaises(ValueError):
            FirewallRule.create("R1", src="10.0.0.0/24", dst="10.1.0.1",
                                dst_ports="80--90")


if __name__ == "__main__":
    unittest.main()
