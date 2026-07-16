"""분석 엔진(Shadowing/Redundancy/위험 탐지) 정확성 테스트."""

import unittest
from datetime import datetime, timedelta, timezone

from policygate.analysis.detector import PolicyAnalyzer, Severity
from policygate.rule import FirewallRule


def make_rule(rule_id, priority, src="10.0.0.0/24", dst="10.1.0.10/32",
              protocol="tcp", dst_ports="443", action="allow",
              owner="team-a", description="test rule", expires_at=None):
    return FirewallRule.create(
        rule_id=rule_id, src=src, dst=dst, protocol=protocol,
        dst_ports=dst_ports, action=action, priority=priority,
        owner=owner, description=description, expires_at=expires_at,
    )


def codes_for(findings, rule_id):
    return {f.code for f in findings if f.rule_id == rule_id}


class RelationDetectionTest(unittest.TestCase):
    def setUp(self):
        self.analyzer = PolicyAnalyzer()

    def test_shadowed_rule_detected(self):
        # 앞선 allow가 뒤의 deny를 완전히 가림 → deny 의도가 무효화
        rules = [
            make_rule("R1", 10, src="10.0.0.0/16", action="allow"),
            make_rule("R2", 20, src="10.0.5.0/24", action="deny"),
        ]
        report = self.analyzer.analyze(rules)
        self.assertIn("SHADOWED", codes_for(report.findings, "R2"))
        shadow = next(f for f in report.findings if f.code == "SHADOWED")
        self.assertEqual(shadow.related_rule_id, "R1")
        self.assertEqual(shadow.severity, Severity.HIGH)

    def test_redundant_rule_detected(self):
        rules = [
            make_rule("R1", 10, src="10.0.0.0/16"),
            make_rule("R2", 20, src="10.0.5.0/24"),  # 동일 액션, 부분집합
        ]
        report = self.analyzer.analyze(rules)
        self.assertIn("REDUNDANT", codes_for(report.findings, "R2"))

    def test_correlation_detected(self):
        # 부분 겹침 + 액션 상이 → 순서 민감
        rules = [
            make_rule("R1", 10, dst_ports="80-100", action="allow"),
            make_rule("R2", 20, dst_ports="90-200", action="deny"),
        ]
        report = self.analyzer.analyze(rules)
        self.assertIn("CORRELATED", codes_for(report.findings, "R2"))

    def test_no_false_positive_on_disjoint(self):
        rules = [
            make_rule("R1", 10, src="10.0.0.0/24"),
            make_rule("R2", 20, src="10.9.0.0/24"),
        ]
        report = self.analyzer.analyze(rules)
        relation_codes = {"SHADOWED", "REDUNDANT", "CORRELATED"}
        found = {f.code for f in report.findings}
        self.assertFalse(found & relation_codes)

    def test_order_matters_wide_after_narrow_is_not_shadowing(self):
        # 좁은 deny가 앞, 넓은 allow가 뒤: 정상 패턴 (예외 후 일반 허용)
        rules = [
            make_rule("R1", 10, src="10.0.5.0/24", action="deny"),
            make_rule("R2", 20, src="10.0.0.0/16", action="allow"),
        ]
        report = self.analyzer.analyze(rules)
        self.assertNotIn("SHADOWED", codes_for(report.findings, "R2"))


class RiskDetectionTest(unittest.TestCase):
    def setUp(self):
        self.analyzer = PolicyAnalyzer()

    def test_any_to_any_allow_is_critical(self):
        rules = [make_rule("R1", 10, src="any", dst="any",
                           protocol="any", dst_ports="any")]
        report = self.analyzer.analyze(rules)
        self.assertIn("ANY_TO_ANY_ALLOW", codes_for(report.findings, "R1"))
        self.assertTrue(report.has_blocking_issues())

    def test_risky_port_exposed(self):
        rules = [make_rule("R1", 10, src="any", dst="10.1.0.9/32",
                           dst_ports="3389")]
        report = self.analyzer.analyze(rules)
        self.assertIn("RISKY_PORT_EXPOSED", codes_for(report.findings, "R1"))

    def test_risky_port_in_range_detected(self):
        # 3389가 명시되지 않아도 3000-4000 범위에 포함되면 탐지해야 함
        rules = [make_rule("R1", 10, src="any", dst="10.1.0.9/32",
                           dst_ports="3000-4000")]
        report = self.analyzer.analyze(rules)
        self.assertIn("RISKY_PORT_EXPOSED", codes_for(report.findings, "R1"))

    def test_internal_risky_port_not_flagged(self):
        # 출발지가 내부망이면 인터넷 노출이 아님 → 미탐지 (false positive 방지)
        rules = [make_rule("R1", 10, src="10.2.0.0/24", dst="10.1.0.9/32",
                           dst_ports="3389")]
        report = self.analyzer.analyze(rules)
        self.assertNotIn("RISKY_PORT_EXPOSED", codes_for(report.findings, "R1"))

    def test_expired_rule(self):
        past = datetime.now(timezone.utc) - timedelta(days=3)
        rules = [make_rule("R1", 10, expires_at=past)]
        report = self.analyzer.analyze(rules)
        self.assertIn("EXPIRED_RULE", codes_for(report.findings, "R1"))

    def test_not_yet_expired(self):
        future = datetime.now(timezone.utc) + timedelta(days=3)
        rules = [make_rule("R1", 10, expires_at=future)]
        report = self.analyzer.analyze(rules)
        self.assertNotIn("EXPIRED_RULE", codes_for(report.findings, "R1"))

    def test_governance_missing_owner_description(self):
        rules = [make_rule("R1", 10, owner="", description="")]
        report = self.analyzer.analyze(rules)
        codes = codes_for(report.findings, "R1")
        self.assertIn("MISSING_OWNER", codes)
        self.assertIn("MISSING_DESCRIPTION", codes)


class ValidateNewRuleTest(unittest.TestCase):
    """신규 신청 사전 검증 (워크플로 게이트) 테스트."""

    def setUp(self):
        self.analyzer = PolicyAnalyzer()
        self.existing = [
            make_rule("FW-1", 10, src="10.0.0.0/16", dst="10.1.0.10/32",
                      dst_ports="443", action="allow"),
        ]

    def test_duplicate_rejected(self):
        new = make_rule("NEW", 100, src="10.0.7.0/24", dst="10.1.0.10/32",
                        dst_ports="443", action="allow")
        findings = self.analyzer.validate_new_rule(new, self.existing)
        self.assertIn("DUPLICATE_OF_EXISTING", {f.code for f in findings})
        self.assertTrue(any(f.severity == Severity.CRITICAL for f in findings))

    def test_will_be_shadowed_rejected(self):
        new = make_rule("NEW", 100, src="10.0.7.0/24", dst="10.1.0.10/32",
                        dst_ports="443", action="deny")
        findings = self.analyzer.validate_new_rule(new, self.existing)
        self.assertIn("WILL_BE_SHADOWED", {f.code for f in findings})

    def test_conflict_overlap_flagged_high(self):
        new = make_rule("NEW", 100, src="10.0.0.0/8", dst="10.1.0.10/32",
                        dst_ports="443", action="deny")
        findings = self.analyzer.validate_new_rule(new, self.existing)
        self.assertIn("CONFLICT_OVERLAP", {f.code for f in findings})
        # 부분 겹침은 반려가 아닌 승인자 검토 대상 (critical 아님)
        conflict = next(f for f in findings if f.code == "CONFLICT_OVERLAP")
        self.assertEqual(conflict.severity, Severity.HIGH)

    def test_clean_rule_passes(self):
        new = make_rule("NEW", 100, src="10.5.0.0/24", dst="10.9.0.10/32",
                        dst_ports="8080", action="allow")
        findings = self.analyzer.validate_new_rule(new, self.existing)
        self.assertFalse(any(f.severity == Severity.CRITICAL for f in findings))


if __name__ == "__main__":
    unittest.main()
