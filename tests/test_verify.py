"""실배포 검증(NamespaceVerifier) 테스트.

격리된 network namespace에서 iptables-restore를 실제 수행하므로
root + unshare + iptables-restore가 있는 환경(리눅스/CI)에서만 실행되고,
그 외 환경에서는 자동으로 skip됩니다.
"""

import unittest

from policygate.adapters import IptablesAdapter, NamespaceVerifier
from policygate.adapters.verify import VerificationResult
from policygate.rule import FirewallRule
from policygate.store import Store
from policygate.workflow import PolicyService, WorkflowError

NS_AVAILABLE = NamespaceVerifier.available()


def make_rules(n=3):
    return [
        FirewallRule.create(
            rule_id=f"VT-{i:02d}", src=f"10.{i}.0.0/24", dst=f"172.16.{i}.1/32",
            protocol="tcp", dst_ports=str(8000 + i), action="allow",
            priority=i * 10, owner="t", description="검증 테스트",
        )
        for i in range(n)
    ]


@unittest.skipUnless(NS_AVAILABLE, "netns 검증 불가 환경 (root+unshare 필요)")
class NamespaceVerifierTest(unittest.TestCase):
    def test_real_kernel_apply_and_readback(self):
        """생성된 설정이 실제 커널에 적용되고 readback 대조를 통과한다."""
        rules = make_rules()
        rendered = IptablesAdapter().render(rules)
        result = NamespaceVerifier().verify(rendered, rules)
        self.assertTrue(result.applied, result.error)
        self.assertTrue(result.ok, result.summary())
        self.assertEqual(result.missing_rule_ids, [])
        self.assertTrue(result.default_policy_ok)
        # readback에 rule_id 주석이 실제로 존재
        self.assertIn("VT-00", result.readback)

    def test_detects_missing_rule(self):
        """설정에 없는 정책을 기대하면 검증이 실패해야 한다 (미탐 방지)."""
        rules = make_rules()
        rendered = IptablesAdapter().render(rules[:2])  # 마지막 정책 누락
        result = NamespaceVerifier().verify(rendered, rules)
        self.assertTrue(result.applied)
        self.assertFalse(result.ok)
        self.assertEqual(result.missing_rule_ids, ["VT-02"])

    def test_broken_config_reports_apply_failure(self):
        """문법이 깨진 설정은 applied=False로 보고되어야 한다."""
        result = NamespaceVerifier().verify("*filter\n-A GARBAGE\n", make_rules(1))
        self.assertFalse(result.applied)
        self.assertFalse(result.ok)
        self.assertTrue(result.error)

    def test_full_workflow_deploy_with_real_verification(self):
        """워크플로 deploy가 실제 커널 검증을 통과하며 배포되는 엔드투엔드."""
        store = Store(":memory:")
        service = PolicyService(store)
        req = service.submit_request(
            requester="alice", src="10.5.0.0/24", dst="10.9.0.10/32",
            protocol="tcp", dst_ports="8080", description="e2e",
        )
        service.approve(req["request_id"], reviewer="bob")
        result = service.deploy(
            req["request_id"], IptablesAdapter(), actor="bob",
            verifier=NamespaceVerifier(),
        )
        self.assertEqual(result["request"]["state"], "deployed")
        self.assertTrue(result["verification"]["ok"])
        events = [e["event"] for e in store.audit_trail()]
        self.assertIn("DEPLOY_VERIFIED", events)


class FakeVerifierWorkflowTest(unittest.TestCase):
    """검증기 계약(실패 시 배포 중단)을 환경 무관하게 검증 — 가짜 검증기 주입."""

    class FailingVerifier:
        def verify(self, rendered, rules):
            return VerificationResult(
                ok=False, applied=True,
                missing_rule_ids=[r.rule_id for r in rules[:1]],
                default_policy_ok=True,
            )

    def test_failed_verification_blocks_deploy_and_keeps_state(self):
        store = Store(":memory:")
        service = PolicyService(store)
        req = service.submit_request(
            requester="alice", src="10.5.0.0/24", dst="10.9.0.10/32",
            protocol="tcp", dst_ports="8080", description="d",
        )
        service.approve(req["request_id"], reviewer="bob")
        with self.assertRaises(WorkflowError):
            service.deploy(req["request_id"], IptablesAdapter(), actor="bob",
                           verifier=self.FailingVerifier())
        # 실패 시: 상태 approved 유지 + 정책 미반영 + 감사 기록
        self.assertEqual(
            store.get_request(req["request_id"])["state"], "approved")
        self.assertEqual(len(store.active_rules()), 0)
        events = [e["event"] for e in store.audit_trail()]
        self.assertIn("DEPLOY_VERIFY_FAILED", events)


if __name__ == "__main__":
    unittest.main()
