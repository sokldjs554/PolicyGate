"""워크플로(신청→검증→승인→배포) 및 상태 머신 테스트."""

import unittest

from policygate.adapters import IptablesAdapter
from policygate.store import Store
from policygate.workflow import PolicyService, WorkflowError


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.service = PolicyService(self.store)

    def _submit_clean(self, **overrides):
        params = dict(
            requester="alice",
            src="10.5.0.0/24",
            dst="10.9.0.10/32",
            protocol="tcp",
            dst_ports="8080",
            action="allow",
            description="배치 서버 -> 내부 API",
            reason="신규 배치 작업 오픈",
        )
        params.update(overrides)
        return self.service.submit_request(**params)

    # ---------------- 신청 + 자동 검증 ----------------

    def test_clean_request_goes_to_pending_approval(self):
        req = self._submit_clean()
        self.assertEqual(req["state"], "pending_approval")

    def test_any_to_any_auto_rejected(self):
        req = self._submit_clean(src="any", dst="any", protocol="any",
                                 dst_ports="any")
        self.assertEqual(req["state"], "rejected")
        codes = {f["code"] for f in req["findings"]}
        self.assertIn("ANY_TO_ANY_ALLOW", codes)

    def test_duplicate_request_auto_rejected(self):
        # 첫 신청을 배포까지 완료
        req1 = self._submit_clean()
        self.service.approve(req1["request_id"], reviewer="bob")
        self.service.deploy(req1["request_id"], IptablesAdapter(), actor="bob")

        # 동일 트래픽 재신청 → 자동 반려
        req2 = self._submit_clean(requester="carol")
        self.assertEqual(req2["state"], "rejected")
        codes = {f["code"] for f in req2["findings"]}
        self.assertIn("DUPLICATE_OF_EXISTING", codes)

    # ---------------- 승인 ----------------

    def test_self_approval_forbidden(self):
        req = self._submit_clean()
        with self.assertRaises(WorkflowError):
            self.service.approve(req["request_id"], reviewer="alice")  # 신청자 본인

    def test_approve_then_deploy(self):
        req = self._submit_clean()
        self.service.approve(req["request_id"], reviewer="bob", note="OK")
        result = self.service.deploy(req["request_id"], IptablesAdapter(),
                                     actor="bob")
        self.assertEqual(result["request"]["state"], "deployed")
        # 배포된 정책이 활성 정책 셋에 반영되어야 함
        self.assertEqual(len(self.store.active_rules()), 1)
        # 생성된 iptables 설정에 신규 정책이 포함되어야 함
        self.assertIn("--dports 8080", result["rendered"])

    # ---------------- 상태 머신 강제 ----------------

    def test_deploy_without_approval_fails(self):
        req = self._submit_clean()
        with self.assertRaises(WorkflowError):
            self.service.deploy(req["request_id"], IptablesAdapter(), actor="bob")
        self.assertEqual(len(self.store.active_rules()), 0)

    def test_rejected_request_cannot_be_approved(self):
        req = self._submit_clean(src="any", dst="any", protocol="any",
                                 dst_ports="any")  # 자동 반려됨
        with self.assertRaises(WorkflowError):
            self.service.approve(req["request_id"], reviewer="bob")

    def test_double_deploy_fails(self):
        req = self._submit_clean()
        self.service.approve(req["request_id"], reviewer="bob")
        self.service.deploy(req["request_id"], IptablesAdapter(), actor="bob")
        with self.assertRaises(WorkflowError):
            self.service.deploy(req["request_id"], IptablesAdapter(), actor="bob")

    # ---------------- dry-run ----------------

    def test_dry_run_does_not_change_state(self):
        req = self._submit_clean()
        self.service.approve(req["request_id"], reviewer="bob")
        result = self.service.deploy(req["request_id"], IptablesAdapter(),
                                     actor="bob", dry_run=True)
        self.assertTrue(result["dry_run"])
        self.assertIn("*filter", result["rendered"])
        # dry-run은 상태/정책 셋을 변경하지 않아야 함
        self.assertEqual(
            self.store.get_request(req["request_id"])["state"],
            "approved",
        )
        self.assertEqual(len(self.store.active_rules()), 0)

    # ---------------- 회수 / 감사 로그 ----------------

    def test_decommission(self):
        req = self._submit_clean()
        self.service.approve(req["request_id"], reviewer="bob")
        result = self.service.deploy(req["request_id"], IptablesAdapter(),
                                     actor="bob")
        rule_id = result["request"]["rule"]["rule_id"]
        self.service.decommission_rule(rule_id, actor="bob", note="서비스 종료")
        self.assertEqual(len(self.store.active_rules()), 0)

    def test_audit_trail_records_full_lifecycle(self):
        req = self._submit_clean()
        rid = req["request_id"]
        self.service.approve(rid, reviewer="bob")
        self.service.deploy(rid, IptablesAdapter(), actor="bob")

        events = [e["event"] for e in self.store.audit_trail()]
        for expected in ("REQUEST_CREATED", "REQUEST_VALIDATED",
                         "REQUEST_APPROVED", "RULE_DEPLOYED"):
            self.assertIn(expected, events)


if __name__ == "__main__":
    unittest.main()
