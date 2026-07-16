"""롤백 및 감사(before/after) 스냅샷 테스트."""

import unittest

from policygate.adapters import IptablesAdapter
from policygate.store import Store
from policygate.workflow import PolicyService, WorkflowError


class RollbackTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.service = PolicyService(self.store)

    def _deployed_request(self):
        req = self.service.submit_request(
            requester="alice", src="10.5.0.0/24", dst="10.9.0.10/32",
            protocol="tcp", dst_ports="8080", description="d",
        )
        self.service.approve(req["request_id"], reviewer="bob")
        self.service.deploy(req["request_id"], IptablesAdapter(), actor="bob")
        return req["request_id"]

    def test_rollback_deactivates_rule_and_sets_state(self):
        rid = self._deployed_request()
        self.assertEqual(len(self.store.active_rules()), 1)
        req = self.service.rollback(rid, actor="admin", note="장애 대응")
        self.assertEqual(req["state"], "rolled_back")
        self.assertEqual(len(self.store.active_rules()), 0)

    def test_rollback_requires_deployed_state(self):
        req = self.service.submit_request(
            requester="alice", src="10.5.0.0/24", dst="10.9.0.10/32",
            protocol="tcp", dst_ports="8080", description="d",
        )
        with self.assertRaises(WorkflowError):
            self.service.rollback(req["request_id"], actor="admin")

    def test_double_rollback_fails(self):
        rid = self._deployed_request()
        self.service.rollback(rid, actor="admin")
        with self.assertRaises(WorkflowError):
            self.service.rollback(rid, actor="admin")

    def test_rolled_back_is_terminal(self):
        rid = self._deployed_request()
        self.service.rollback(rid, actor="admin")
        with self.assertRaises(WorkflowError):
            self.service.approve(rid, reviewer="bob")

    def test_redeploy_after_rollback_possible_via_new_request(self):
        # 롤백 후 동일 트래픽 재신청은 (기존 정책이 비활성이므로) 중복 반려되지 않아야 함
        rid = self._deployed_request()
        self.service.rollback(rid, actor="admin")
        req2 = self.service.submit_request(
            requester="alice", src="10.5.0.0/24", dst="10.9.0.10/32",
            protocol="tcp", dst_ports="8080", description="재오픈",
        )
        self.assertEqual(req2["state"], "pending_approval")


class AuditSnapshotTest(unittest.TestCase):
    """모든 정책 변경에 timestamp/actor/action/before/after가 남는지 검증."""

    def setUp(self):
        self.store = Store(":memory:")
        self.service = PolicyService(self.store)

    def _deploy(self):
        req = self.service.submit_request(
            requester="alice", src="10.5.0.0/24", dst="10.9.0.10/32",
            protocol="tcp", dst_ports="8080", description="d",
        )
        self.service.approve(req["request_id"], reviewer="bob")
        result = self.service.deploy(req["request_id"], IptablesAdapter(),
                                     actor="bob")
        return req["request_id"], result["request"]["rule"]["rule_id"]

    def test_every_entry_has_timestamp_and_actor(self):
        self._deploy()
        for entry in self.store.audit_trail():
            self.assertTrue(entry["at"])      # ISO timestamp
            self.assertTrue(entry["actor"])
            self.assertTrue(entry["event"])
            self.assertTrue(entry["target"])

    def test_deploy_records_after_snapshot(self):
        _, rule_id = self._deploy()
        deployed = next(e for e in self.store.audit_trail(rule_id)
                        if e["event"] == "RULE_DEPLOYED")
        self.assertIsNone(deployed["before"])          # 신규 정책: 이전 상태 없음
        self.assertEqual(deployed["after"]["rule_id"], rule_id)
        self.assertEqual(deployed["after"]["dst_ports"], "8080")

    def test_state_changes_record_before_after(self):
        rid, _ = self._deploy()
        changes = [e for e in self.store.audit_trail(rid)
                   if e["event"] == "REQUEST_STATE_CHANGED"]
        # submitted->pending_approval, approved->deployed 최소 2건
        self.assertGreaterEqual(len(changes), 2)
        first = changes[0]
        self.assertEqual(first["before"]["state"], "submitted")
        self.assertEqual(first["after"]["state"], "pending_approval")

    def test_approve_records_state_transition(self):
        rid, _ = self._deploy()
        approved = next(e for e in self.store.audit_trail(rid)
                        if e["event"] == "REQUEST_APPROVED")
        self.assertEqual(approved["before"]["state"], "pending_approval")
        self.assertEqual(approved["after"]["state"], "approved")

    def test_decommission_records_before_after(self):
        _, rule_id = self._deploy()
        self.service.decommission_rule(rule_id, actor="admin", note="정리")
        entry = next(e for e in self.store.audit_trail(rule_id)
                     if e["event"] == "RULE_DECOMMISSIONED")
        self.assertTrue(entry["before"]["active"])
        self.assertFalse(entry["after"]["active"])
        self.assertEqual(entry["actor"], "admin")

    def test_request_created_records_rule_snapshot(self):
        rid, _ = self._deploy()
        created = next(e for e in self.store.audit_trail(rid)
                       if e["event"] == "REQUEST_CREATED")
        self.assertIsNone(created["before"])
        self.assertEqual(created["after"]["src"], "10.5.0.0/24")


if __name__ == "__main__":
    unittest.main()
