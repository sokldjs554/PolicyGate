"""RBAC(역할 기반 접근 제어) 테스트.

핵심 검증 포인트:
1. 역할은 서버측 저장소에서 조회된다 (클라이언트가 자칭 불가)
2. 권한 매트릭스가 API 경계에서 실제로 강제된다 (역할별 403)
3. 역할 관리 자체도 admin 전용이며 변경이 감사에 남는다
"""

import unittest

from policygate.api import create_app
from policygate.rbac import PERMISSIONS, RBAC, AccessDenied, Role
from policygate.store import Store


class RbacUnitTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.rbac = RBAC(self.store)

    def test_bootstrap_admin_created_once(self):
        self.assertEqual(self.rbac.role_of("admin"), Role.ADMIN)
        # 두 번째 인스턴스가 admin을 중복 생성하지 않아야 함
        RBAC(self.store)
        self.assertEqual(len(self.store.list_users()), 1)

    def test_unknown_user_denied(self):
        with self.assertRaises(AccessDenied):
            self.rbac.require("ghost", "request.create")

    def test_unknown_permission_is_programming_error(self):
        with self.assertRaises(ValueError):
            self.rbac.require("admin", "no.such.permission")

    def test_assign_requires_admin(self):
        self.rbac.assign("admin", "alice", Role.REQUESTER)
        with self.assertRaises(AccessDenied):
            self.rbac.assign("alice", "bob", Role.ADMIN)  # requester가 역할 부여 시도

    def test_role_change_audited_with_before_after(self):
        self.rbac.assign("admin", "alice", Role.REQUESTER)
        self.rbac.assign("admin", "alice", Role.APPROVER)
        events = [e for e in self.store.audit_trail("alice")
                  if e["event"] == "USER_ROLE_ASSIGNED"]
        self.assertEqual(len(events), 2)
        self.assertIsNone(events[0]["before"]["role"])        # 신규 부여
        self.assertEqual(events[1]["before"]["role"], "requester")
        self.assertEqual(events[1]["after"]["role"], "approver")

    def test_permission_matrix_shape(self):
        # 매트릭스 무결성: 모든 권한에 admin 포함 (관리 불능 상태 방지)
        for perm, roles in PERMISSIONS.items():
            self.assertIn(Role.ADMIN, roles, f"{perm}에 admin이 없습니다")

    def test_requester_permissions(self):
        self.rbac.assign("admin", "u", Role.REQUESTER)
        self.rbac.require("u", "request.create")   # 가능
        self.rbac.require("u", "rule.view")        # 가능
        for denied in ("request.approve", "request.reject", "deploy.execute",
                       "rule.decommission", "audit.view", "user.manage",
                       "deploy.rollback"):
            with self.assertRaises(AccessDenied, msg=denied):
                self.rbac.require("u", denied)

    def test_reviewer_permissions(self):
        self.rbac.assign("admin", "u", Role.REVIEWER)
        self.rbac.require("u", "request.reject")   # 반려 가능
        self.rbac.require("u", "audit.view")       # 감사 조회 가능
        for denied in ("request.approve", "deploy.execute", "deploy.rollback",
                       "rule.decommission", "user.manage"):
            with self.assertRaises(AccessDenied, msg=denied):
                self.rbac.require("u", denied)

    def test_approver_permissions(self):
        self.rbac.assign("admin", "u", Role.APPROVER)
        self.rbac.require("u", "request.approve")
        self.rbac.require("u", "deploy.execute")
        for denied in ("deploy.rollback", "rule.decommission", "user.manage"):
            with self.assertRaises(AccessDenied, msg=denied):
                self.rbac.require("u", denied)


class RbacApiTest(unittest.TestCase):
    """API 경계에서 권한이 실제로 강제되는지 (역할별 403) 검증."""

    def setUp(self):
        self.app = create_app(Store(":memory:"))
        self.client = self.app.test_client()
        for username, role in (
            ("req", "requester"), ("rev", "reviewer"),
            ("app", "approver"),
        ):
            self.client.post("/api/users",
                             json={"username": username, "role": role},
                             headers={"X-User": "admin"})

    def _submit(self, user="req"):
        return self.client.post(
            "/api/requests",
            json={"src": "10.5.0.0/24", "dst": "10.9.0.10/32",
                  "protocol": "tcp", "dst_ports": "8080", "description": "d"},
            headers={"X-User": user},
        ).get_json()["request_id"]

    def test_unregistered_user_gets_403(self):
        res = self.client.post("/api/requests", json={},
                               headers={"X-User": "ghost"})
        self.assertEqual(res.status_code, 403)

    def test_requester_cannot_approve(self):
        rid = self._submit()
        res = self.client.post(f"/api/requests/{rid}/approve", json={},
                               headers={"X-User": "req"})
        self.assertEqual(res.status_code, 403)

    def test_reviewer_can_reject_but_not_approve(self):
        rid = self._submit()
        res = self.client.post(f"/api/requests/{rid}/approve", json={},
                               headers={"X-User": "rev"})
        self.assertEqual(res.status_code, 403)
        res = self.client.post(f"/api/requests/{rid}/reject",
                               json={"note": "범위 과다"},
                               headers={"X-User": "rev"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["state"], "rejected")

    def test_approver_cannot_rollback(self):
        rid = self._submit()
        self.client.post(f"/api/requests/{rid}/approve", json={},
                         headers={"X-User": "app"})
        self.client.post(f"/api/requests/{rid}/deploy",
                         json={"adapter": "iptables"},
                         headers={"X-User": "app"})
        res = self.client.post(f"/api/requests/{rid}/rollback", json={},
                               headers={"X-User": "app"})
        self.assertEqual(res.status_code, 403)

    def test_requester_cannot_view_audit(self):
        res = self.client.get("/api/audit/trail", headers={"X-User": "req"})
        self.assertEqual(res.status_code, 403)

    def test_non_admin_cannot_manage_users(self):
        res = self.client.post("/api/users",
                               json={"username": "x", "role": "admin"},
                               headers={"X-User": "app"})
        self.assertEqual(res.status_code, 403)

    def test_non_admin_cannot_decommission(self):
        res = self.client.delete("/api/rules/FW-0001",
                                 headers={"X-User": "app"})
        self.assertEqual(res.status_code, 403)

    def test_roles_endpoint_returns_matrix(self):
        res = self.client.get("/api/roles", headers={"X-User": "req"})
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        self.assertEqual(body["you"]["role"], "requester")
        self.assertIn("request.approve", body["permissions"])

    def test_invalid_role_assignment_rejected(self):
        res = self.client.post("/api/users",
                               json={"username": "x", "role": "superuser"},
                               headers={"X-User": "admin"})
        self.assertEqual(res.status_code, 400)


if __name__ == "__main__":
    unittest.main()
