"""REST API 통합 테스트 (Flask test client).

실제 HTTP 계층을 통과하는 엔드투엔드 시나리오:
신청 → 자동 검증 → 승인 → dry-run → 배포 → 롤백 → 감사 조회
(RBAC 권한 위반 케이스는 tests/test_rbac.py에서 별도 검증)
"""

import unittest

from policygate.api import create_app
from policygate.store import Store


class ApiTest(unittest.TestCase):
    def setUp(self):
        self.app = create_app(Store(":memory:"))
        self.client = self.app.test_client()
        # RBAC: 부트스트랩 admin으로 테스트 사용자 역할 등록
        for username, role in (
            ("alice", "approver"),   # 신청자이자 승인 권한 보유 (SoD 테스트용)
            ("bob", "approver"),
            ("carol", "reviewer"),
            ("dave", "requester"),
        ):
            res = self.client.post(
                "/api/users",
                json={"username": username, "role": role},
                headers={"X-User": "admin"},
            )
            assert res.status_code == 201, res.get_json()

    def _submit(self, user="alice", **overrides):
        body = dict(
            src="10.5.0.0/24",
            dst="10.9.0.10/32",
            protocol="tcp",
            dst_ports="8080",
            action="allow",
            description="배치 서버 -> 내부 API",
            reason="신규 배치 오픈",
        )
        body.update(overrides)
        return self.client.post(
            "/api/requests", json=body, headers={"X-User": user}
        )

    def test_full_lifecycle(self):
        # 1) 신청 → 자동 검증 통과
        res = self._submit()
        self.assertEqual(res.status_code, 201)
        req = res.get_json()
        self.assertEqual(req["state"], "pending_approval")
        rid = req["request_id"]

        # 2) 승인 (다른 사용자)
        res = self.client.post(
            f"/api/requests/{rid}/approve",
            json={"note": "확인 완료"},
            headers={"X-User": "bob"},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["state"], "approved")

        # 3) dry-run으로 생성될 설정 확인
        res = self.client.post(
            f"/api/requests/{rid}/deploy?dry_run=true",
            json={"adapter": "iptables"},
            headers={"X-User": "bob"},
        )
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json()["dry_run"])
        self.assertIn("--dports 8080", res.get_json()["rendered"])

        # 4) 실제 배포
        res = self.client.post(
            f"/api/requests/{rid}/deploy",
            json={"adapter": "iptables"},
            headers={"X-User": "bob"},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["request"]["state"], "deployed")

        # 5) 활성 정책에 반영 확인
        rules = self.client.get(
            "/api/rules", headers={"X-User": "alice"}
        ).get_json()
        self.assertEqual(len(rules), 1)

        # 6) 감사 로그에 전체 이력 존재 (audit.view는 reviewer 이상)
        trail = self.client.get(
            "/api/audit/trail", headers={"X-User": "carol"}
        ).get_json()
        events = [e["event"] for e in trail]
        self.assertIn("REQUEST_CREATED", events)
        self.assertIn("RULE_DEPLOYED", events)

        # 7) 롤백 (admin 전용) → 활성 정책 0건
        rule_id = rules[0]["rule_id"]
        res = self.client.post(
            f"/api/requests/{rid}/rollback",
            json={"note": "장애 대응"},
            headers={"X-User": "admin"},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["state"], "rolled_back")
        rules_after = self.client.get(
            "/api/rules", headers={"X-User": "alice"}
        ).get_json()
        self.assertEqual(len(rules_after), 0)
        # 롤백의 before/after 스냅샷 확인
        trail = self.client.get(
            f"/api/audit/trail?target={rule_id}", headers={"X-User": "admin"}
        ).get_json()
        rb = next(e for e in trail if e["event"] == "DEPLOY_ROLLED_BACK")
        self.assertTrue(rb["before"]["active"])
        self.assertFalse(rb["after"]["active"])

    def test_dangerous_request_rejected_with_422(self):
        res = self._submit(src="any", dst="any", protocol="any", dst_ports="any")
        self.assertEqual(res.status_code, 422)
        body = res.get_json()
        self.assertEqual(body["state"], "rejected")
        self.assertIn(
            "ANY_TO_ANY_ALLOW", {f["code"] for f in body["findings"]}
        )

    def test_self_approval_returns_409(self):
        rid = self._submit().get_json()["request_id"]
        res = self.client.post(
            f"/api/requests/{rid}/approve", json={}, headers={"X-User": "alice"}
        )
        self.assertEqual(res.status_code, 409)

    def test_missing_user_header_rejected(self):
        res = self.client.post("/api/requests", json={"src": "10.0.0.0/24",
                                                      "dst": "10.1.0.1"})
        self.assertEqual(res.status_code, 403)

    def test_invalid_cidr_returns_400(self):
        res = self._submit(src="10.0.0.999/24")
        self.assertEqual(res.status_code, 400)

    def test_unknown_adapter_returns_400(self):
        rid = self._submit().get_json()["request_id"]
        self.client.post(f"/api/requests/{rid}/approve", json={},
                         headers={"X-User": "bob"})
        res = self.client.post(
            f"/api/requests/{rid}/deploy",
            json={"adapter": "cisco-asa"},
            headers={"X-User": "bob"},
        )
        self.assertEqual(res.status_code, 400)

    def test_audit_report_endpoint(self):
        res = self.client.get("/api/audit/report",
                              headers={"X-User": "carol"})
        self.assertEqual(res.status_code, 200)
        self.assertIn("findings", res.get_json())

    def test_deploy_with_fake_verifier(self):
        """verify=true 시 검증기를 통과해야만 배포되는 경로 (주입된 가짜 검증기)."""

        class FakeVerifier:
            def __init__(self, ok):
                self.ok = ok

            def verify(self, rendered, rules):
                from policygate.adapters.verify import VerificationResult
                return VerificationResult(
                    ok=self.ok, applied=True,
                    missing_rule_ids=[] if self.ok else ["FW-XXXX"],
                    default_policy_ok=True,
                )

        app = create_app(Store(":memory:"), verifier=FakeVerifier(ok=False))
        client = app.test_client()
        client.post("/api/users", json={"username": "a", "role": "requester"},
                    headers={"X-User": "admin"})
        client.post("/api/users", json={"username": "b", "role": "approver"},
                    headers={"X-User": "admin"})
        rid = client.post(
            "/api/requests",
            json={"src": "10.5.0.0/24", "dst": "10.9.0.10/32",
                  "protocol": "tcp", "dst_ports": "8080",
                  "description": "d"},
            headers={"X-User": "a"},
        ).get_json()["request_id"]
        client.post(f"/api/requests/{rid}/approve", json={},
                    headers={"X-User": "b"})
        res = client.post(
            f"/api/requests/{rid}/deploy",
            json={"adapter": "iptables", "verify": True},
            headers={"X-User": "b"},
        )
        # 검증 실패 → 배포 중단(409), 상태는 approved 유지
        self.assertEqual(res.status_code, 409)
        req = client.get(f"/api/requests/{rid}",
                         headers={"X-User": "b"}).get_json()
        self.assertEqual(req["state"], "approved")


if __name__ == "__main__":
    unittest.main()
