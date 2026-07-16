"""REST API (Flask) — RBAC로 보호되는 워크플로 엔드포인트.

정책 신청/승인/배포 워크플로를 HTTP로 노출합니다.
사내 포털·챗봇·CI 파이프라인 등 어떤 클라이언트든 이 API를 통해
동일한 검증 게이트와 동일한 권한 통제를 통과하게 만드는 것이 목적입니다.

엔드포인트 요약 (괄호는 필요한 권한)
  POST   /api/requests                  정책 신청 (request.create)
  GET    /api/requests                  신청 목록 (request.view)
  GET    /api/requests/<id>             신청 상세 (request.view)
  POST   /api/requests/<id>/approve     승인 (request.approve — Approver+)
  POST   /api/requests/<id>/reject      반려 (request.reject — Reviewer+)
  POST   /api/requests/<id>/deploy      배포 (deploy.execute — Approver+)
                                        ?dry_run=true / body {"verify": true}
  POST   /api/requests/<id>/rollback    배포 롤백 (deploy.rollback — Admin)
  GET    /api/rules                     활성 정책 목록 (rule.view)
  DELETE /api/rules/<rule_id>           정책 회수 (rule.decommission — Admin)
  GET    /api/audit/report              정책 셋 감사 리포트 (audit.view)
  GET    /api/audit/trail               감사 로그 (audit.view)
  GET    /api/users                     사용자 목록 (user.manage — Admin)
  POST   /api/users                     역할 부여/변경 (user.manage — Admin)
  GET    /api/roles                     권한 매트릭스 조회 (모든 등록 사용자)

인증/인가 구조
- 인증(누구인가): 데모에서는 X-User 헤더. 실서비스는 SSO(OIDC)로 교체하며
  그 경계는 _actor() 하나에 격리되어 있습니다.
- 인가(무엇을 할 수 있는가): 역할은 클라이언트 주장이 아닌 서버측 users
  테이블에서 조회하고, 선언적 권한 매트릭스(rbac.PERMISSIONS)로 판정합니다.
- 오류 매핑: 권한 없음 403 / 절차 위반 409 / 입력 오류 400 / 검증 반려 422.
"""

from __future__ import annotations

from datetime import datetime, timezone

from flask import Flask, jsonify, request

from policygate.adapters import IptablesAdapter, NamespaceVerifier, NftablesAdapter
from policygate.rbac import PERMISSIONS, RBAC, AccessDenied
from policygate.store import Store
from policygate.workflow import PolicyService, WorkflowError

ADAPTERS = {
    "iptables": IptablesAdapter,
    "nftables": NftablesAdapter,
}


def create_app(store: Store | None = None, verifier=None) -> Flask:
    """앱 팩토리.

    테스트에서 격리된 인메모리 store와 가짜 verifier를 주입할 수 있습니다.
    verifier=None이면 배포 시 verify 요청이 왔을 때 NamespaceVerifier
    가용 여부를 확인해 사용합니다.
    """
    app = Flask(__name__)
    store = store or Store()
    service = PolicyService(store)
    rbac = RBAC(store)

    def _actor() -> str:
        actor = request.headers.get("X-User", "").strip()
        if not actor:
            raise AccessDenied("X-User 헤더로 행위자를 지정해야 합니다")
        return actor

    def _require(permission: str) -> str:
        """행위자를 식별하고 권한을 검사한 뒤 username을 반환."""
        actor = _actor()
        rbac.require(actor, permission)
        return actor

    # ---------------- 신청 ----------------

    @app.post("/api/requests")
    def create_request():
        actor = _require("request.create")
        body = request.get_json(silent=True) or {}
        expires = None
        if body.get("expires_at"):
            expires = datetime.fromisoformat(body["expires_at"])
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
        req = service.submit_request(
            requester=actor,
            src=body.get("src", ""),
            dst=body.get("dst", ""),
            protocol=body.get("protocol", "tcp"),
            dst_ports=body.get("dst_ports", "any"),
            action=body.get("action", "allow"),
            priority=int(body.get("priority", 100)),
            description=body.get("description", ""),
            expires_at=expires,
            reason=body.get("reason", ""),
        )
        status = 201 if req["state"] != "rejected" else 422
        return jsonify(req), status

    @app.get("/api/requests")
    def list_requests():
        _require("request.view")
        return jsonify(service.store.list_requests(request.args.get("state")))

    @app.get("/api/requests/<request_id>")
    def get_request(request_id: str):
        _require("request.view")
        req = service.store.get_request(request_id)
        if req is None:
            return jsonify({"error": f"존재하지 않는 신청: {request_id}"}), 404
        return jsonify(req)

    # ---------------- 승인 / 반려 ----------------

    @app.post("/api/requests/<request_id>/approve")
    def approve(request_id: str):
        actor = _require("request.approve")
        body = request.get_json(silent=True) or {}
        return jsonify(service.approve(request_id, actor, body.get("note", "")))

    @app.post("/api/requests/<request_id>/reject")
    def reject(request_id: str):
        actor = _require("request.reject")
        body = request.get_json(silent=True) or {}
        return jsonify(service.reject(request_id, actor, body.get("note", "")))

    # ---------------- 배포 / 롤백 ----------------

    @app.post("/api/requests/<request_id>/deploy")
    def deploy(request_id: str):
        actor = _require("deploy.execute")
        body = request.get_json(silent=True) or {}
        adapter_name = body.get("adapter", "iptables")
        if adapter_name not in ADAPTERS:
            return jsonify({
                "error": f"지원하지 않는 어댑터: {adapter_name}",
                "supported": sorted(ADAPTERS),
            }), 400
        dry_run = request.args.get("dry_run", "").lower() in ("1", "true", "yes")

        # verify=true: 격리 namespace에서 커널 적용 검증 후 배포
        use_verifier = None
        if body.get("verify"):
            use_verifier = verifier
            if use_verifier is None:
                if adapter_name != "iptables":
                    return jsonify({
                        "error": "namespace 검증은 현재 iptables 어댑터만 지원합니다"
                    }), 400
                if not NamespaceVerifier.available():
                    return jsonify({
                        "error": "이 환경에서는 namespace 검증을 사용할 수 없습니다 "
                                 "(unshare/iptables-restore 필요)"
                    }), 400
                use_verifier = NamespaceVerifier()

        adapter = ADAPTERS[adapter_name]()
        result = service.deploy(
            request_id, adapter, actor, dry_run=dry_run, verifier=use_verifier
        )
        return jsonify(result)

    @app.post("/api/requests/<request_id>/rollback")
    def rollback(request_id: str):
        actor = _require("deploy.rollback")
        body = request.get_json(silent=True) or {}
        return jsonify(service.rollback(request_id, actor, body.get("note", "")))

    # ---------------- 정책 / 감사 ----------------

    @app.get("/api/rules")
    def list_rules():
        _require("rule.view")
        return jsonify([r.to_dict() for r in service.store.active_rules()])

    @app.delete("/api/rules/<rule_id>")
    def decommission(rule_id: str):
        actor = _require("rule.decommission")
        body = request.get_json(silent=True) or {}
        service.decommission_rule(rule_id, actor, body.get("note", ""))
        return jsonify({"rule_id": rule_id, "status": "decommissioned"})

    @app.get("/api/audit/report")
    def audit_report():
        _require("audit.view")
        return jsonify(service.audit_current_ruleset())

    @app.get("/api/audit/trail")
    def audit_trail():
        _require("audit.view")
        return jsonify(service.store.audit_trail(request.args.get("target")))

    # ---------------- 사용자 / 역할 ----------------

    @app.get("/api/users")
    def list_users():
        _require("user.manage")
        return jsonify(store.list_users())

    @app.post("/api/users")
    def assign_role():
        actor = _require("user.manage")
        body = request.get_json(silent=True) or {}
        username = (body.get("username") or "").strip()
        role = (body.get("role") or "").strip()
        if not username or not role:
            return jsonify({"error": "username과 role은 필수입니다"}), 400
        return jsonify(rbac.assign(actor, username, role)), 201

    @app.get("/api/roles")
    def roles_matrix():
        # 자신의 역할과 전체 권한 매트릭스 조회 (등록 사용자 누구나)
        actor = _actor()
        role = rbac.role_of(actor)
        if role is None:
            raise AccessDenied(f"등록되지 않은 사용자입니다: {actor}")
        return jsonify({
            "you": {"username": actor, "role": role.value},
            "permissions": {
                perm: sorted(r.value for r in roles)
                for perm, roles in PERMISSIONS.items()
            },
        })

    # ---------------- 오류 처리 ----------------

    @app.errorhandler(AccessDenied)
    def access_denied(e: AccessDenied):
        return jsonify({"error": str(e)}), 403

    @app.errorhandler(WorkflowError)
    def workflow_error(e: WorkflowError):
        return jsonify({"error": str(e)}), 409

    @app.errorhandler(ValueError)
    def value_error(e: ValueError):
        return jsonify({"error": str(e)}), 400

    # 서비스/RBAC 객체를 테스트에서 접근할 수 있도록 노출
    app.extensions["policy_service"] = service
    app.extensions["rbac"] = rbac
    return app


if __name__ == "__main__":
    create_app(Store("policygate.db")).run(host="127.0.0.1", port=8080, debug=False)
