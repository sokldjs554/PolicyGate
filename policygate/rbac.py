"""RBAC — 역할 기반 접근 제어.

방화벽을 여닫는 시스템은 그 자체가 조직에서 가장 민감한 권한입니다.
"누가 무엇을 할 수 있는가"를 코드 여기저기의 if문이 아니라
**선언적 권한 매트릭스 한 곳**에 모아 강제합니다.

역할 설계 (최소 권한 원칙)
- REQUESTER : 정책을 신청하고 자기 신청을 조회한다. (모든 구성원의 기본 역할)
- REVIEWER  : 신청을 검토하고 반려할 수 있다. 승인 권한은 없다.
- APPROVER  : 승인/반려 및 승인된 신청의 배포를 수행한다.
- ADMIN     : 전체 권한 + 사용자 역할 관리, 정책 회수, 롤백.

설계 결정
- 역할은 클라이언트가 헤더로 주장하는 값이 아니라 **서버측 저장소(users
  테이블)에서 조회**합니다. 클라이언트가 역할을 자칭할 수 있으면 RBAC는
  장식일 뿐입니다.
- 인가 실패는 WorkflowError(409)와 구분되는 AccessDenied(→ 403)로 던져,
  "절차 위반"과 "권한 없음"을 감사 관점에서 분리합니다.
- 권한 확인 지점은 API 경계(api.py) 한 곳입니다. 도메인 서비스는 직무 분리
  (신청자 ≠ 승인자) 같은 '업무 불변식'만 담당합니다 — 인가 정책이 바뀌어도
  도메인 로직은 변하지 않습니다.
"""

from __future__ import annotations

from enum import Enum

from policygate.store import Store


class Role(str, Enum):
    REQUESTER = "requester"
    REVIEWER = "reviewer"
    APPROVER = "approver"
    ADMIN = "admin"


class AccessDenied(Exception):
    """권한 없음 (HTTP 403으로 매핑)."""


_ALL = {Role.REQUESTER, Role.REVIEWER, Role.APPROVER, Role.ADMIN}

#: 선언적 권한 매트릭스 — 이 파일이 곧 인가 정책의 단일 진실 공급원
PERMISSIONS: dict[str, set[Role]] = {
    "request.create":     _ALL,
    "request.view":       _ALL,
    "rule.view":          _ALL,
    "request.reject":     {Role.REVIEWER, Role.APPROVER, Role.ADMIN},
    "request.approve":    {Role.APPROVER, Role.ADMIN},
    "deploy.execute":     {Role.APPROVER, Role.ADMIN},
    "deploy.rollback":    {Role.ADMIN},
    "rule.decommission":  {Role.ADMIN},
    "audit.view":         {Role.REVIEWER, Role.APPROVER, Role.ADMIN},
    "user.manage":        {Role.ADMIN},
}


class RBAC:
    """저장소 기반 역할 관리 + 권한 판정."""

    def __init__(self, store: Store, bootstrap_admin: str = "admin"):
        self.store = store
        # 최초 기동 시 관리자 계정이 없으면 시스템이 잠겨버리므로
        # 사용자 테이블이 비어있을 때 1회에 한해 부트스트랩 관리자를 만든다.
        if not store.list_users():
            store.upsert_user(bootstrap_admin, Role.ADMIN.value, "system")
            store.audit(
                "system", "USER_BOOTSTRAPPED", bootstrap_admin,
                "최초 관리자 부트스트랩",
                before=None,
                after={"username": bootstrap_admin, "role": Role.ADMIN.value},
            )

    def role_of(self, username: str) -> Role | None:
        raw = self.store.get_user_role(username)
        return Role(raw) if raw else None

    def require(self, username: str, permission: str) -> Role:
        """username이 permission을 갖는지 확인. 없으면 AccessDenied."""
        if permission not in PERMISSIONS:
            raise ValueError(f"정의되지 않은 권한입니다: {permission}")
        role = self.role_of(username)
        if role is None:
            raise AccessDenied(f"등록되지 않은 사용자입니다: {username}")
        if role not in PERMISSIONS[permission]:
            raise AccessDenied(
                f"권한이 없습니다: {username}({role.value})에게는 "
                f"{permission} 권한이 필요합니다"
            )
        return role

    def assign(self, actor: str, username: str, role: Role | str) -> dict:
        """사용자 역할 부여/변경 (admin 전용). 변경 전/후를 감사에 남긴다."""
        self.require(actor, "user.manage")
        role = Role(role)
        old_role = self.store.get_user_role(username)
        self.store.upsert_user(username, role.value, actor)
        self.store.audit(
            actor, "USER_ROLE_ASSIGNED", username,
            before={"username": username, "role": old_role},
            after={"username": username, "role": role.value},
        )
        return {"username": username, "role": role.value, "previous_role": old_role}
