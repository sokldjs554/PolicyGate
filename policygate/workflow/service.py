"""정책 라이프사이클 서비스 (워크플로의 두뇌).

수작업 방화벽 운영의 문제:
- 신청서(메일/티켓) → 담당자가 눈으로 검토 → 콘솔에서 수동 입력
- 사람이 병목이고, 중복/충돌 정책 검토가 담당자 기억력에 의존하며,
  누가 언제 왜 넣었는지 이력이 흩어짐

PolicyService는 이 과정을 코드로 대체합니다:
1. submit_request  — 신청 즉시 분석 엔진으로 자동 검증.
                     critical 발견 시 사람 개입 없이 즉시 반려(사유 포함).
2. approve/reject  — 검증을 통과한 건만 승인자에게 도달. 셀프 승인 금지.
3. deploy          — 승인된 정책만 어댑터를 통해 배포. dry-run 지원.
4. 모든 단계는 감사 로그에 불변 기록.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from policygate.adapters.base import FirewallAdapter
from policygate.analysis.detector import PolicyAnalyzer, Severity
from policygate.rule import FirewallRule
from policygate.store import Store
from policygate.workflow.state import RequestState, assert_transition


class WorkflowError(Exception):
    """워크플로 규칙 위반 (잘못된 상태 전이, 권한 위반 등)."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class PolicyService:
    def __init__(self, store: Store, analyzer: Optional[PolicyAnalyzer] = None):
        self.store = store
        self.analyzer = analyzer or PolicyAnalyzer()

    # ------------------------------------------------------------------
    # 1) 신청 + 자동 검증
    # ------------------------------------------------------------------

    def submit_request(
        self,
        requester: str,
        src: str,
        dst: str,
        protocol: str = "tcp",
        dst_ports: str = "any",
        action: str = "allow",
        priority: int = 100,
        description: str = "",
        expires_at: Optional[datetime] = None,
        reason: str = "",
    ) -> dict[str, Any]:
        """정책 신청을 접수하고 즉시 자동 검증한다.

        반환된 dict의 state가 'pending_approval'이면 검증 통과,
        'rejected'이면 자동 반려(findings에 사유가 담김)입니다.
        """
        if not requester:
            raise WorkflowError("신청자(requester)는 필수입니다")

        rule = FirewallRule.create(
            rule_id=self.store.next_rule_id(),
            src=src,
            dst=dst,
            protocol=protocol,
            dst_ports=dst_ports,
            action=action,
            priority=priority,
            description=description,
            owner=requester,
            expires_at=expires_at,
        )

        request_id = self.store.next_request_id()
        req: dict[str, Any] = {
            "request_id": request_id,
            "rule": rule.to_dict(),
            "requester": requester,
            "reason": reason,
            "state": RequestState.SUBMITTED.value,
            "findings": [],
            "reviewer": None,
            "review_note": None,
            "created_at": _now(),
            "updated_at": _now(),
        }
        self.store.audit(
            requester, "REQUEST_CREATED", request_id, rule.summary(),
            before=None, after=rule.to_dict(),
        )

        # --- 자동 검증 (Policy-as-Code 게이트) ---
        findings = self.analyzer.validate_new_rule(rule, self.store.active_rules())
        req["findings"] = [f.to_dict() for f in findings]

        has_critical = any(f.severity == Severity.CRITICAL for f in findings)
        if has_critical:
            req["state"] = RequestState.REJECTED.value
            req["review_note"] = "자동 반려: 검증 규칙 위반 (findings 참고)"
            self.store.audit(
                "policygate-validator", "REQUEST_AUTO_REJECTED", request_id,
                "; ".join(f.message for f in findings if f.severity == Severity.CRITICAL),
            )
        else:
            req["state"] = RequestState.PENDING_APPROVAL.value
            self.store.audit(
                "policygate-validator", "REQUEST_VALIDATED", request_id,
                f"발견 {len(findings)}건, 승인 대기로 전환",
            )

        req["updated_at"] = _now()
        self.store.save_request(req)
        self.store.audit(
            "policygate-validator", "REQUEST_STATE_CHANGED", request_id,
            before={"state": RequestState.SUBMITTED.value},
            after={"state": req["state"]},
        )
        return req

    # ------------------------------------------------------------------
    # 2) 승인 / 반려
    # ------------------------------------------------------------------

    def approve(self, request_id: str, reviewer: str, note: str = "") -> dict[str, Any]:
        req = self._get_request_or_raise(request_id)
        if reviewer == req["requester"]:
            # 직무 분리(Separation of Duties): 신청자 본인은 승인 불가
            raise WorkflowError("신청자 본인은 승인할 수 없습니다 (직무 분리 원칙)")
        old_state = self._transition(req, RequestState.APPROVED)
        req["reviewer"] = reviewer
        req["review_note"] = note
        self.store.save_request(req)
        self.store.audit(
            reviewer, "REQUEST_APPROVED", request_id, note,
            before={"state": old_state}, after={"state": req["state"]},
        )
        return req

    def reject(self, request_id: str, reviewer: str, note: str = "") -> dict[str, Any]:
        req = self._get_request_or_raise(request_id)
        old_state = self._transition(req, RequestState.REJECTED)
        req["reviewer"] = reviewer
        req["review_note"] = note
        self.store.save_request(req)
        self.store.audit(
            reviewer, "REQUEST_REJECTED", request_id, note,
            before={"state": old_state}, after={"state": req["state"]},
        )
        return req

    # ------------------------------------------------------------------
    # 3) 배포
    # ------------------------------------------------------------------

    def deploy(
        self, request_id: str, adapter: FirewallAdapter, actor: str,
        dry_run: bool = False, verifier=None,
    ) -> dict[str, Any]:
        """승인된 신청을 방화벽에 반영한다.

        dry_run=True 이면 실제 반영 없이 생성될 설정만 반환합니다.
        (변경 작업 전 리뷰용 — 실무에서 가장 많이 쓰는 기능)

        verifier가 주어지면 배포 '전에' 격리된 network namespace에서
        설정을 실제 커널에 적용해 검증하고, 실패 시 배포를 중단합니다.
        검증 실패는 상태를 바꾸지 않으므로(approved 유지) 원인 수정 후
        재배포할 수 있습니다.
        """
        req = self._get_request_or_raise(request_id)
        if req["state"] != RequestState.APPROVED.value:
            raise WorkflowError(
                f"승인(approved) 상태의 신청만 배포할 수 있습니다 "
                f"(현재: {req['state']})"
            )

        rule = self._rule_from_snapshot(req["rule"])
        target_rules = sorted(
            self.store.active_rules() + [rule], key=lambda r: (r.priority, r.rule_id)
        )
        rendered = adapter.render(target_rules)

        if dry_run:
            self.store.audit(actor, "DEPLOY_DRY_RUN", request_id, adapter.name)
            return {"request": req, "dry_run": True, "rendered": rendered}

        verification = None
        if verifier is not None:
            result = verifier.verify(rendered, target_rules)
            verification = {
                "ok": result.ok,
                "applied": result.applied,
                "missing_rule_ids": result.missing_rule_ids,
                "summary": result.summary(),
            }
            if not result.ok:
                self.store.audit(
                    actor, "DEPLOY_VERIFY_FAILED", request_id, result.summary()
                )
                raise WorkflowError(f"배포 사전 검증 실패: {result.summary()}")
            self.store.audit(
                actor, "DEPLOY_VERIFIED", request_id,
                "격리 namespace에서 커널 적용 검증 통과",
            )

        adapter.deploy(target_rules)
        self.store.add_rule(rule)
        old_state = self._transition(req, RequestState.DEPLOYED)
        self.store.save_request(req)
        self.store.audit(
            actor, "RULE_DEPLOYED", rule.rule_id,
            f"{adapter.name} 배포 완료 / 신청 {request_id}",
            before=None,
            after=rule.to_dict(),
        )
        self.store.audit(
            actor, "REQUEST_STATE_CHANGED", request_id,
            before={"state": old_state}, after={"state": req["state"]},
        )
        return {
            "request": req, "dry_run": False, "rendered": rendered,
            "verification": verification,
        }

    def rollback(self, request_id: str, actor: str, note: str = "") -> dict[str, Any]:
        """배포된 정책을 회수(롤백)한다.

        배포가 곧 사고로 이어질 수 있는 시스템에서 되돌리기는 배포만큼
        중요한 1급 기능입니다. 롤백도 배포와 동일하게 상태 머신을 통과하고
        (deployed -> rolled_back), 변경 전/후가 감사에 남습니다.
        """
        req = self._get_request_or_raise(request_id)
        rule_id = req["rule"]["rule_id"]
        rule = self.store.get_rule(rule_id)
        old_state = self._transition(req, RequestState.ROLLED_BACK)  # 상태 검증 먼저

        if not self.store.deactivate_rule(rule_id):
            raise WorkflowError(f"활성 정책이 아니어서 롤백할 수 없습니다: {rule_id}")
        self.store.save_request(req)

        before = rule.to_dict() if rule else {"rule_id": rule_id}
        before["active"] = True
        after = dict(before, active=False)
        self.store.audit(
            actor, "DEPLOY_ROLLED_BACK", rule_id,
            note or f"신청 {request_id} 롤백",
            before=before, after=after,
        )
        self.store.audit(
            actor, "REQUEST_STATE_CHANGED", request_id,
            before={"state": old_state}, after={"state": req["state"]},
        )
        return req

    # ------------------------------------------------------------------
    # 4) 회수(정책 삭제) 및 감사
    # ------------------------------------------------------------------

    def decommission_rule(self, rule_id: str, actor: str, note: str = "") -> None:
        """정책 회수. 만료·불용 정책 정리는 신설만큼 중요합니다."""
        rule = self.store.get_rule(rule_id)
        if not self.store.deactivate_rule(rule_id):
            raise WorkflowError(f"활성 정책이 아닙니다: {rule_id}")
        before = rule.to_dict() if rule else {"rule_id": rule_id}
        before["active"] = True
        self.store.audit(
            actor, "RULE_DECOMMISSIONED", rule_id, note,
            before=before, after=dict(before, active=False),
        )

    def audit_current_ruleset(self) -> dict[str, Any]:
        """운영 중인 전체 정책 셋 감사 리포트."""
        report = self.analyzer.analyze(self.store.active_rules())
        return report.to_dict()

    def expired_rules(self) -> list[FirewallRule]:
        """만료된 활성 정책 목록 (자동 회수 배치의 입력)."""
        return [r for r in self.store.active_rules() if r.is_expired()]

    # ------------------------------------------------------------------
    # 내부 헬퍼
    # ------------------------------------------------------------------

    def _get_request_or_raise(self, request_id: str) -> dict[str, Any]:
        req = self.store.get_request(request_id)
        if req is None:
            raise WorkflowError(f"존재하지 않는 신청입니다: {request_id}")
        return req

    @staticmethod
    def _transition(req: dict[str, Any], target: RequestState) -> str:
        """상태 전이를 수행하고 이전 상태를 반환한다 (감사 기록용)."""
        old = req["state"]
        try:
            assert_transition(RequestState(old), target)
        except ValueError as e:
            raise WorkflowError(str(e)) from e
        req["state"] = target.value
        req["updated_at"] = _now()
        return old

    @staticmethod
    def _rule_from_snapshot(snapshot: dict[str, Any]) -> FirewallRule:
        expires = (
            datetime.fromisoformat(snapshot["expires_at"])
            if snapshot.get("expires_at") else None
        )
        return FirewallRule.create(
            rule_id=snapshot["rule_id"],
            src=snapshot["src"],
            dst=snapshot["dst"],
            protocol=snapshot["protocol"],
            dst_ports=snapshot["dst_ports"],
            action=snapshot["action"],
            priority=snapshot["priority"],
            description=snapshot["description"],
            owner=snapshot["owner"],
            expires_at=expires,
        )
