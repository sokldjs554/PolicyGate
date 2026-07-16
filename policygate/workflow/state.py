"""정책 신청 상태 머신.

방화벽 정책 변경은 반드시 다음 상태를 순서대로 통과해야 합니다.

  SUBMITTED ──(자동 검증 통과)──> PENDING_APPROVAL ──(승인)──> APPROVED ──(배포)──> DEPLOYED
      │                              │                                        │
      └──(critical 발견: 자동 반려)──> REJECTED <──(승인자 반려)──┘              └──(롤백)──> ROLLED_BACK

상태 전이를 화이트리스트로 강제하여 "검증을 건너뛴 배포",
"승인 없는 배포" 같은 우회를 코드 수준에서 차단합니다.
"""

from __future__ import annotations

from enum import Enum


class RequestState(str, Enum):
    SUBMITTED = "submitted"                # 접수됨 (자동 검증 전)
    PENDING_APPROVAL = "pending_approval"  # 자동 검증 통과, 승인 대기
    REJECTED = "rejected"                  # 자동 또는 수동 반려
    APPROVED = "approved"                  # 승인 완료, 배포 대기
    DEPLOYED = "deployed"                  # 방화벽에 반영 완료
    ROLLED_BACK = "rolled_back"            # 배포 후 회수(롤백)됨


# 허용되는 상태 전이 화이트리스트
ALLOWED_TRANSITIONS: dict[RequestState, set[RequestState]] = {
    RequestState.SUBMITTED: {RequestState.PENDING_APPROVAL, RequestState.REJECTED},
    RequestState.PENDING_APPROVAL: {RequestState.APPROVED, RequestState.REJECTED},
    RequestState.APPROVED: {RequestState.DEPLOYED, RequestState.REJECTED},
    RequestState.DEPLOYED: {RequestState.ROLLED_BACK},
    RequestState.REJECTED: set(),      # 종결 상태
    RequestState.ROLLED_BACK: set(),   # 종결 상태
}


def assert_transition(current: RequestState, target: RequestState) -> None:
    """허용되지 않은 상태 전이면 ValueError를 던진다."""
    if target not in ALLOWED_TRANSITIONS[current]:
        raise ValueError(
            f"허용되지 않은 상태 전이입니다: {current.value} -> {target.value}"
        )
