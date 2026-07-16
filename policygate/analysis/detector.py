"""방화벽 정책 셋 정적 분석 엔진.

운영 중인 방화벽 정책은 수년에 걸쳐 수백~수천 줄로 늘어나면서
다음과 같은 문제가 조용히 쌓입니다.

1. Shadowing   — 앞선 정책이 뒤 정책을 완전히 가려서, 뒤 정책이
                 절대 매칭되지 않는데 액션이 서로 달라 의도가 깨진 상태.
                 (예: 앞에서 allow한 트래픽을 뒤에서 deny하려 했지만 무효)
2. Redundancy  — 앞선 동일-액션 정책에 완전히 포함되어 존재 의미가 없는
                 정책. 장비 성능·가독성만 갉아먹는 정리 대상.
3. Correlation — 서로 부분적으로 겹치는데 액션이 달라, 정책 '순서'가
                 바뀌는 순간 동작이 달라지는 위험한 쌍.
4. 위험 노출    — any→any 허용, 인터넷 전체(0.0.0.0/0)에 위험 포트 오픈,
                 만료 지난 정책, 소유자 불명 정책 등 컴플라이언스 위반.

이 모듈은 first-match 의미론을 전제로 위 문제를 전수 탐지합니다.

정확성에 대한 노트
- Shadowing 판정은 보수적으로 '단일 선행 정책에 의한 완전 포함'만
  확정 판정합니다. 여러 선행 정책의 합집합에 의한 가림(union shadowing)은
  기하급수적 계산량을 요구하므로, 부분 겹침은 Correlation으로 분리 보고해
  거짓 양성(false positive)을 만들지 않는 쪽을 택했습니다.
  (감사 도구는 '확실한 것만 확정 보고'가 원칙이라고 판단했습니다)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from policygate.rule import Action, FirewallRule, Protocol

# 인터넷 전체에 노출되면 안 되는 대표적 위험 포트
RISKY_PORTS: dict[int, str] = {
    21: "FTP(평문 인증)",
    23: "Telnet(평문 원격 접속)",
    135: "MS-RPC",
    139: "NetBIOS",
    445: "SMB(랜섬웨어 주요 침투 경로)",
    1433: "MS-SQL",
    3306: "MySQL",
    3389: "RDP(무차별 대입 공격 표적)",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis(기본 무인증)",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class Finding:
    """분석 결과 한 건."""

    code: str                 # 예: "SHADOWED", "RISKY_PORT_EXPOSED"
    severity: Severity
    rule_id: str              # 문제가 되는 정책
    message: str
    related_rule_id: Optional[str] = None  # 원인이 되는 상대 정책

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "rule_id": self.rule_id,
            "related_rule_id": self.related_rule_id,
            "message": self.message,
        }


@dataclass
class AnalysisReport:
    """정책 셋 전체에 대한 분석 리포트."""

    findings: list[Finding] = field(default_factory=list)
    rule_count: int = 0
    analyzed_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings, key=lambda f: (_SEVERITY_ORDER[f.severity], f.rule_id)
        )

    def count_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def has_blocking_issues(self) -> bool:
        """배포를 차단해야 할 수준(critical)의 문제가 있는가."""
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "analyzed_at": self.analyzed_at.isoformat(),
            "rule_count": self.rule_count,
            "summary": self.count_by_severity(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }


class PolicyAnalyzer:
    """정책 셋 정적 분석기 (stateless).

    사용처가 두 곳입니다.
    1. 전체 감사: 운영 중인 정책 셋 전체를 주기적으로 스캔 (analyze)
    2. 사전 검증: 신규 정책 신청 1건이 기존 셋에 어떤 영향을 주는지
       배포 '전에' 검증 (validate_new_rule) — Policy-as-Code 게이트
    """

    # ------------------------------------------------------------------
    # 1) 전체 감사
    # ------------------------------------------------------------------

    def analyze(
        self, rules: list[FirewallRule], now: Optional[datetime] = None
    ) -> AnalysisReport:
        report = AnalysisReport(rule_count=len(rules))
        ordered = sorted(rules, key=lambda r: r.priority)

        report.findings.extend(self._detect_relations(ordered))
        for rule in ordered:
            report.findings.extend(self._check_rule_risk(rule, now=now))
        return report

    def detect_shadowed(self, rules: list[FirewallRule]) -> list[Finding]:
        """Shadowing만 골라 반환 (벤치마크/부분 감사용 공개 API)."""
        ordered = sorted(rules, key=lambda r: r.priority)
        return [f for f in self._detect_relations(ordered) if f.code == "SHADOWED"]

    def detect_redundant(self, rules: list[FirewallRule]) -> list[Finding]:
        """Redundancy만 골라 반환 (벤치마크/부분 감사용 공개 API)."""
        ordered = sorted(rules, key=lambda r: r.priority)
        return [f for f in self._detect_relations(ordered) if f.code == "REDUNDANT"]

    # ------------------------------------------------------------------
    # 2) 신규 정책 사전 검증
    # ------------------------------------------------------------------

    def validate_new_rule(
        self,
        new_rule: FirewallRule,
        existing: list[FirewallRule],
        now: Optional[datetime] = None,
    ) -> list[Finding]:
        """신규 정책 1건을 기존 정책 셋과 대조해 배포 전 검증한다.

        반환된 Finding 중 CRITICAL이 있으면 워크플로가 신청을 자동 반려하고,
        HIGH는 승인자 검토를 강제하며, 그 외는 참고 정보로 첨부됩니다.
        """
        findings = list(self._check_rule_risk(new_rule, now=now))
        ordered = sorted(existing, key=lambda r: r.priority)

        for old in ordered:
            if not new_rule.overlaps(old):
                continue

            if old.priority <= new_rule.priority and old.covers(new_rule):
                if old.action == new_rule.action:
                    findings.append(Finding(
                        code="DUPLICATE_OF_EXISTING",
                        severity=Severity.CRITICAL,
                        rule_id=new_rule.rule_id,
                        related_rule_id=old.rule_id,
                        message=(
                            f"기존 정책 {old.rule_id}이(가) 동일 트래픽을 이미 "
                            f"{old.action.value} 처리 중입니다. 중복 신청으로 반려합니다."
                        ),
                    ))
                else:
                    findings.append(Finding(
                        code="WILL_BE_SHADOWED",
                        severity=Severity.CRITICAL,
                        rule_id=new_rule.rule_id,
                        related_rule_id=old.rule_id,
                        message=(
                            f"선행 정책 {old.rule_id}({old.action.value})에 완전히 "
                            f"가려져 신규 정책이 절대 동작하지 않습니다. "
                            f"우선순위 조정 또는 기존 정책 변경이 필요합니다."
                        ),
                    ))
            elif old.action != new_rule.action:
                findings.append(Finding(
                    code="CONFLICT_OVERLAP",
                    severity=Severity.HIGH,
                    rule_id=new_rule.rule_id,
                    related_rule_id=old.rule_id,
                    message=(
                        f"정책 {old.rule_id}({old.action.value})과 트래픽이 부분적으로 "
                        f"겹치며 액션이 다릅니다. 평가 순서에 따라 동작이 달라지므로 "
                        f"승인자 확인이 필요합니다."
                    ),
                ))
        return findings

    # ------------------------------------------------------------------
    # 내부: 정책 간 관계 분석
    # ------------------------------------------------------------------

    def _detect_relations(self, ordered: list[FirewallRule]) -> list[Finding]:
        """우선순위 순으로 정렬된 정책 셋에서 쌍(pair) 관계를 전수 분석.

        O(n^2) 쌍 비교입니다. 안쪽 루프는 미리 계산한 정수 구간(bounds)으로
        src/dst가 겹치지 않는 쌍을 즉시 탈락시키므로(현실 정책 셋에서 쌍의
        대부분), 쌍당 비용은 수백 나노초 수준입니다 — 10,000줄(5천만 쌍)도
        수십 초 안에 처리됩니다(benchmarks/ 참고). 더 큰 규모의 개선 방향은
        ARCHITECTURE.md의 ADR-11(Trie/Interval Tree)에 정리했습니다.
        """
        findings: list[Finding] = []
        bounds = [r.bounds for r in ordered]  # (src_lo, src_hi, dst_lo, dst_hi)
        for j, later in enumerate(ordered):
            bj = bounds[j]
            for i in range(j):
                bi = bounds[i]
                # 빠른 탈락 경로: src 또는 dst 구간이 아예 겹치지 않으면
                # 이후의 모든 판정이 불필요 (정수 비교 4회)
                if (bi[0] > bj[1] or bj[0] > bi[1]
                        or bi[2] > bj[3] or bj[2] > bi[3]):
                    continue
                earlier = ordered[i]
                if not earlier.overlaps(later):
                    continue

                if earlier.covers(later):
                    if earlier.action == later.action:
                        findings.append(Finding(
                            code="REDUNDANT",
                            severity=Severity.MEDIUM,
                            rule_id=later.rule_id,
                            related_rule_id=earlier.rule_id,
                            message=(
                                f"선행 정책 {earlier.rule_id}에 완전히 포함되는 "
                                f"동일 액션 정책입니다. 삭제해도 동작이 변하지 않는 "
                                f"정리 대상입니다."
                            ),
                        ))
                    else:
                        findings.append(Finding(
                            code="SHADOWED",
                            severity=Severity.HIGH,
                            rule_id=later.rule_id,
                            related_rule_id=earlier.rule_id,
                            message=(
                                f"선행 정책 {earlier.rule_id}({earlier.action.value})에 "
                                f"가려져 절대 매칭되지 않습니다. "
                                f"이 정책의 의도({later.action.value})가 무효화된 상태입니다."
                            ),
                        ))
                    break  # 완전 포함 원인 1건이면 충분 (중복 보고 방지)

                if earlier.action != later.action:
                    findings.append(Finding(
                        code="CORRELATED",
                        severity=Severity.LOW,
                        rule_id=later.rule_id,
                        related_rule_id=earlier.rule_id,
                        message=(
                            f"정책 {earlier.rule_id}과 부분적으로 겹치고 액션이 "
                            f"다릅니다. 순서 변경 시 동작이 달라지므로 주의가 필요합니다."
                        ),
                    ))
        return findings

    # ------------------------------------------------------------------
    # 내부: 단일 정책 위험도 점검
    # ------------------------------------------------------------------

    def _check_rule_risk(
        self, rule: FirewallRule, now: Optional[datetime] = None
    ) -> list[Finding]:
        findings: list[Finding] = []
        src_is_any = rule.src == "0.0.0.0/0"
        dst_is_any = rule.dst == "0.0.0.0/0"
        ports_any = rule.dst_ports == ((1, 65535),)

        # 1) any -> any 허용: 방화벽을 무력화하는 최악의 정책
        if rule.action == Action.ALLOW and src_is_any and dst_is_any and (
            ports_any or rule.protocol == Protocol.ANY
        ):
            findings.append(Finding(
                code="ANY_TO_ANY_ALLOW",
                severity=Severity.CRITICAL,
                rule_id=rule.rule_id,
                message="출발지/목적지/포트 전체 허용 정책입니다. 방화벽을 사실상 무력화합니다.",
            ))

        # 2) 인터넷 전체(0.0.0.0/0)에서 위험 포트로의 허용
        if rule.action == Action.ALLOW and src_is_any and rule.protocol in (
            Protocol.TCP, Protocol.ANY
        ):
            exposed = [
                f"{port}({reason})"
                for port, reason in RISKY_PORTS.items()
                if any(lo <= port <= hi for lo, hi in rule.dst_ports)
            ]
            if exposed:
                findings.append(Finding(
                    code="RISKY_PORT_EXPOSED",
                    severity=Severity.CRITICAL,
                    rule_id=rule.rule_id,
                    message=(
                        "인터넷 전체(0.0.0.0/0)에 위험 포트가 노출됩니다: "
                        + ", ".join(exposed)
                    ),
                ))

        # 3) 과도하게 넓은 허용 포트 범위 (any 포트 허용인데 any->any는 아님)
        if (
            rule.action == Action.ALLOW
            and ports_any
            and rule.protocol != Protocol.ICMP
            and not (src_is_any and dst_is_any)
        ):
            findings.append(Finding(
                code="ALL_PORTS_OPEN",
                severity=Severity.MEDIUM,
                rule_id=rule.rule_id,
                message="전체 포트(1-65535)를 허용합니다. 필요한 포트만 명시하세요.",
            ))

        # 4) 만료된 정책이 아직 살아있는 경우
        if rule.is_expired(now):
            findings.append(Finding(
                code="EXPIRED_RULE",
                severity=Severity.HIGH,
                rule_id=rule.rule_id,
                message=(
                    f"만료일({rule.expires_at:%Y-%m-%d})이 지난 정책입니다. "
                    f"즉시 회수(삭제)가 필요합니다."
                ),
            ))

        # 5) 거버넌스: 소유자/설명 누락 — 정책 회수가 불가능해지는 원인
        if not rule.owner:
            findings.append(Finding(
                code="MISSING_OWNER",
                severity=Severity.LOW,
                rule_id=rule.rule_id,
                message="정책 소유자가 지정되지 않았습니다. 회수 판단이 불가능해집니다.",
            ))
        if not rule.description:
            findings.append(Finding(
                code="MISSING_DESCRIPTION",
                severity=Severity.LOW,
                rule_id=rule.rule_id,
                message="정책 목적 설명이 없습니다.",
            ))

        return findings
