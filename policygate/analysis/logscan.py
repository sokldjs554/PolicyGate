"""방화벽 로그 기반 정책 사용 현황 분석.

정책 위생(hygiene)의 마지막 조각은 "이 정책, 실제로 쓰이고는 있나?"입니다.
정적 분석(detector)은 정책 셋 내부의 모순을 찾지만, 한 번도 매칭되지 않는
정책(과거 서비스의 유령 정책)은 트래픽 로그와 대조해야만 찾을 수 있습니다.

동작 방식
1. iptables 스타일 syslog 라인에서 SRC/DST/PROTO/DPT를 추출해 Packet으로 변환
2. 각 패킷을 first-match 시뮬레이터에 흘려 정책별 히트 카운트 집계
3. 리포트 산출:
   - 미사용(hit=0) allow 정책  → 회수 검토 대상
   - 정책별 히트 카운트        → 우선순위 재배치 근거 (핫한 정책을 앞으로)
   - 기본 차단된 트래픽 상위    → 미허용 접근 시도 (설정 누락 또는 공격 시도)

정확성에 대한 노트
- "미사용" 판정은 로그가 관측한 기간에 한정됩니다. 분기 배치처럼 드물게
  쓰이는 정책이 있으므로, 리포트는 삭제가 아니라 '회수 검토'를 권고합니다.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Optional

from policygate.analysis.simulator import Packet, first_match
from policygate.rule import Action, FirewallRule

# iptables LOG 타깃이 남기는 syslog 라인에서 필요한 필드만 추출
# 예: "Jul 12 03:22:01 fw1 kernel: PGATE SRC=10.0.1.5 DST=10.20.0.10 ... PROTO=TCP SPT=51514 DPT=443 ..."
_LOG_PATTERN = re.compile(
    r"SRC=(?P<src>\d+\.\d+\.\d+\.\d+)\s+"
    r"DST=(?P<dst>\d+\.\d+\.\d+\.\d+)"
    r".*?PROTO=(?P<proto>\w+)"
    r"(?:.*?DPT=(?P<dpt>\d+))?"
)


def parse_log_line(line: str) -> Optional[Packet]:
    """syslog 라인 1줄 → Packet. 형식이 안 맞으면 None (관대한 파싱).

    로그는 외부에서 오는 신뢰할 수 없는 입력이므로, 깨진 라인 때문에
    분석 전체가 중단되지 않도록 파싱 실패는 건너뜁니다(카운트만 유지).
    """
    m = _LOG_PATTERN.search(line)
    if not m:
        return None
    proto = m.group("proto").lower()
    if proto not in ("tcp", "udp", "icmp"):
        return None
    dpt = m.group("dpt")
    try:
        return Packet(
            src_ip=m.group("src"),
            dst_ip=m.group("dst"),
            protocol=proto,
            dst_port=int(dpt) if dpt else None,
        )
    except ValueError:
        return None


@dataclass
class UsageReport:
    """로그 대조 분석 결과."""

    total_lines: int = 0
    parsed_packets: int = 0
    hit_counts: dict[str, int] = field(default_factory=dict)   # rule_id -> hits
    unused_allow_rules: list[str] = field(default_factory=list)
    default_denied: Counter = field(default_factory=Counter)   # (src,dst,proto,port) -> count

    def to_dict(self) -> dict:
        return {
            "total_lines": self.total_lines,
            "parsed_packets": self.parsed_packets,
            "hit_counts": self.hit_counts,
            "unused_allow_rules": self.unused_allow_rules,
            "default_denied_top": [
                {"flow": flow, "count": count}
                for flow, count in self.default_denied.most_common(10)
            ],
        }


def analyze_usage(
    rules: list[FirewallRule], log_lines: Iterable[str]
) -> UsageReport:
    """로그 스트림을 정책 셋과 대조해 사용 현황을 집계한다.

    메모리에 로그 전체를 올리지 않는 스트리밍 처리이므로
    대용량 로그 파일에도 그대로 사용할 수 있습니다.
    """
    report = UsageReport(hit_counts={r.rule_id: 0 for r in rules})

    for line in log_lines:
        report.total_lines += 1
        packet = parse_log_line(line)
        if packet is None:
            continue
        report.parsed_packets += 1

        result = first_match(rules, packet)
        if result.matched_rule is not None:
            report.hit_counts[result.matched_rule.rule_id] += 1
        else:
            port = packet.dst_port if packet.dst_port else "-"
            report.default_denied[
                f"{packet.src_ip} -> {packet.dst_ip} {packet.protocol}/{port}"
            ] += 1

    report.unused_allow_rules = [
        r.rule_id
        for r in sorted(rules, key=lambda r: (r.priority, r.rule_id))
        if r.action == Action.ALLOW and report.hit_counts.get(r.rule_id, 0) == 0
    ]
    return report
