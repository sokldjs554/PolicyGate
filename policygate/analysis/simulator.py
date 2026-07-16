"""정책 시뮬레이터 — "이 트래픽, 지금 허용되나요?"에 코드로 답한다.

방화벽 운영에서 가장 자주 받는 질문이 "A에서 B로 통신이 되나요/왜 안 되나요"
입니다. 장비에 들어가 정책을 눈으로 따라가는 대신, first-match 의미론을
그대로 시뮬레이션해서 어떤 정책에 걸리는지 즉시 답합니다.

이 시뮬레이터는 로그 분석(logscan)의 기반이기도 합니다:
로그의 각 패킷을 정책 셋에 흘려보내 히트 카운트를 계산합니다.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional

from policygate.rule import FirewallRule, Protocol


@dataclass(frozen=True)
class Packet:
    """시뮬레이션 대상 트래픽 한 건 (5-tuple 중 매칭에 필요한 필드)."""

    src_ip: str
    dst_ip: str
    protocol: str  # "tcp" | "udp" | "icmp"
    dst_port: Optional[int] = None  # icmp면 None

    def __post_init__(self):
        # 잘못된 입력은 생성 시점에 즉시 실패시킨다
        ipaddress.ip_address(self.src_ip)
        ipaddress.ip_address(self.dst_ip)
        proto = self.protocol.lower()
        if proto not in ("tcp", "udp", "icmp"):
            raise ValueError(f"지원하지 않는 프로토콜: {self.protocol}")
        object.__setattr__(self, "protocol", proto)
        if proto == "icmp":
            object.__setattr__(self, "dst_port", None)
        elif self.dst_port is None or not (1 <= int(self.dst_port) <= 65535):
            raise ValueError("tcp/udp 패킷에는 1-65535 범위의 dst_port가 필요합니다")


@dataclass(frozen=True)
class MatchResult:
    """시뮬레이션 결과."""

    packet: Packet
    matched_rule: Optional[FirewallRule]  # None = 어떤 정책에도 안 걸림
    allowed: bool                          # 최종 판정 (기본 차단 반영)

    @property
    def verdict(self) -> str:
        if self.matched_rule is None:
            return "기본 차단 (deny-by-default, 매칭 정책 없음)"
        return (
            f"{self.matched_rule.action.value.upper()} "
            f"(정책 {self.matched_rule.rule_id}: {self.matched_rule.description or '설명 없음'})"
        )


def rule_matches_packet(rule: FirewallRule, packet: Packet) -> bool:
    """정책 한 줄이 패킷 한 건에 매칭되는지 판정."""
    # 프로토콜
    if rule.protocol != Protocol.ANY and rule.protocol.value != packet.protocol:
        return False
    # 출발지/목적지
    if ipaddress.ip_address(packet.src_ip) not in rule.src_net:
        return False
    if ipaddress.ip_address(packet.dst_ip) not in rule.dst_net:
        return False
    # 포트 (icmp는 포트 개념 없음)
    if packet.protocol != "icmp":
        if not any(lo <= packet.dst_port <= hi for lo, hi in rule.dst_ports):
            return False
    return True


def first_match(rules: list[FirewallRule], packet: Packet) -> MatchResult:
    """우선순위 순으로 정책을 평가해 처음 매칭되는 정책을 반환.

    실제 방화벽과 동일한 first-match 의미론이며,
    아무 정책에도 매칭되지 않으면 기본 차단(deny-by-default)입니다.
    (어댑터가 생성하는 설정의 기본 정책과 일치해야 합니다 — 테스트로 고정)
    """
    for rule in sorted(rules, key=lambda r: (r.priority, r.rule_id)):
        if rule_matches_packet(rule, packet):
            from policygate.rule import Action

            return MatchResult(
                packet=packet,
                matched_rule=rule,
                allowed=(rule.action == Action.ALLOW),
            )
    return MatchResult(packet=packet, matched_rule=None, allowed=False)
