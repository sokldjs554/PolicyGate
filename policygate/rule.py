"""방화벽 정책(Rule) 도메인 모델.

방화벽 정책 분석의 핵심은 "한 정책이 다른 정책을 포함(cover)하는가,
겹치는(overlap)가"를 정확하게 판정하는 것입니다. 이 모듈은
5-tuple(출발지, 목적지, 프로토콜, 목적지 포트, 액션) 기반의
포함/중첩 관계 연산을 표준 라이브러리(ipaddress)만으로 구현합니다.

설계 원칙
- 벤더 중립: iptables든 상용 방화벽이든 결국 5-tuple 매칭이라는
  동일한 의미론을 가지므로, 분석은 벤더 독립적인 이 모델 위에서 수행하고
  벤더별 문법 변환은 adapters 계층에 위임합니다.
- 불변(immutable) 객체: 분석 도중 정책이 변형되는 실수를 방지합니다.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Action(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"

    def covers(self, other: "Protocol") -> bool:
        """이 프로토콜이 other 프로토콜의 트래픽을 전부 포함하는가."""
        return self == Protocol.ANY or self == other

    def overlaps(self, other: "Protocol") -> bool:
        """두 프로토콜에 공통으로 매칭되는 트래픽이 존재하는가."""
        return self == Protocol.ANY or other == Protocol.ANY or self == other


# 포트 범위: (시작, 끝) 폐구간. any = (1, 65535)
PortRange = tuple[int, int]
PORT_MIN, PORT_MAX = 1, 65535
ANY_PORTS: tuple[PortRange, ...] = ((PORT_MIN, PORT_MAX),)


def parse_ports(spec: str) -> tuple[PortRange, ...]:
    """포트 명세 문자열을 정규화된 포트 범위 목록으로 파싱.

    지원 형식: "any", "443", "80,443", "8000-8100", "22,8000-8100"
    반환값은 병합(merge)·정렬된 겹치지 않는 구간 목록이므로
    이후의 포함/중첩 판정이 단순한 구간 연산으로 환원됩니다.
    """
    spec = (spec or "any").strip().lower()
    if spec in ("any", "*", ""):
        return ANY_PORTS

    ranges: list[PortRange] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
        else:
            lo = hi = int(part)
        if not (PORT_MIN <= lo <= hi <= PORT_MAX):
            raise ValueError(f"잘못된 포트 범위: {part!r}")
        ranges.append((lo, hi))
    if not ranges:
        raise ValueError(f"포트 명세를 해석할 수 없습니다: {spec!r}")
    return merge_ranges(ranges)


def merge_ranges(ranges: list[PortRange]) -> tuple[PortRange, ...]:
    """겹치거나 인접한 포트 구간을 병합해 정규형으로 만든다."""
    ranges = sorted(ranges)
    merged: list[PortRange] = [ranges[0]]
    for lo, hi in ranges[1:]:
        last_lo, last_hi = merged[-1]
        if lo <= last_hi + 1:  # 겹침 또는 인접(예: 80-81, 82-90)
            merged[-1] = (last_lo, max(last_hi, hi))
        else:
            merged.append((lo, hi))
    return tuple(merged)


def ports_cover(a: tuple[PortRange, ...], b: tuple[PortRange, ...]) -> bool:
    """포트 집합 a가 b를 완전히 포함하는가.

    두 입력 모두 정규형(정렬·병합됨)을 전제로 하는 O(n+m) 투 포인터 스캔.
    """
    i = 0
    for b_lo, b_hi in b:
        # b의 구간 하나가 a의 단일 구간 안에 완전히 들어가야 함
        # (a는 병합된 정규형이므로 두 구간에 걸쳐 있을 수 없음)
        while i < len(a) and a[i][1] < b_lo:
            i += 1
        if i >= len(a) or not (a[i][0] <= b_lo and b_hi <= a[i][1]):
            return False
    return True


def ports_overlap(a: tuple[PortRange, ...], b: tuple[PortRange, ...]) -> bool:
    """포트 집합 a와 b에 공통 포트가 하나라도 존재하는가."""
    i = j = 0
    while i < len(a) and j < len(b):
        lo = max(a[i][0], b[j][0])
        hi = min(a[i][1], b[j][1])
        if lo <= hi:
            return True
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return False


def format_ports(ranges: tuple[PortRange, ...]) -> str:
    """포트 범위 목록을 사람이 읽는 문자열로."""
    if ranges == ANY_PORTS:
        return "any"
    return ",".join(f"{lo}" if lo == hi else f"{lo}-{hi}" for lo, hi in ranges)


@dataclass(frozen=True)
class FirewallRule:
    """벤더 중립적인 방화벽 정책 한 줄.

    first-match 의미론(위에서부터 처음 매칭되는 정책이 적용됨)을 가정하며,
    priority 값이 작을수록 먼저 평가됩니다.
    """

    rule_id: str
    src: str                       # 출발지 CIDR ("any" 허용)
    dst: str                       # 목적지 CIDR ("any" 허용)
    protocol: Protocol
    dst_ports: tuple[PortRange, ...]
    action: Action
    priority: int = 100
    description: str = ""
    owner: str = ""                # 정책 책임자 (팀/담당자)
    expires_at: Optional[datetime] = None  # 만료일 (None = 영구)
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # ---------- 생성 헬퍼 ----------

    @staticmethod
    def normalize_cidr(value: str) -> str:
        """CIDR 문자열 정규화. 'any'는 0.0.0.0/0으로 통일."""
        value = (value or "").strip().lower()
        if value in ("any", "*", "0.0.0.0/0", ""):
            return "0.0.0.0/0"
        # 호스트 IP(예: 10.1.2.3)는 /32로 정규화
        net = ipaddress.ip_network(value, strict=False)
        if net.version != 4:
            # IPv6는 아직 미지원. 조용히 받아들이면 v4/v6 구간 비교가
            # 의미 없이 뒤섞이므로 입구에서 명시적으로 거부한다.
            raise ValueError(f"IPv6는 아직 지원하지 않습니다: {value}")
        return str(net)

    @classmethod
    def create(
        cls,
        rule_id: str,
        src: str,
        dst: str,
        protocol: str = "any",
        dst_ports: str = "any",
        action: str = "allow",
        priority: int = 100,
        description: str = "",
        owner: str = "",
        expires_at: Optional[datetime] = None,
    ) -> "FirewallRule":
        """문자열 입력을 검증·정규화하여 Rule을 생성하는 팩토리.

        모든 외부 입력(API, CSV, CLI)은 이 팩토리를 통과하므로
        저장소에는 항상 정규화된 정책만 존재함을 보장합니다.
        """
        proto = Protocol((protocol or "any").strip().lower())
        act = Action((action or "allow").strip().lower())
        if proto == Protocol.ICMP and (dst_ports or "any").strip().lower() not in ("any", "*", ""):
            raise ValueError("ICMP 정책에는 포트를 지정할 수 없습니다")
        return cls(
            rule_id=rule_id,
            src=cls.normalize_cidr(src),
            dst=cls.normalize_cidr(dst),
            protocol=proto,
            dst_ports=parse_ports(dst_ports),
            action=act,
            priority=int(priority),
            description=(description or "").strip(),
            owner=(owner or "").strip(),
            expires_at=expires_at,
        )

    # ---------- 관계 연산 (분석 엔진의 기반) ----------
    #
    # 성능 노트: 관계 연산은 정책 셋 분석에서 O(n^2)회 호출되는 최핵심
    # 경로입니다. ipaddress 객체 연산은 쌍당 수 마이크로초가 걸리므로,
    # 네트워크를 [시작주소, 끝주소] 정수 구간으로 1회 변환해 캐시하고
    # 이후 비교는 정수 대소 비교만으로 수행합니다.
    # (CIDR은 항상 연속 구간이므로 이 변환은 의미를 보존합니다)

    @property
    def src_net(self) -> ipaddress.IPv4Network:
        net = self.__dict__.get("_src_net")
        if net is None:
            net = ipaddress.ip_network(self.src)
            object.__setattr__(self, "_src_net", net)
        return net

    @property
    def dst_net(self) -> ipaddress.IPv4Network:
        net = self.__dict__.get("_dst_net")
        if net is None:
            net = ipaddress.ip_network(self.dst)
            object.__setattr__(self, "_dst_net", net)
        return net

    @property
    def bounds(self) -> tuple[int, int, int, int]:
        """(src_lo, src_hi, dst_lo, dst_hi) 정수 구간. 최초 접근 시 1회 계산."""
        b = self.__dict__.get("_bounds")
        if b is None:
            s, d = self.src_net, self.dst_net
            b = (
                int(s.network_address), int(s.broadcast_address),
                int(d.network_address), int(d.broadcast_address),
            )
            object.__setattr__(self, "_bounds", b)
        return b

    def covers(self, other: "FirewallRule") -> bool:
        """이 정책이 other가 매칭하는 트래픽을 '전부' 매칭하는가.

        self ⊇ other 이면, first-match 순서상 self가 앞에 있을 때
        other는 절대 매칭될 수 없습니다(shadowing/redundancy의 판정 기준).
        """
        a, b = self.bounds, other.bounds
        return (
            a[0] <= b[0] and b[1] <= a[1]      # src 구간 포함
            and a[2] <= b[2] and b[3] <= a[3]  # dst 구간 포함
            and self.protocol.covers(other.protocol)
            and self._ports_for_compare_cover(other)
        )

    def overlaps(self, other: "FirewallRule") -> bool:
        """두 정책이 매칭하는 트래픽에 교집합이 존재하는가."""
        a, b = self.bounds, other.bounds
        return (
            a[0] <= b[1] and b[0] <= a[1]      # src 구간 교차
            and a[2] <= b[3] and b[2] <= a[3]  # dst 구간 교차
            and self.protocol.overlaps(other.protocol)
            and self._ports_for_compare_overlap(other)
        )

    def _ports_for_compare_cover(self, other: "FirewallRule") -> bool:
        # ICMP에는 포트 개념이 없으므로 포트 비교를 생략
        if other.protocol == Protocol.ICMP:
            return True
        return ports_cover(self.dst_ports, other.dst_ports)

    def _ports_for_compare_overlap(self, other: "FirewallRule") -> bool:
        if self.protocol == Protocol.ICMP or other.protocol == Protocol.ICMP:
            return True
        return ports_overlap(self.dst_ports, other.dst_ports)

    # ---------- 표현 ----------

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        if self.expires_at is None:
            return False
        now = now or datetime.now(timezone.utc)
        return self.expires_at < now

    def summary(self) -> str:
        return (
            f"[{self.rule_id}] {self.action.value.upper():5s} "
            f"{self.src} -> {self.dst} "
            f"{self.protocol.value}/{format_ports(self.dst_ports)}"
        )

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "src": self.src,
            "dst": self.dst,
            "protocol": self.protocol.value,
            "dst_ports": format_ports(self.dst_ports),
            "action": self.action.value,
            "priority": self.priority,
            "description": self.description,
            "owner": self.owner,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat(),
        }


def _net_covers(a: ipaddress.IPv4Network, b: ipaddress.IPv4Network) -> bool:
    """네트워크 a가 b를 포함하는가 (a ⊇ b)."""
    return b.subnet_of(a)
