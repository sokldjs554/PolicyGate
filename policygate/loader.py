"""CSV 정책 파일 로더.

기존에 스프레드시트로 관리되던 방화벽 정책 대장을 그대로 흡수하기 위한
가져오기(import) 경로입니다. 실무 전환 시나리오(엑셀 대장 → 시스템 관리)를
가정했습니다.

CSV 헤더: rule_id,src,dst,protocol,dst_ports,action,priority,description,owner,expires_at
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

from policygate.rule import FirewallRule


def load_rules_csv(path: str | Path) -> list[FirewallRule]:
    rules: list[FirewallRule] = []
    seen_ids: set[str] = set()

    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for line_no, row in enumerate(reader, start=2):  # 1행은 헤더
            rule_id = (row.get("rule_id") or "").strip()
            if not rule_id:
                raise ValueError(f"{path}:{line_no}: rule_id가 비어 있습니다")
            if rule_id in seen_ids:
                raise ValueError(f"{path}:{line_no}: rule_id 중복 ({rule_id})")
            seen_ids.add(rule_id)

            expires_raw = (row.get("expires_at") or "").strip()
            expires = None
            if expires_raw:
                expires = datetime.fromisoformat(expires_raw)
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)

            try:
                rules.append(FirewallRule.create(
                    rule_id=rule_id,
                    src=row.get("src", "any"),
                    dst=row.get("dst", "any"),
                    protocol=row.get("protocol", "any"),
                    dst_ports=row.get("dst_ports", "any"),
                    action=row.get("action", "allow"),
                    priority=int(row.get("priority") or 100),
                    description=row.get("description", ""),
                    owner=row.get("owner", ""),
                    expires_at=expires,
                ))
            except (ValueError, KeyError) as e:
                raise ValueError(f"{path}:{line_no}: 정책 파싱 실패 — {e}") from e

    return rules
