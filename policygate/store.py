"""SQLite 기반 저장소 (정책 / 신청 / 감사 로그).

외부 DB 없이 파일 하나로 완결되도록 표준 라이브러리 sqlite3를 사용합니다.
저장소 계층을 분리해 두었기 때문에, 실서비스에서 PostgreSQL 등으로
교체하더라도 워크플로/분석 코드는 변경이 없습니다.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from policygate.rule import FirewallRule

_SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    rule_id     TEXT PRIMARY KEY,
    src         TEXT NOT NULL,
    dst         TEXT NOT NULL,
    protocol    TEXT NOT NULL,
    dst_ports   TEXT NOT NULL,
    action      TEXT NOT NULL,
    priority    INTEGER NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    owner       TEXT NOT NULL DEFAULT '',
    expires_at  TEXT,
    created_at  TEXT NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS requests (
    request_id  TEXT PRIMARY KEY,
    rule_json   TEXT NOT NULL,      -- 신청된 정책 스냅샷
    requester   TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    state       TEXT NOT NULL,      -- workflow.state.RequestState
    findings    TEXT NOT NULL DEFAULT '[]',  -- 자동 검증 결과 스냅샷
    reviewer    TEXT,
    review_note TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    event       TEXT NOT NULL,      -- 예: REQUEST_CREATED, RULE_DEPLOYED
    target      TEXT NOT NULL,      -- request_id 또는 rule_id
    detail      TEXT NOT NULL DEFAULT '',
    before_json TEXT,               -- 변경 전 상태 스냅샷 (JSON, 없으면 NULL)
    after_json  TEXT                -- 변경 후 상태 스냅샷 (JSON, 없으면 NULL)
);

CREATE TABLE IF NOT EXISTS users (
    username    TEXT PRIMARY KEY,
    role        TEXT NOT NULL,      -- rbac.Role
    assigned_by TEXT NOT NULL,
    assigned_at TEXT NOT NULL
);

-- ID 채번용 카운터. "테이블 행 수 세기" 방식은 동시 요청에서 같은 ID를
-- 발급하는 경쟁 상태(race)가 있어, 원자적 증가 방식으로 교체했다.
CREATE TABLE IF NOT EXISTS counters (
    name        TEXT PRIMARY KEY,
    value       INTEGER NOT NULL
);
"""


def _rule_to_row(rule: FirewallRule) -> tuple:
    from policygate.rule import format_ports

    return (
        rule.rule_id,
        rule.src,
        rule.dst,
        rule.protocol.value,
        format_ports(rule.dst_ports),
        rule.action.value,
        rule.priority,
        rule.description,
        rule.owner,
        rule.expires_at.isoformat() if rule.expires_at else None,
        rule.created_at.isoformat(),
    )


def _row_to_rule(row: sqlite3.Row) -> FirewallRule:
    expires = (
        datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None
    )
    rule = FirewallRule.create(
        rule_id=row["rule_id"],
        src=row["src"],
        dst=row["dst"],
        protocol=row["protocol"],
        dst_ports=row["dst_ports"],
        action=row["action"],
        priority=row["priority"],
        description=row["description"],
        owner=row["owner"],
        expires_at=expires,
    )
    # created_at 은 저장된 값으로 복원 (frozen dataclass 우회)
    object.__setattr__(rule, "created_at", datetime.fromisoformat(row["created_at"]))
    return rule


class Store:
    """스레드 안전한 SQLite 저장소."""

    def __init__(self, path: str = ":memory:"):
        # check_same_thread=False + 자체 락으로 멀티스레드 API 서버에서도 안전
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # ---------------- rules ----------------

    def add_rule(self, rule: FirewallRule) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO rules (rule_id, src, dst, protocol, dst_ports, action,"
                " priority, description, owner, expires_at, created_at, active)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,1)",
                _rule_to_row(rule),
            )
            self._conn.commit()

    def deactivate_rule(self, rule_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE rules SET active = 0 WHERE rule_id = ? AND active = 1",
                (rule_id,),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def get_rule(self, rule_id: str) -> Optional[FirewallRule]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM rules WHERE rule_id = ?", (rule_id,)
            ).fetchone()
        return _row_to_rule(row) if row else None

    def active_rules(self) -> list[FirewallRule]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM rules WHERE active = 1 ORDER BY priority, rule_id"
            ).fetchall()
        return [_row_to_rule(r) for r in rows]

    def next_rule_id(self) -> str:
        return self._next_id("rule", "FW")

    def _next_id(self, counter: str, prefix: str) -> str:
        """경쟁 상태 없는 ID 채번 (카운터 원자 증가).

        처음에는 COUNT(*) 기반이었으나, 동시 신청 테스트에서 두 요청이
        같은 ID를 받는 race를 발견해 UPDATE...RETURNING 원자 연산으로
        교체했다 (tests/test_concurrency.py가 이 보장을 회귀 방지).
        """
        with self._lock:
            self._conn.execute(
                "INSERT INTO counters (name, value) VALUES (?, 0)"
                " ON CONFLICT(name) DO NOTHING",
                (counter,),
            )
            row = self._conn.execute(
                "UPDATE counters SET value = value + 1 WHERE name = ?"
                " RETURNING value",
                (counter,),
            ).fetchone()
            self._conn.commit()
        return f"{prefix}-{row[0]:04d}"

    # ---------------- requests ----------------

    def save_request(self, req: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO requests (request_id, rule_json, requester, reason,"
                " state, findings, reviewer, review_note, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(request_id) DO UPDATE SET"
                " state=excluded.state, findings=excluded.findings,"
                " reviewer=excluded.reviewer, review_note=excluded.review_note,"
                " updated_at=excluded.updated_at",
                (
                    req["request_id"],
                    json.dumps(req["rule"], ensure_ascii=False),
                    req["requester"],
                    req.get("reason", ""),
                    req["state"],
                    json.dumps(req.get("findings", []), ensure_ascii=False),
                    req.get("reviewer"),
                    req.get("review_note"),
                    req["created_at"],
                    req["updated_at"],
                ),
            )
            self._conn.commit()

    def get_request(self, request_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM requests WHERE request_id = ?", (request_id,)
            ).fetchone()
        return self._request_row_to_dict(row) if row else None

    def list_requests(self, state: Optional[str] = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM requests"
        params: tuple = ()
        if state:
            query += " WHERE state = ?"
            params = (state,)
        query += " ORDER BY created_at"
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._request_row_to_dict(r) for r in rows]

    def next_request_id(self) -> str:
        return self._next_id("request", "REQ")

    @staticmethod
    def _request_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "request_id": row["request_id"],
            "rule": json.loads(row["rule_json"]),
            "requester": row["requester"],
            "reason": row["reason"],
            "state": row["state"],
            "findings": json.loads(row["findings"]),
            "reviewer": row["reviewer"],
            "review_note": row["review_note"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    # ---------------- users (RBAC) ----------------

    def upsert_user(self, username: str, role: str, assigned_by: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO users (username, role, assigned_by, assigned_at)"
                " VALUES (?,?,?,?)"
                " ON CONFLICT(username) DO UPDATE SET"
                " role=excluded.role, assigned_by=excluded.assigned_by,"
                " assigned_at=excluded.assigned_at",
                (username, role, assigned_by,
                 datetime.now(timezone.utc).isoformat()),
            )
            self._conn.commit()

    def get_user_role(self, username: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT role FROM users WHERE username = ?", (username,)
            ).fetchone()
        return row["role"] if row else None

    def list_users(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM users ORDER BY username"
            ).fetchall()
        return [dict(r) for r in rows]

    # ---------------- audit ----------------
    # 감사 로그는 append-only: UPDATE/DELETE 경로가 존재하지 않는다.
    # 모든 변경 이벤트는 변경 전(before)/후(after) 상태 스냅샷을 함께 남겨,
    # "무엇이 어떻게 바뀌었는가"를 로그만으로 재구성할 수 있게 한다.

    def audit(
        self,
        actor: str,
        event: str,
        target: str,
        detail: str = "",
        before: Optional[dict] = None,
        after: Optional[dict] = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_log"
                " (at, actor, event, target, detail, before_json, after_json)"
                " VALUES (?,?,?,?,?,?,?)",
                (
                    datetime.now(timezone.utc).isoformat(),
                    actor,
                    event,
                    target,
                    detail,
                    json.dumps(before, ensure_ascii=False) if before is not None else None,
                    json.dumps(after, ensure_ascii=False) if after is not None else None,
                ),
            )
            self._conn.commit()

    def audit_trail(self, target: Optional[str] = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM audit_log"
        params: tuple = ()
        if target:
            query += " WHERE target = ?"
            params = (target,)
        query += " ORDER BY id"
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [
            {
                "at": r["at"],
                "actor": r["actor"],
                "event": r["event"],
                "target": r["target"],
                "detail": r["detail"],
                "before": json.loads(r["before_json"]) if r["before_json"] else None,
                "after": json.loads(r["after_json"]) if r["after_json"] else None,
            }
            for r in rows
        ]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
