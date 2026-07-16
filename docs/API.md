# REST API 레퍼런스

PolicyGate의 워크플로를 HTTP로 노출하는 API 전체 문서입니다.
서버 기동: `python -m policygate.cli serve --db policygate.db --port 8080`

## 인증과 권한

- 인증: 데모에서는 `X-User` 헤더로 행위자를 식별합니다. 운영 환경에서는
  SSO(OIDC)로 교체하며, 그 경계는 `api.py`의 `_actor()` 한 함수에 격리되어
  있습니다.
- 인가: 역할은 클라이언트가 주장하는 값이 아니라 서버측 users 테이블에서
  조회하고, 선언적 권한 매트릭스(`policygate/rbac.py`)로 판정합니다.
- 최초 기동 시 부트스트랩 관리자 `admin`이 자동 생성됩니다.

### 역할별 권한 매트릭스

| 권한 | Requester | Reviewer | Approver | Admin |
|---|:-:|:-:|:-:|:-:|
| 정책 신청 / 조회 | ✅ | ✅ | ✅ | ✅ |
| 신청 반려 | | ✅ | ✅ | ✅ |
| 신청 승인 | | | ✅ | ✅ |
| 배포 (배포 검증 포함) | | | ✅ | ✅ |
| 감사 로그 조회 | | ✅ | ✅ | ✅ |
| 롤백 / 정책 회수 | | | | ✅ |
| 사용자 역할 관리 | | | | ✅ |

추가로 도메인 규칙: 신청자 본인은 역할과 무관하게 자기 신청을 승인할 수
없습니다(직무 분리).

### HTTP 오류 매핑

| 코드 | 의미 | 예 |
|---|---|---|
| 400 | 입력 오류 | 잘못된 CIDR, 지원하지 않는 어댑터/역할 |
| 403 | 권한 없음 (RBAC) | requester가 승인 시도, 미등록 사용자 |
| 404 | 대상 없음 | 존재하지 않는 신청 ID |
| 409 | 절차 위반 (상태 머신/직무 분리) | 승인 없는 배포, 본인 승인 |
| 422 | 자동 검증 반려 | any-any 허용, 중복 신청 (사유가 findings에 포함) |

## 엔드포인트

| 메서드/경로 | 권한 | 설명 |
|---|---|---|
| `POST /api/requests` | request.create | 정책 신청 (즉시 자동 검증) |
| `GET /api/requests?state=` | request.view | 신청 목록 |
| `GET /api/requests/<id>` | request.view | 신청 상세 (검증 결과 포함) |
| `POST /api/requests/<id>/approve` | request.approve | 승인 |
| `POST /api/requests/<id>/reject` | request.reject | 반려 |
| `POST /api/requests/<id>/deploy` | deploy.execute | 배포. `?dry_run=true`, body `{"verify": true}` |
| `POST /api/requests/<id>/rollback` | deploy.rollback | 배포 롤백 |
| `GET /api/rules` | rule.view | 활성 정책 목록 |
| `DELETE /api/rules/<rule_id>` | rule.decommission | 정책 회수 |
| `GET /api/audit/report` | audit.view | 정책 셋 감사 리포트 |
| `GET /api/audit/trail?target=` | audit.view | 감사 로그 (before/after 포함) |
| `GET /api/users` / `POST /api/users` | user.manage | 사용자 조회 / 역할 부여 |
| `GET /api/roles` | 등록 사용자 | 내 역할 + 권한 매트릭스 |

## 전체 라이프사이클 예시

```bash
# 0) 사용자 역할 등록 (부트스트랩 admin)
curl -X POST localhost:8080/api/users -H 'X-User: admin' -H 'Content-Type: application/json' \
  -d '{"username":"alice","role":"requester"}'
curl -X POST localhost:8080/api/users -H 'X-User: admin' -H 'Content-Type: application/json' \
  -d '{"username":"bob","role":"approver"}'

# 1) 신청 — 즉시 자동 검증. 위험/중복이면 422 + 사유(findings)
curl -X POST localhost:8080/api/requests -H 'X-User: alice' -H 'Content-Type: application/json' \
  -d '{"src":"10.5.0.0/24","dst":"10.9.0.10/32","protocol":"tcp","dst_ports":"8080",
       "action":"allow","description":"배치 서버 -> 내부 API","reason":"신규 배치 오픈",
       "expires_at":"2026-12-31T00:00:00+09:00"}'

# 2) 승인 — requester가 시도하면 403, 신청자 본인이면 409
curl -X POST localhost:8080/api/requests/REQ-0001/approve \
  -H 'X-User: bob' -H 'Content-Type: application/json' -d '{"note":"확인 완료"}'

# 3) dry-run — 배포될 설정 전문 미리보기 (상태 변화 없음)
curl -X POST 'localhost:8080/api/requests/REQ-0001/deploy?dry_run=true' \
  -H 'X-User: bob' -H 'Content-Type: application/json' -d '{"adapter":"nftables"}'

# 4) 배포 — verify:true면 격리 namespace에서 커널 적용을 검증한 뒤에만 배포
curl -X POST localhost:8080/api/requests/REQ-0001/deploy \
  -H 'X-User: bob' -H 'Content-Type: application/json' \
  -d '{"adapter":"iptables","verify":true}'
# 응답의 verification.ok / verification.summary에 검증 결과가 담김
# 검증 실패 시 409 반환, 상태는 approved 유지 (수정 후 재시도 가능)

# 5) 감사 — 모든 변경의 timestamp/actor/action/before/after
curl 'localhost:8080/api/audit/trail?target=REQ-0001' -H 'X-User: bob'

# 6) 롤백 (admin 전용) — deployed -> rolled_back, 정책 비활성화
curl -X POST localhost:8080/api/requests/REQ-0001/rollback \
  -H 'X-User: admin' -H 'Content-Type: application/json' -d '{"note":"장애 대응"}'

# 7) 정책 회수 (admin 전용) — 만료/불용 정책 정리
curl -X DELETE localhost:8080/api/rules/FW-0001 \
  -H 'X-User: admin' -H 'Content-Type: application/json' -d '{"note":"서비스 종료"}'
```

## 신청 본문 필드

| 필드 | 필수 | 기본값 | 설명 |
|---|:-:|---|---|
| `src`, `dst` | ✅ | — | CIDR 또는 `any` (호스트 IP는 /32로 정규화, IPv4만) |
| `protocol` | | `tcp` | `tcp` / `udp` / `icmp` / `any` |
| `dst_ports` | | `any` | `443`, `80,443`, `8000-8100` 조합 (icmp는 지정 불가) |
| `action` | | `allow` | `allow` / `deny` |
| `priority` | | `100` | 작을수록 먼저 평가 (first-match) |
| `description` | 권장 | `""` | 누락 시 감사에서 MISSING_DESCRIPTION |
| `expires_at` | | 영구 | ISO 8601. 만료 정책은 감사에서 EXPIRED_RULE |
| `reason` | | `""` | 신청 사유 (감사 기록용) |
