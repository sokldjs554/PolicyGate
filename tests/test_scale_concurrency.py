"""대용량 정책 셋 + 동시 요청 테스트.

1. 대용량: 수천 건 규모에서 분석이 시간 내에 끝나고 결과가 정확한가
2. 동시성: 여러 스레드가 동시에 신청해도 ID 충돌/유실이 없는가
   (COUNT(*) 기반 채번의 race를 발견하고 원자 카운터로 교체한 근거)
"""

import threading
import time
import unittest

from policygate.analysis import PolicyAnalyzer
from policygate.rule import FirewallRule
from policygate.store import Store
from policygate.workflow import PolicyService


def disjoint_rules(n: int) -> list[FirewallRule]:
    """서로 겹치지 않는 n개의 정책 생성 (거짓 양성 검증용)."""
    rules = []
    for i in range(n):
        a, b = divmod(i, 250)
        rules.append(FirewallRule.create(
            rule_id=f"R{i:05d}",
            src=f"10.{a}.{b}.0/28",
            dst=f"172.16.{a}.{b * 16 // 250 * 16}/32" if False else f"172.{16 + a % 16}.{b}.{i % 250}/32",
            protocol="tcp",
            dst_ports=str(1000 + (i % 50000) % 60000 + 1),
            action="allow",
            priority=i,
            owner="team", description="d",
        ))
    return rules


class ScaleTest(unittest.TestCase):
    def test_2000_disjoint_rules_no_false_positives(self):
        """겹치지 않는 2,000개 정책 → 관계 finding이 0건이어야 한다."""
        rules = disjoint_rules(2000)
        analyzer = PolicyAnalyzer()
        start = time.monotonic()
        report = analyzer.analyze(rules)
        elapsed = time.monotonic() - start

        relation_codes = {"SHADOWED", "REDUNDANT", "CORRELATED"}
        relations = [f for f in report.findings if f.code in relation_codes]
        self.assertEqual(relations, [])
        # 2,000개(약 200만 쌍)는 수 초 안에 끝나야 한다
        self.assertLess(elapsed, 10.0, f"분석이 너무 느립니다: {elapsed:.1f}s")

    def test_large_set_correctness_with_planted_issues(self):
        """대용량 셋 속에 심어놓은 문제를 정확히 그 정책만 찾아내는가."""
        rules = disjoint_rules(1000)
        # 문제 심기: R00010을 가리는 정책 + R00020과 중복인 정책
        shadow_victim = FirewallRule.create(
            rule_id="VICTIM", src=rules[10].src, dst=rules[10].dst,
            protocol="tcp", dst_ports=rules[10].to_dict()["dst_ports"],
            action="deny", priority=99999, owner="t", description="d",
        )
        dup = FirewallRule.create(
            rule_id="DUP", src=rules[20].src, dst=rules[20].dst,
            protocol="tcp", dst_ports=rules[20].to_dict()["dst_ports"],
            action="allow", priority=99998, owner="t", description="d",
        )
        report = PolicyAnalyzer().analyze(rules + [shadow_victim, dup])
        shadowed = {f.rule_id for f in report.findings if f.code == "SHADOWED"}
        redundant = {f.rule_id for f in report.findings if f.code == "REDUNDANT"}
        self.assertEqual(shadowed, {"VICTIM"})
        self.assertEqual(redundant, {"DUP"})

    def test_validate_new_rule_fast_on_large_set(self):
        """신규 신청 검증은 대용량 셋에서도 즉답 수준이어야 한다 (O(n))."""
        rules = disjoint_rules(5000)
        new = FirewallRule.create(
            rule_id="NEW", src="192.168.77.0/24", dst="10.200.0.1/32",
            protocol="tcp", dst_ports="8443", action="allow",
            owner="t", description="d",
        )
        start = time.monotonic()
        PolicyAnalyzer().validate_new_rule(new, rules)
        self.assertLess(time.monotonic() - start, 1.0)


class ConcurrencyTest(unittest.TestCase):
    def test_concurrent_submissions_unique_ids(self):
        """20개 스레드 동시 신청 → 요청/정책 ID가 전부 고유해야 한다."""
        store = Store(":memory:")
        service = PolicyService(store)
        results, errors = [], []
        barrier = threading.Barrier(20)

        def submit(i):
            try:
                barrier.wait()  # 전원 동시 출발
                req = service.submit_request(
                    requester=f"user{i}",
                    src=f"10.{i}.0.0/24", dst=f"172.16.{i}.1/32",
                    protocol="tcp", dst_ports=str(1000 + i),
                    description=f"동시 신청 {i}",
                )
                results.append(req)
            except Exception as e:  # noqa: BLE001 - 테스트 수집용
                errors.append(e)

        threads = [threading.Thread(target=submit, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 20)
        request_ids = {r["request_id"] for r in results}
        rule_ids = {r["rule"]["rule_id"] for r in results}
        self.assertEqual(len(request_ids), 20, "request_id 충돌 발생")
        self.assertEqual(len(rule_ids), 20, "rule_id 충돌 발생")
        # 전부 저장소에 존재해야 함 (유실 없음)
        self.assertEqual(len(store.list_requests()), 20)

    def test_concurrent_audit_writes_not_lost(self):
        """감사 로그 동시 기록에서 유실이 없어야 한다 (append-only 보장)."""
        store = Store(":memory:")
        barrier = threading.Barrier(10)

        def write(i):
            barrier.wait()
            for j in range(20):
                store.audit(f"actor{i}", "TEST_EVENT", f"target-{i}-{j}")

        threads = [threading.Thread(target=write, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        events = [e for e in store.audit_trail() if e["event"] == "TEST_EVENT"]
        self.assertEqual(len(events), 200)


if __name__ == "__main__":
    unittest.main()
