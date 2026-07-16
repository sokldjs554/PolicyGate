"""실배포 검증 — 격리된 network namespace에서 실제 커널에 적용해본다.

"설정 파일을 생성했다"와 "그 설정이 실제 커널에 적용된다"는 다른 문제입니다.
문법은 맞지만 커널 모듈이 거부하는 경우, 버전에 따라 지원되지 않는 매치가
섞인 경우가 실제로 존재합니다.

이 모듈은 배포 전에 다음을 수행합니다.

1. `unshare --net` 으로 **격리된 network namespace**를 만들고
   (호스트 방화벽에 어떤 영향도 주지 않음)
2. 그 안에서 `iptables-restore` 로 생성된 설정을 실제 커널에 적용
3. `iptables-save` 로 적용 결과를 읽어와(readback)
4. 모든 rule_id 주석이 존재하는지 + 기본 정책(DROP)이 맞는지 대조

즉, "배포 성공"을 시스템이 스스로 증명하게 만듭니다.

설계 노트
- `ip netns` 대신 `unshare --net`을 쓴 이유: iproute2 없이 util-linux만으로
  동작하고, 프로세스 종료와 함께 namespace가 자동 소멸해 정리(cleanup)
  실패라는 오류 부류 자체가 없습니다.
- 검증 실패 시 예외가 아니라 결과 객체(VerificationResult)를 반환합니다.
  호출자(워크플로)가 실패를 '상태'로 다뤄 감사 로그에 남기기 위함입니다.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field

from policygate.rule import FirewallRule


@dataclass
class VerificationResult:
    """namespace 검증 결과."""

    ok: bool
    applied: bool                       # iptables-restore 자체가 성공했는가
    missing_rule_ids: list[str] = field(default_factory=list)
    default_policy_ok: bool = False
    error: str = ""
    readback: str = ""                  # 커널에서 읽어온 실제 상태

    def summary(self) -> str:
        if self.ok:
            return "검증 통과: 모든 정책이 커널에 적용됨 (기본 정책 DROP 확인)"
        if not self.applied:
            return f"적용 실패: {self.error}"
        parts = []
        if self.missing_rule_ids:
            parts.append(f"누락된 정책: {', '.join(self.missing_rule_ids)}")
        if not self.default_policy_ok:
            parts.append("기본 정책이 DROP이 아님")
        return "검증 실패: " + "; ".join(parts)


class NamespaceVerifier:
    """iptables 설정을 격리된 netns에서 실제 적용·검증하는 검증기."""

    UNSHARE = "unshare"
    RESTORE = "iptables-restore"
    SAVE = "iptables-save"

    @classmethod
    def available(cls) -> bool:
        """이 환경에서 namespace 검증이 가능한가 (CI/컨테이너 호환성)."""
        if not (shutil.which(cls.UNSHARE) and shutil.which(cls.RESTORE)):
            return False
        # 실제로 unshare --net 권한이 있는지 1회 시험 (CAP_NET_ADMIN 필요)
        try:
            probe = subprocess.run(
                [cls.UNSHARE, "--net", "true"],
                capture_output=True, timeout=10,
            )
            return probe.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def verify(
        self, rendered: str, expected_rules: list[FirewallRule]
    ) -> VerificationResult:
        """생성된 iptables 설정을 격리 namespace의 커널에 적용하고 대조한다."""
        with tempfile.NamedTemporaryFile(
            "w", suffix=".rules", delete=True
        ) as f:
            f.write(rendered)
            f.flush()
            # restore와 save를 '같은 namespace'에서 실행해야 하므로
            # 하나의 unshare 프로세스 안에서 연속 수행한다.
            try:
                proc = subprocess.run(
                    [
                        self.UNSHARE, "--net", "sh", "-c",
                        f"{self.RESTORE} < {f.name} && {self.SAVE}",
                    ],
                    capture_output=True, text=True, timeout=60,
                )
            except (OSError, subprocess.TimeoutExpired) as e:
                return VerificationResult(ok=False, applied=False, error=str(e))

        if proc.returncode != 0:
            return VerificationResult(
                ok=False, applied=False, error=proc.stderr.strip()
            )

        readback = proc.stdout
        # iptables-save는 공백 없는 주석의 따옴표를 제거하므로 양쪽 형태 허용
        missing = [
            r.rule_id
            for r in expected_rules
            if (f'--comment "{r.rule_id}"' not in readback
                and f"--comment {r.rule_id}" not in readback)
        ]
        policy_ok = ":FORWARD DROP" in readback

        return VerificationResult(
            ok=(not missing and policy_ok),
            applied=True,
            missing_rule_ids=missing,
            default_policy_ok=policy_ok,
            readback=readback,
        )
