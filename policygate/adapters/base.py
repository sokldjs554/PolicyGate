"""방화벽 어댑터 추상 계층.

분석/워크플로는 벤더 중립 모델(FirewallRule)만 다루고,
"그 정책을 실제 장비 문법으로 어떻게 쓰는가"는 어댑터가 책임집니다.

이 구조 덕분에:
- 새 벤더 지원 = 어댑터 클래스 하나 추가 (기존 코드 무변경, OCP)
- 배포 방식 교체(SSH, REST API, 에이전트)도 어댑터 내부에만 국한
- 테스트에서는 render() 결과 문자열만 검증하면 됨 (장비 불필요)
"""

from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod

from policygate.rule import FirewallRule


class FirewallAdapter(ABC):
    """벤더별 방화벽 어댑터 인터페이스."""

    #: 어댑터 식별자 (감사 로그에 기록됨)
    name: str = "abstract"

    @abstractmethod
    def render(self, rules: list[FirewallRule]) -> str:
        """정책 셋 전체를 해당 벤더의 설정 문법으로 변환한다.

        '전체 선언형(declarative full-set)' 방식을 사용합니다.
        개별 룰을 한 줄씩 추가/삭제(imperative)하면 장비 상태와
        관리 시스템 상태가 어긋나는 드리프트가 생기기 쉽기 때문에,
        항상 원하는 최종 상태 전체를 생성해 원자적으로 교체합니다.
        """

    def deploy(self, rules: list[FirewallRule]) -> str:
        """정책 셋을 장비에 반영한다. 기본 구현은 render 결과 반환만.

        실제 장비 반영이 필요한 어댑터는 이 메서드를 오버라이드합니다.
        """
        return self.render(rules)


class CommandRunner:
    """시스템 명령 실행 래퍼 (테스트에서 모킹하기 위한 이음새).

    어댑터가 subprocess를 직접 부르면 테스트가 불가능해지므로,
    실행 책임을 분리하고 테스트에서는 FakeRunner로 대체합니다.
    """

    def run(self, cmd: list[str], input_text: str = "") -> str:
        result = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"명령 실행 실패({' '.join(cmd)}): {result.stderr.strip()}"
            )
        return result.stdout
