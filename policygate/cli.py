"""PolicyGate CLI.

보안 인프라 운영자는 대부분의 작업을 터미널에서 합니다.
CSV 정책 대장 감사, 벤더 설정 생성, API 서버 기동을 명령 한 줄로 제공합니다.

사용 예
  python -m policygate.cli audit sample_data/policies.csv
  python -m policygate.cli render sample_data/policies.csv --format nftables
  python -m policygate.cli serve --db policygate.db
"""

from __future__ import annotations

import json
import sys

import click

from policygate.adapters import IptablesAdapter, NftablesAdapter
from policygate.analysis import PolicyAnalyzer
from policygate.loader import load_rules_csv

_SEVERITY_MARK = {
    "critical": "[!!] CRITICAL",
    "high": "[! ] HIGH    ",
    "medium": "[* ] MEDIUM  ",
    "low": "[- ] LOW     ",
    "info": "[  ] INFO    ",
}


@click.group()
def cli() -> None:
    """PolicyGate — 방화벽 정책 라이프사이클 자동화."""


@cli.command()
@click.argument("csv_path", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="JSON으로 출력 (CI 연동용)")
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high"]),
    default="critical",
    show_default=True,
    help="이 심각도 이상 발견 시 종료 코드 1 (CI 게이트)",
)
def audit(csv_path: str, as_json: bool, fail_on: str) -> None:
    """CSV 정책 대장을 감사하고 문제를 보고한다."""
    rules = load_rules_csv(csv_path)
    report = PolicyAnalyzer().analyze(rules)

    if as_json:
        click.echo(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        click.echo(f"정책 {report.rule_count}건 분석 완료 — 발견 {len(report.findings)}건")
        click.echo("-" * 72)
        for f in report.sorted_findings():
            related = f" (관련: {f.related_rule_id})" if f.related_rule_id else ""
            click.echo(f"{_SEVERITY_MARK[f.severity.value]} {f.rule_id}{related}")
            click.echo(f"     {f.code}: {f.message}")
        summary = ", ".join(f"{k}={v}" for k, v in report.count_by_severity().items())
        click.echo("-" * 72)
        click.echo(f"요약: {summary or '이상 없음'}")

    blocking = {"critical"} if fail_on == "critical" else {"critical", "high"}
    if any(f.severity.value in blocking for f in report.findings):
        sys.exit(1)


@cli.command()
@click.argument("csv_path", type=click.Path(exists=True))
@click.option(
    "--format", "fmt",
    type=click.Choice(["iptables", "nftables"]),
    default="iptables",
    show_default=True,
)
def render(csv_path: str, fmt: str) -> None:
    """CSV 정책 대장을 벤더 설정 파일로 변환한다 (stdout)."""
    rules = load_rules_csv(csv_path)
    adapter = IptablesAdapter() if fmt == "iptables" else NftablesAdapter()
    click.echo(adapter.render(rules), nl=False)


@cli.command()
@click.argument("csv_path", type=click.Path(exists=True))
@click.option("--src", required=True, help="출발지 IP")
@click.option("--dst", required=True, help="목적지 IP")
@click.option("--proto", default="tcp", show_default=True,
              type=click.Choice(["tcp", "udp", "icmp"]))
@click.option("--port", type=int, default=None, help="목적지 포트 (icmp면 생략)")
def trace(csv_path: str, src: str, dst: str, proto: str, port: int | None) -> None:
    """단일 트래픽이 어떤 정책에 매칭되는지 시뮬레이션한다.

    예: python -m policygate.cli trace sample_data/policies.csv \\
          --src 10.0.1.5 --dst 10.20.0.10 --proto tcp --port 443
    """
    from policygate.analysis import Packet, first_match

    rules = load_rules_csv(csv_path)
    result = first_match(rules, Packet(src_ip=src, dst_ip=dst,
                                       protocol=proto, dst_port=port))
    mark = "허용" if result.allowed else "차단"
    click.echo(f"[{mark}] {result.verdict}")
    sys.exit(0 if result.allowed else 1)


@cli.command()
@click.argument("csv_path", type=click.Path(exists=True))
@click.argument("log_path", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="JSON으로 출력")
def usage(csv_path: str, log_path: str, as_json: bool) -> None:
    """방화벽 로그를 정책 셋과 대조해 사용 현황을 분석한다.

    미사용(hit=0) allow 정책과 기본 차단된 접근 시도를 보고합니다.
    """
    from policygate.analysis import analyze_usage

    rules = load_rules_csv(csv_path)
    with open(log_path, encoding="utf-8") as f:
        report = analyze_usage(rules, f)

    if as_json:
        click.echo(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        return

    click.echo(
        f"로그 {report.total_lines}줄 중 {report.parsed_packets}건 분석"
    )
    click.echo("-" * 72)
    click.echo("정책별 히트 카운트:")
    for rule in sorted(rules, key=lambda r: (r.priority, r.rule_id)):
        hits = report.hit_counts.get(rule.rule_id, 0)
        click.echo(f"  {rule.rule_id}: {hits:6d}  {rule.summary()}")
    if report.unused_allow_rules:
        click.echo("-" * 72)
        click.echo("미사용(hit=0) 허용 정책 — 회수 검토 대상:")
        for rule_id in report.unused_allow_rules:
            click.echo(f"  {rule_id}")
        click.echo("  * 관측 기간에 한정된 판정입니다. 분기 배치 등 저빈도 사용을 확인 후 회수하세요.")
    if report.default_denied:
        click.echo("-" * 72)
        click.echo("기본 차단된 접근 시도 상위 (설정 누락 또는 공격 시도):")
        for item in report.to_dict()["default_denied_top"]:
            click.echo(f"  {item['count']:5d}회  {item['flow']}")


@cli.command()
@click.argument("csv_path", type=click.Path(exists=True))
def verify(csv_path: str) -> None:
    """생성된 iptables 설정을 격리된 network namespace의 커널에
    실제 적용해 검증한다 (호스트 방화벽에는 영향 없음).

    root 권한(CAP_NET_ADMIN)과 unshare, iptables-restore가 필요합니다.
    """
    from policygate.adapters import IptablesAdapter, NamespaceVerifier

    if not NamespaceVerifier.available():
        click.echo("이 환경에서는 namespace 검증을 사용할 수 없습니다 "
                   "(root + unshare + iptables-restore 필요)")
        sys.exit(2)

    rules = load_rules_csv(csv_path)
    rendered = IptablesAdapter().render(rules)
    result = NamespaceVerifier().verify(rendered, rules)
    click.echo(result.summary())
    if result.ok:
        click.echo(f"커널 적용 확인: 정책 {len(rules)}건 전부 readback 대조 통과")
    sys.exit(0 if result.ok else 1)


@cli.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8080, show_default=True)
@click.option("--db", default="policygate.db", show_default=True, help="SQLite 파일 경로")
def serve(host: str, port: int, db: str) -> None:
    """워크플로 REST API 서버를 기동한다."""
    from policygate.api import create_app
    from policygate.store import Store

    create_app(Store(db)).run(host=host, port=port)


if __name__ == "__main__":
    cli()
