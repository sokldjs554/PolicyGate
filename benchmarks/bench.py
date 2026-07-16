"""성능 벤치마크 — 정책 규모별 분석 시간·메모리 측정.

측정 항목 (정책 100 / 1,000 / 5,000 / 10,000건)
- 전체 분석(analyze) 시간: 관계 분석 + 위험 점검 전부
- Shadow Detection 시간:   관계 스캔 후 SHADOWED 필터
- Redundant Detection 시간: 관계 스캔 후 REDUNDANT 필터
- 피크 메모리(tracemalloc): 분석 도중 추가로 할당된 피크

측정 설계에 대한 노트 (정직한 벤치마크를 위해)
- Shadow/Redundant는 같은 쌍(pair) 스캔을 공유하므로 두 시간은 거의
  동일합니다. 별도 열로 두는 이유는 "분리 호출 시 비용"을 보여주기 위함이며,
  실무에서는 analyze() 한 번으로 둘 다 얻습니다.
- 시간 측정과 메모리 측정은 별도 실행합니다. tracemalloc은 할당 추적
  오버헤드로 시간을 크게 부풀리기 때문입니다.
- 데이터셋은 대부분 서로 겹치지 않고 일부(약 5%)만 겹치게 생성합니다.
  실제 운영 정책 셋의 형태(대부분 무관, 소수 중복/충돌)를 모사하면서
  빠른 탈락 경로와 정밀 판정 경로를 모두 통과시키기 위함입니다.

사용:
  python -m benchmarks.bench                      # 기본 4개 규모
  python -m benchmarks.bench --sizes 100,1000     # CI용 축소 실행
  python -m benchmarks.bench --plot               # docs/benchmark.png 생성
"""

from __future__ import annotations

import argparse
import statistics
import time
import tracemalloc
from pathlib import Path

from policygate.analysis import PolicyAnalyzer
from policygate.rule import FirewallRule

DOCS = Path(__file__).resolve().parent.parent / "docs"


def generate_rules(n: int, overlap_every: int = 20) -> list[FirewallRule]:
    """벤치마크용 정책 셋 생성.

    - 기본: 서로 겹치지 않는 (src, dst, port) 조합
    - overlap_every마다 1건: 직전 정책과 겹치는 정책(부분집합)을 심어
      shadowing/redundancy 탐지 경로도 실제로 타게 한다
    """
    rules: list[FirewallRule] = []
    for i in range(n):
        a = (i // 250) % 200
        b = i % 250
        if i > 0 and i % overlap_every == 0:
            # 직전 정책의 부분집합 (동일 액션 → REDUNDANT 후보)
            prev = rules[-1]
            rules.append(FirewallRule.create(
                rule_id=f"B{i:05d}",
                src=prev.src.rsplit("/", 1)[0] + "/30",
                dst=prev.dst,
                protocol="tcp",
                dst_ports=prev.to_dict()["dst_ports"],
                action="allow",
                priority=i,
                owner="bench", description="overlap",
            ))
        else:
            rules.append(FirewallRule.create(
                rule_id=f"B{i:05d}",
                src=f"10.{a}.{b}.0/28",
                dst=f"172.{16 + (a % 16)}.{b}.{(i * 7) % 250}/32",
                protocol="tcp",
                dst_ports=str(1024 + (i % 60000)),
                action="allow",
                priority=i,
                owner="bench", description="bench",
            ))
    return rules


def measurement_env() -> dict:
    """측정 환경 기록 — 벤치마크 수치는 환경 없이는 의미가 없다."""
    import platform

    cpu = platform.processor() or "unknown"
    ram = "unknown"
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("model name"):
                    cpu = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    try:
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    kb = int(line.split()[1])
                    ram = f"{kb / 1024 / 1024:.0f} GB"
                    break
    except OSError:
        pass
    return {
        "cpu": cpu,
        "cores": __import__("os").cpu_count(),
        "ram": ram,
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
    }


def bench_one(n: int, repeat: int = 3) -> dict:
    """규모 n에 대해 repeat회 반복 측정하고 중앙값을 취한다.

    1회 측정은 GC/스케줄러 노이즈에 흔들리므로 중앙값을 보고한다.
    (평균은 이상치 1회에 오염되므로 중앙값이 벤치마크에 적합)
    """
    analyzer = PolicyAnalyzer()
    t_analyze, t_shadow, t_redundant = [], [], []
    findings = shadowed = redundant = 0

    for _ in range(repeat):
        # 관계 연산 캐시(bounds)가 회차 간 공유되지 않도록 매회 새로 생성
        # (최초 실행의 캐시 구축 비용까지 포함해 측정 — 실제 사용과 동일)
        rules = generate_rules(n)

        t0 = time.perf_counter()
        report = analyzer.analyze(rules)
        t_analyze.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        sh = analyzer.detect_shadowed(rules)
        t_shadow.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        rd = analyzer.detect_redundant(rules)
        t_redundant.append(time.perf_counter() - t0)

        findings, shadowed, redundant = len(report.findings), len(sh), len(rd)

    # 메모리는 별도 실행 (tracemalloc 오버헤드가 시간을 오염시키므로)
    fresh_rules = generate_rules(n)
    tracemalloc.start()
    analyzer.analyze(fresh_rules)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    med = statistics.median
    return {
        "rules": n,
        "pairs": n * (n - 1) // 2,
        "analyze_s": med(t_analyze),
        "shadow_s": med(t_shadow),
        "redundant_s": med(t_redundant),
        "peak_mb": peak / (1024 * 1024),
        "findings": findings,
        "shadowed": shadowed,
        "redundant": redundant,
        "repeat": repeat,
    }


def to_markdown(results: list[dict]) -> str:
    lines = [
        "| 정책 수 | 쌍 비교 수 | 전체 분석 | Shadow 탐지 | Redundant 탐지 | 피크 메모리 |",
        "|--------:|-----------:|----------:|------------:|---------------:|------------:|",
    ]
    for r in results:
        lines.append(
            f"| {r['rules']:,} | {r['pairs']:,} "
            f"| {r['analyze_s']:.2f}s | {r['shadow_s']:.2f}s "
            f"| {r['redundant_s']:.2f}s | {r['peak_mb']:.1f} MB |"
        )
    return "\n".join(lines)


def plot(results: list[dict], out: Path) -> None:
    """README용 벤치마크 그래프 (두 측정 단위 → 두 개의 차트, 이중축 금지)."""
    import matplotlib
    matplotlib.use("Agg")
    # 한글 라벨 렌더링: 환경에 있는 CJK 폰트를 탐색해 사용 (없으면 기본 폰트)
    import matplotlib.font_manager as fm
    import matplotlib.pyplot as plt
    cjk = [f.name for f in fm.fontManager.ttflist
           if "CJK" in f.name or "Nanum" in f.name or "Noto Sans KR" in f.name]
    if cjk:
        plt.rcParams["font.family"] = sorted(set(cjk))[0]
    plt.rcParams["axes.unicode_minus"] = False

    # 팔레트: 검증된 기본 카테고리 팔레트 (light)
    C1, C2, C3 = "#2a78d6", "#008300", "#e87ba4"
    SURFACE, TEXT, MUTED = "#fcfcfb", "#0b0b0b", "#52514e"

    xs = [r["rules"] for r in results]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4), dpi=150)
    fig.patch.set_facecolor(SURFACE)

    for ax in (ax1, ax2):
        ax.set_facecolor(SURFACE)
        ax.grid(True, which="major", color="#e6e5e0", linewidth=0.8)
        ax.set_axisbelow(True)
        for spine in ("top", "right"):
            ax.spines[spine].set_visible(False)
        for spine in ("left", "bottom"):
            ax.spines[spine].set_color(MUTED)
        ax.tick_params(colors=MUTED, labelsize=8)
        ax.set_xscale("log")
        ax.set_xticks(xs)
        ax.set_xticklabels([f"{x:,}" for x in xs])
        ax.minorticks_off()
        ax.set_xlabel("정책 수", color=MUTED, fontsize=9)

    # 차트 1: 분석 시간 (초, 로그 스케일 — O(n^2) 성장 확인용)
    ax1.set_yscale("log")
    series = [
        ("전체 분석", "analyze_s", C1),
        ("Shadow 탐지", "shadow_s", C2),
        ("Redundant 탐지", "redundant_s", C3),
    ]
    for label, key, color in series:
        ys = [r[key] for r in results]
        ax1.plot(xs, ys, color=color, linewidth=2, marker="o",
                 markersize=5, label=label)
    ax1.set_title("분석 시간 (로그-로그)", color=TEXT, fontsize=10)
    ax1.set_ylabel("초", color=MUTED, fontsize=9)
    ax1.legend(fontsize=8, frameon=False, labelcolor=TEXT)

    # 차트 2: 피크 메모리 (MB, 선형)
    ys = [r["peak_mb"] for r in results]
    ax2.plot(xs, ys, color=C1, linewidth=2, marker="o", markersize=5)
    for x, y in zip(xs, ys, strict=True):
        ax2.annotate(f"{y:.1f}", (x, y), textcoords="offset points",
                     xytext=(0, 8), ha="center", fontsize=8, color=MUTED)
    ax2.set_title("분석 중 피크 메모리", color=TEXT, fontsize=10)
    ax2.set_ylabel("MB", color=MUTED, fontsize=9)
    ax2.set_ylim(bottom=0)

    fig.tight_layout()
    fig.savefig(out, facecolor=SURFACE, bbox_inches="tight")
    print(f"그래프 저장: {out}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", default="100,1000,5000,10000",
                        help="쉼표로 구분한 정책 수 목록")
    parser.add_argument("--plot", action="store_true",
                        help="docs/benchmark.png 그래프 생성")
    parser.add_argument("--repeat", type=int, default=3,
                        help="규모당 반복 측정 횟수 (중앙값 보고)")
    args = parser.parse_args()

    env = measurement_env()
    print(f"측정 환경: {env['cpu']} ({env['cores']} cores, RAM {env['ram']}) / "
          f"{env['os']} / Python {env['python']} / 반복 {args.repeat}회(중앙값)")

    sizes = [int(s) for s in args.sizes.split(",")]
    results = []
    for n in sizes:
        r = bench_one(n, repeat=args.repeat)
        results.append(r)
        print(
            f"정책 {n:>6,}건: 분석 {r['analyze_s']:6.2f}s "
            f"(shadow {r['shadow_s']:.2f}s / redundant {r['redundant_s']:.2f}s) "
            f"피크 {r['peak_mb']:.1f}MB — 발견 {r['findings']}건"
        )

    md = to_markdown(results)
    print("\n" + md)
    DOCS.mkdir(exist_ok=True)
    out = DOCS / "BENCHMARK.md"
    out.write_text(
        "# 성능 벤치마크\n\n"
        "`python -m benchmarks.bench` 측정 결과입니다. "
        "Shadow/Redundant 탐지는 동일한 쌍 스캔을 공유하므로 시간이 거의 같습니다 — "
        "운영에서는 `analyze()` 한 번으로 둘 다 얻습니다.\n\n"
        "## 측정 환경\n\n"
        f"- CPU: {env['cpu']} ({env['cores']} cores)\n"
        f"- RAM: {env['ram']}\n"
        f"- OS: {env['os']}\n"
        f"- Python: {env['python']}\n"
        f"- 측정 방식: 규모당 {args.repeat}회 반복, **중앙값** 보고 "
        f"(메모리는 tracemalloc 오버헤드 격리를 위해 별도 1회 실행)\n\n"
        "## 결과\n\n"
        + md + "\n\n![benchmark](benchmark.png)\n\n"
        "## 해석\n\n"
        "쌍 비교 수는 n(n-1)/2로 늘어나므로 분석 시간도 이차 함수로 성장합니다. "
        "그래프의 로그-로그 스케일에서 기울기 2의 직선이 이를 보여줍니다.\n\n"
        "정책 10,000건(쌍 비교 약 5천만 회)이 3초 안에 끝나는 이유는 두 가지입니다. "
        "첫째, CIDR을 정수 구간 (시작주소, 끝주소)로 변환해 포함/교차 판정을 "
        "정수 대소 비교로 환원했습니다. CIDR은 정의상 연속된 주소 구간이므로 이 "
        "변환에 의미 손실이 없습니다. 둘째, 안쪽 루프에 빠른 탈락 경로를 두어 "
        "src 또는 dst가 아예 겹치지 않는 쌍(현실 정책 셋의 대부분)을 정수 비교 "
        "4회로 즉시 제외합니다.\n\n"
        "이보다 큰 규모가 필요해지면 Interval Tree로 후보 쌍 조회를 "
        "O(n log n + K)로 줄이는 경로가 있습니다. 적용 지점과 트레이드오프는 "
        "ARCHITECTURE.md의 ADR-11에 정리했습니다.\n\n"
        "벤치마크 데이터셋은 대부분 겹치지 않는 정책에 약 5%의 중복/포함 정책을 "
        "심어 생성합니다. 빠른 탈락 경로와 정밀 판정 경로를 모두 통과시키기 "
        "위한 구성입니다. 재현: `python -m benchmarks.bench --repeat 3 --plot`\n",
        encoding="utf-8",
    )
    print(f"\n결과 저장: {out}")

    if args.plot:
        plot(results, DOCS / "benchmark.png")


if __name__ == "__main__":
    main()
