"""靶场基准：对 `ranges/*` 算召回率与误报（PRD §10.4）。

    uv run python tests/benchmark.py            # 只跑静态分析（不需要 Docker）
    uv run python tests/benchmark.py --dynamic  # ⚠️ 尚未实现，见 main() 里的说明

## 这个脚本存在的意义

把「我觉得我的工具还行」换成一个**可复现、可证伪**的数字。所以它做了三件事，
每一件都是为了让人能来反驳：

1. **分母来自 `GROUND_TRUTH.yaml`，不来自代码。** 分析器改一行，分子会动，
   分母不会 —— 否则"提高召回率"最简单的方法就变成了改基准。
2. **匹配规则是明确的、写出来的。** （类别 + 文件 + 行号窗口）
   规则藏在代码里而不写在输出里，读者就只能相信这个数字，没法检验它。
3. **漏掉的条目逐条列出来，不折叠成一个百分比。**
   `6/8` 是结论，`V6、V7 是什么、为什么漏` 才是信息。

## 匹配规则（`_match`）

一条 ground truth 算命中，当且仅当存在一条 finding 同时满足：

* **类别相同** —— 比 `vuln_type` 的字面值，**不做归一化**。
  基准里写 `hardcoded_secret`，就得拿 `hardcoded_secret` 去比；
  用 `canonical_vuln_type()` 归一化过再比，会让
  `hardcoded_secret` 与 `info_disclosure` 互相顶替，
  于是 `usercenter-debug-endpoint`（真正的调试口）会被
  `settings.py` 的密钥 finding 顶成"命中" —— 那正是本基准要区分的两件事。
* **文件同名** —— 只比 `basename`，因为 finding 的 `file_path` 可能是
  相对靶场根、也可能是绝对路径，取决于调用方式。
* **行号落在 `[line_start - WINDOW, line_end + WINDOW]` 内** ——
  留窗口是承认一个事实：缺陷的"载体行"与"检出点"可以差一两行
  （例如 `target = os.path.join(...)` 与 `uploaded.save(target)`）。
  窗口取值写在 `LINE_WINDOW`，不藏在逻辑里。

一条 ground truth 可以被多条 finding 命中（`/search` 的两条 SQL 注入探针
就命中同一条），**不额外加分** —— 召回率算的是"这条漏洞找到没有"。
反过来，一条 finding 若匹配不上任何 ground truth，计一次**误报**。
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# 允许 `uv run python tests/benchmark.py` 直接跑（把 backend/ 放进 sys.path）
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.analysis import analyze_project  # noqa: E402

RANGES_DIR = Path(__file__).resolve().parents[2] / "ranges"

#: 行号匹配窗口（见模块 docstring）。取 2：够容纳"载体行 vs 检出点"的常见偏移，
#: 又小到不会把同一个文件里两个相距很远的缺陷混成一条。
LINE_WINDOW = 2


@dataclass
class EntryResult:
    entry_id: str
    prd_id: str | None
    category: str
    file: str
    line: int
    line_end: int
    detected: bool
    note: str = ""

    def covers(self, line: int) -> bool:
        """finding 的行号是否落在本条基准的区间（含窗口）内。"""
        return self.line - LINE_WINDOW <= line <= self.line_end + LINE_WINDOW


@dataclass
class RangeResult:
    name: str
    total_findings: int
    entries: list[EntryResult] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    prd_mapping: dict[str, list[str]] = field(default_factory=dict)

    @property
    def detected(self) -> int:
        return sum(1 for e in self.entries if e.detected)

    @property
    def total(self) -> int:
        return len(self.entries)

    def prd_recall(self) -> tuple[int, int, list[str]]:
        """按 PRD §10 的编号算一遍 —— 同一份基准的另一种切法。

        返回 `(命中数, 总数, 半命中的编号)`。

        **"半命中"这一档是必须的**：一个 PRD 编号可能有多条载体
        （V8 的"调试接口未关闭"在基准里是"硬编码密钥"+"调试路由"两条），
        只找到其中一条时说"命中"会高估、说"漏了"会低估。
        折成一个数就必然丢掉这个区别，所以单列出来。
        """
        by_id = {e.entry_id: e for e in self.entries}
        hit = 0
        partial: list[str] = []
        for prd_id, ids in self.prd_mapping.items():
            present = [by_id[i] for i in ids if i in by_id]
            found = sum(1 for e in present if e.detected)
            if found:
                hit += 1
            if found and found < len(present):
                partial.append(prd_id)
        return hit, len(self.prd_mapping), partial


def _load_ground_truth(range_dir: Path) -> dict[str, Any]:
    with (range_dir / "GROUND_TRUTH.yaml").open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _category_of(finding: Any) -> str:
    """finding 的类别字面值。`VulnType.SQL_INJECTION` → `sql_injection`。"""
    return str(getattr(finding, "vuln_type", "")).split(".")[-1].lower()


def _relates(entry: EntryResult, finding: Any) -> bool:
    """类别 + 文件名 + 行号区间，三条全中才算这条 finding 与本条基准相关。"""
    if _category_of(finding) != entry.category:
        return False
    if Path(str(getattr(finding, "file_path", ""))).name != entry.file:
        return False
    return entry.covers(int(getattr(finding, "line_start", 0) or 0))


def _match(entries: list[EntryResult], findings: list[Any]) -> None:
    """就地标记命中。"""
    for entry in entries:
        entry.detected = any(_relates(entry, f) for f in findings)


def run_range(range_dir: Path) -> RangeResult:
    truth = _load_ground_truth(range_dir)
    result = analyze_project(range_dir)
    findings = list(result.findings)

    entries = [
        EntryResult(
            entry_id=item["id"],
            prd_id=item.get("prd_id"),
            category=str(item["category"]),
            file=str(item["file"]),
            line=int(item["line_start"]),
            line_end=int(item.get("line_end") or item["line_start"]),
            detected=False,
        )
        for item in truth["vulnerabilities"]
    ]

    _match(entries, findings)

    fps: list[str] = []
    for finding in findings:
        if not any(_relates(e, finding) for e in entries):
            name = Path(str(getattr(finding, "file_path", ""))).name
            line = int(getattr(finding, "line_start", 0) or 0)
            fps.append(f"{_category_of(finding)} {name}:{line}")

    return RangeResult(
        name=range_dir.name,
        total_findings=len(findings),
        entries=entries,
        false_positives=fps,
        prd_mapping=truth.get("prd_mapping") or {},
    )


def _print_result(res: RangeResult) -> RangeResult:
    print(f"\n=== 靶场：{res.name} ===")
    print(f"静态分析产出 finding {res.total_findings} 条\n")
    for entry in res.entries:
        mark = "命中" if entry.detected else "**漏**"
        prd = entry.prd_id or "—"
        print(f"  [{mark}] {prd:<3} {entry.category:<18} {entry.file}:{entry.line}")
    missed = [e for e in res.entries if not e.detected]
    print(
        f"\n  静态召回： {res.detected}/{res.total} ({res.detected / res.total * 100:.1f}%)"
        if res.total
        else "  静态召回： 0/0"
    )
    if missed:
        # 列 `entry_id` 而不是 `prd_id`：一个 PRD 编号可以有多条载体，
        # 只说"V8 漏了"会与"V8 的另一条命中了"打架，读者无从判断到底漏了什么。
        print(f"  漏掉的：   {'、'.join(e.entry_id for e in missed)}")
    print(f"  误报：     {len(res.false_positives)}")
    for fp in res.false_positives:
        print(f"             {fp}")
    if res.prd_mapping:
        hit, total, partial = res.prd_recall()
        tail = f"（其中 {'、'.join(partial)} 为半命中）" if partial else ""
        print(f"  按 PRD §10 编号： {hit}/{total} ({hit / total * 100:.1f}%){tail}")
    return res


def main() -> int:
    parser = argparse.ArgumentParser(description="靶场基准（PRD §10.4）")
    parser.add_argument("--dynamic", action="store_true", help="再跑一遍动态验证（需要沙箱）")
    parser.add_argument("--range", dest="only", default=None, help="只跑某一个靶场")
    args = parser.parse_args()

    targets = sorted(p for p in RANGES_DIR.iterdir() if (p / "GROUND_TRUTH.yaml").exists())
    if args.only:
        targets = [p for p in targets if p.name == args.only]
    if not targets:
        print(f"没找到任何带 GROUND_TRUTH.yaml 的靶场（{RANGES_DIR}）")
        return 2

    results = [_print_result(run_range(d)) for d in targets]

    total_detected = sum(r.detected for r in results)
    total_entries = sum(r.total for r in results)
    total_fp = sum(len(r.false_positives) for r in results)
    prd_hit = sum(r.prd_recall()[0] for r in results)
    prd_total = sum(r.prd_recall()[1] for r in results)
    prd_partial = [p for r in results for p in r.prd_recall()[2]]
    print("\n" + "=" * 60)
    print(
        f"合计静态召回： {total_detected}/{total_entries} "
        f"({total_detected / total_entries * 100:.1f}%)   误报 {total_fp}"
    )
    # PRD §10.4 的示例输出锚在 PRD §10 的 8 条上，所以这个数也单独给一行 ——
    # 两个分母都给，是因为它们的差本身就是信息（多出来的那些是探针契约要求的植入点）。
    tail = f"（其中 {'、'.join(prd_partial)} 为半命中）" if prd_partial else ""
    print(
        f"其中 PRD §10 的 {prd_total} 条： {prd_hit}/{prd_total} "
        f"({prd_hit / prd_total * 100:.1f}%){tail}"
    )
    if args.dynamic:
        # ⚠️ **`--dynamic` 目前没有实现。** 原先它只被 parse、从没被用过 ——
        # 传了这个标志，输出与不传**逐字节相同**，而脚本开头却写着
        # 「再跑一遍动态验证，算最终精确率」。一个静默失效的开关比没有这个开关更坏：
        # 它让人以为拿到的是"最终精确率"，实际拿到的是静态那一份。
        #
        # 为什么没有顺手补上（记在这里，免得下一个人以为是漏了）：
        # 动态验证需要 `Sandbox` + `WorkspaceHandle`，而本项目的 workspace 是
        # **绑定在数据库里的项目实体**上的（`projects.service.workspace_of`
        # / `sync_to_data_plane` —— 源码要先同步到 ECS 的宿主目录）。
        # 要用就得先建项目行、连 MySQL，而这个脚本的立身之本恰恰是
        # 「分母来自 GROUND_TRUTH.yaml、跑起来不需要任何外部依赖」。
        # 把 DB 引进来会毁掉它「可复现、可证伪」的前提，所以这是**另一件事**，
        # 不该在这里顺手做。
        #
        # 那条 PRD §10.4 要的「误报剔除 / 最终精确率」数字，
        # 目前从**真实流水线跑完的评估**里取（见 `docs/探针路由绑定.md` §6）：
        # 静态 15 条 finding → 动态后 8 verified / 7 potential / 0 rejected。
        print(
            "\n--dynamic 尚未实现：动态验证需要数据库里的项目实体，"
            "本脚本刻意不依赖 DB。\n"
            "最终精确率请从跑完的评估里取，见 backend/docs/探针路由绑定.md §6。",
            file=sys.stderr,
        )
        return 2
    print("\n（未跑动态验证。加 --dynamic 可以看误报被剔除多少 —— 需要沙箱可用。）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
