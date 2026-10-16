"""项目综合评分与整改排序 —— **全部是纯函数，没有一行 LLM**（B6 设计 §4.3 / §4.4）。

这是本模块最重要的一个文件，因为它承载 L1 最容易被破坏的那一半：

> 项目综合等级、`security_score`、第 3 章的清单顺序、**第 5 章的整改顺序** ——
> 全部由这里的确定性公式产出。LLM 只写第 5 章的文案，**既不打分、也不排序**。

**为什么排序必须在这里**：排序是报告的结论之一（「先修哪个」直接决定读者的行动）。
一旦顺序由模型决定，同一份数据跑两次就可能给出两个不同的行动建议，
而「可复现」是本系统对安全报告的基本承诺。函数式模块的另一个好处是
**可回归**：阈值怎么定、罚分怎么算，都能拿两套靶场的 GROUND_TRUTH 直接跑断言。

## 算法（B6 设计 §4.3）

```
① 单漏洞罚分  penalty(v) = cvss_score(v) × status_factor(v)
              status_factor: verified=1.0  potential=0.4  unverified=0.1
② 综合评分    score = max(0, 100 - Σ penalty(v))          # 0–100，越高越安全
③ 综合等级    自上而下首个命中（见 _grade_for）
```

**为什么要有「一票否决」**：靶场里只有 1 个 CVSS 9.8 的已验证 RCE 时，
`score = 90.2` 会被判成「中危」—— 与事实严重背离。一票否决保证**高危事实不被数量稀释**。
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from app.models.enums import SecurityGrade, Severity, VulnStatus
from app.report.types import SecurityScore, TypeSlice

# ---------------------------------------------------------------------------
# 常量（B6 设计 §4.3；阈值标定见设计 §8 待定项 1）
# ---------------------------------------------------------------------------

#: 验证状态对**可利用性**的折算。`unverified` 只计 0.1 是防夸大：
#: 静态分析能证明「这里的数据流没被净化」，不能证明「这条真的能打」。
STATUS_FACTOR: dict[str, float] = {
    VulnStatus.VERIFIED.value: 1.0,
    VulnStatus.POTENTIAL.value: 0.4,
    VulnStatus.UNVERIFIED.value: 0.1,
    # 动态未复现的条目按 0 计 —— 但注意这是**打分口径**，不是「已确认误报」：
    # 该结论由机器给出、未经人工确认，且实测出现过假阴性（详见
    # `fingerprints.can_conclude_absence` 与 `verify/types.py::Probe.param_is_canonical`）。
    # 报告里它仍会以「动态未复现（机器判定，待人工确认）」留痕。
    VulnStatus.REJECTED.value: 0.0,
}

#: `cvss_score` 缺失时按严重度中位值代入（设计 §4.3 边界处理）。
#: 取中位值而不是取满分，是为了不把「缺数据」变成「补一刀」。
SEVERITY_MEDIAN_CVSS: dict[str, float] = {
    Severity.CRITICAL.value: 9.5,
    Severity.HIGH.value: 8.0,
    Severity.MEDIUM.value: 5.5,
    Severity.LOW.value: 2.5,
}

#: 第 5 章排序用的严重度权重。取 4/3/2/1 而不是 CVSS 本身，是因为
#: 「等级」在这里是**档位**语义（跨档优先于档内微调），用 CVSS 会让两条
#: 同档漏洞仅因 0.1 分差而排在彼此之外，读者看不出区别。
SEVERITY_WEIGHT: dict[str, float] = {
    Severity.CRITICAL.value: 4.0,
    Severity.HIGH.value: 3.0,
    Severity.MEDIUM.value: 2.0,
    Severity.LOW.value: 1.0,
}

#: 可达性：这条路径有多容易被真正走到。
REACHABILITY: dict[str, float] = {
    VulnStatus.VERIFIED.value: 1.0,
    VulnStatus.POTENTIAL.value: 0.6,
    VulnStatus.UNVERIFIED.value: 0.3,
    VulnStatus.REJECTED.value: 0.0,
}

#: 无补丁时的修复成本「估计值」：没有 diff 说明还没人给出改法，
#: 人工评估与实施的代价按经验高于一条现成的 diff。
_NO_PATCH_COST = 2.5
#: 每 40 行改动算一个成本单位 —— 与「±20 行窗口」同量级的直觉刻度
_COST_PER_LINES = 40.0
_MAX_COST = 5.0

GRADE_THRESHOLDS = (40.0, 70.0, 90.0)


# ---------------------------------------------------------------------------
# 纯函数入参
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScoringInput:
    """评分与排序真正需要的**最小事实集**。

    刻意不直接吃 ORM `Vulnerability`：那样这些函数就只能连着数据库一起测，
    而它们恰恰是最该被反复跑断言的部分（阈值回归、排序稳定性）。
    """

    code: str
    severity: str
    status: str
    cvss_score: float | None = None
    #: 漏洞类型（`sql_injection` …）。评分用不到它，但类型占比切片要用，
    #: 而它同样来自 ORM 行 —— 放在同一个入参对象里，省掉一次「两个平行列表」
    #: 的错位风险（那种错位不会报错，只会让饼图和清单对不上）
    vuln_type: str = ""
    #: 补丁改动的行数（用于估算修复成本）；0 表示无补丁
    lines_changed: int = 0
    #: 是否存在可参考的补丁（`status != rejected` 的最新一条）
    has_patch: bool = False

    @classmethod
    def of(cls, vuln: Any, patch: Any | None = None) -> ScoringInput:
        return cls(
            code=str(getattr(vuln, "code", "") or ""),
            severity=_value(getattr(vuln, "severity", None)),
            status=_value(getattr(vuln, "status", None)),
            cvss_score=_opt_float(getattr(vuln, "cvss_score", None)),
            vuln_type=str(getattr(vuln, "vuln_type", "") or ""),
            lines_changed=(
                count_changed_lines(getattr(patch, "diff_content", None)) if patch else 0
            ),
            has_patch=patch is not None,
        )

    @property
    def cvss_estimated(self) -> bool:
        """CVSS 缺失：列非空但默认 0.0，所以 `<= 0` 就是「没记录」。"""
        return not self.cvss_score or self.cvss_score <= 0

    @property
    def effective_cvss(self) -> float:
        if not self.cvss_estimated:
            assert self.cvss_score is not None
            return float(self.cvss_score)
        return SEVERITY_MEDIAN_CVSS.get(self.severity, 5.0)

    @property
    def status_factor(self) -> float:
        return STATUS_FACTOR.get(self.status, 0.1)

    @property
    def penalty(self) -> float:
        return round(self.effective_cvss * self.status_factor, 4)


def _value(enum_or_str: Any) -> str:
    return str(getattr(enum_or_str, "value", enum_or_str) or "")


def _opt_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def count_changed_lines(diff: str | None) -> int:
    """统计 unified diff 里真正增删的行数。

    只数 `+` / `-` 开头的正文行，**排除 `+++` / `---` 文件头** ——
    把文件头算进去会让每个补丁凭空多出 2 行，虽然不影响排序的相对关系，
    但它会出现在报告的成本估算里，属于「一眼能看出算错了」的那种错。
    """
    if not diff:
        return 0
    changed = 0
    for line in diff.splitlines():
        if line.startswith(("+++", "---", "@@", "diff ", "index ")):
            continue
        if line.startswith(("+", "-")):
            changed += 1
    return changed


# ---------------------------------------------------------------------------
# ① 综合评分
# ---------------------------------------------------------------------------


def compute_security_score(rows: list[ScoringInput]) -> SecurityScore:
    """漏洞集合 → `SecurityScore`（↔ `assessments.security_score` / `security_grade`）。"""
    breakdown: dict[str, float] = {sev.value: 0.0 for sev in Severity}
    total_penalty = 0.0
    for row in rows:
        penalty = row.penalty
        breakdown[row.severity] = round(breakdown.get(row.severity, 0.0) + penalty, 4)
        total_penalty += penalty

    score = round(max(0.0, 100.0 - total_penalty), 2)
    grade, veto = _grade_for(rows, score)
    return SecurityScore(
        score=score,
        grade=grade,
        veto=veto,
        breakdown={**breakdown, "total_penalty": round(total_penalty, 4)},
        incomplete=any(r.cvss_estimated for r in rows),
    )


def _grade_for(rows: list[ScoringInput], score: float) -> tuple[SecurityGrade, bool]:
    """综合等级映射，**自上而下首个命中**（B6 设计 §4.3 表）。

    只有 `verified` 参与一票否决与「已验证高危」判定：`potential` / `unverified`
    是「可能有问题」，让它们触发一票否决等于把静态误报升格成项目级结论。
    """
    verified = [r for r in rows if r.status == VulnStatus.VERIFIED.value]
    has_verified_critical = any(r.severity == Severity.CRITICAL.value for r in verified)
    has_verified_high = any(r.severity == Severity.HIGH.value for r in verified)

    if has_verified_critical:
        return SecurityGrade.CRITICAL, True
    if score < GRADE_THRESHOLDS[0]:
        return SecurityGrade.CRITICAL, False
    if score < GRADE_THRESHOLDS[1] or has_verified_high:
        return SecurityGrade.HIGH, False
    if score < GRADE_THRESHOLDS[2]:
        return SecurityGrade.MEDIUM, False
    return SecurityGrade.SAFE, False


# ---------------------------------------------------------------------------
# ② 风险大盘：分布矩阵与类型占比
# ---------------------------------------------------------------------------


def build_severity_matrix(rows: list[ScoringInput]) -> dict[tuple[str, str], int]:
    """`(severity, status) → 计数`。

    刻意保留 (严重度, 状态) 的**联合**分布而不是两条独立计数：
    报告要回答的是「有几条高危**并且已经验证**」—— 拆成两个维度就答不了。
    """
    counter = Counter((r.severity, r.status) for r in rows)
    return dict(counter)


def build_type_distribution(
    rows: list[ScoringInput], labels: dict[str, str] | None = None
) -> list[TypeSlice]:
    """漏洞类型占比。`ratio` 在这里算好，模板不做除法（设计 §4.1 ②）。

    排序 `count` 降序、`category` 升序：**保证同一份数据两次生成得到同一个饼图**。
    只按 count 排，会在并列时依赖字典插入顺序 —— 那是个安静的不确定性来源，
    而且它只在并列时才出现，靠抽查发现不了。
    """
    if not rows:
        return []
    counter = Counter(r.vuln_type or "未分类" for r in rows)
    total = sum(counter.values())
    label_map = labels or {}
    slices = [
        TypeSlice(
            category=category,
            label=label_map.get(category, category),
            count=count,
            ratio=round(count / total, 4) if total else 0.0,
        )
        for category, count in counter.items()
    ]
    slices.sort(key=lambda s: (-s.count, s.category))
    return slices


# ---------------------------------------------------------------------------
# ③ 第 3 章清单顺序 & 第 5 章整改顺序
# ---------------------------------------------------------------------------

#: 第 3 章固定按 severity 降序 → cvss 降序 → code 升序（B6 设计 §4.4）
_SEVERITY_ORDER = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
}


def chapter3_sort_key(row: ScoringInput) -> tuple[int, float, str]:
    return (
        _SEVERITY_ORDER.get(row.severity, 9),
        -float(row.cvss_score or 0.0),
        row.code,
    )


def fix_cost(row: ScoringInput) -> float:
    """修复成本（越小越容易修）。

    有补丁时按改动行数估：`1 + 行数/40`，上限 5；
    无补丁时取经验值 2.5 —— **没有补丁不等于容易修**，只说明还没人给出改法。
    """
    if not row.has_patch:
        return _NO_PATCH_COST
    return min(_MAX_COST, 1.0 + max(0, row.lines_changed) / _COST_PER_LINES)


#: 排序因子名，进 `Recommendation.priority_factors`，供「为什么它排在前面」当场复算
FACTOR_SEVERITY = "等级权重"
FACTOR_REACHABILITY = "可达性"
FACTOR_FIX_COST = "修复成本"
FACTOR_PRIORITY = "优先级"


def priority_of(row: ScoringInput) -> tuple[float, dict[str, float]]:
    """整改优先级 = **等级 × 可达性 × 修复成本**（B6 设计 §4.4）。

    ⚠️ **修复成本以倒数进入公式**，这是对设计文档字面写法的一处刻意收紧：
    若按字面直接 `× 成本`，语义会反过来 —— 「改起来最麻烦的漏洞」会排到最前面，
    而第 5 章的语义是「先修什么」。设计文档真正要表达的是「优先修
    **又危险又好修**的」（§4.4 的排序目标），所以这里用 `1/成本`：
    成本越低、优先级越高，同时保留「同等级同可达性时，代价小的先修」这个有用信号。

    并列时由调用方按 `code` 升序兜底 —— 保证同数据两次生成顺序完全一致。
    """
    severity_weight = SEVERITY_WEIGHT.get(row.severity, 1.0)
    reachability = REACHABILITY.get(row.status, 0.3)
    cost = fix_cost(row)
    priority = severity_weight * reachability * (1.0 / cost)
    return round(priority, 6), {
        FACTOR_SEVERITY: severity_weight,
        FACTOR_REACHABILITY: reachability,
        FACTOR_FIX_COST: round(cost, 4),
        FACTOR_PRIORITY: round(priority, 6),
    }


def rank_recommendations(rows: list[ScoringInput]) -> list[tuple[ScoringInput, dict[str, float]]]:
    """第 5 章整改项的确定性排序。

    **动态未复现（`rejected`）的条目不进整改清单** —— 它们的 `可达性` 为 0、
    优先级为 0，即使保留也会沉到末尾，而报告里出现「已排除的漏洞的整改建议」
    本身就会让读者困惑。排除是明确的语义，不是排序的副产品。

    ⚠️ 但「不进清单」**不等于「可以不管」**：这是机器结论，未经人工确认，
    报告在第 3 章留痕、并在第 5 章末尾报出条数（`excluded_rejected`），
    措辞明写「待人工确认」。**不要**把这里的排除当作「误报已确认」——
    实测出现过两条真 SQL 注入被机器判为未复现。
    """
    scored = [(row, priority_of(row)[1]) for row in rows if row.status != VulnStatus.REJECTED.value]
    # 主键优先级降序；次键 `code` 升序 —— `code` 全局唯一（`uk_vulnerabilities_code`），
    # 因此排序结果**完全确定**，不依赖输入顺序
    scored.sort(key=lambda item: (-item[1][FACTOR_PRIORITY], item[0].code))
    return scored


def count_rejected(rows: list[ScoringInput]) -> int:
    return sum(1 for r in rows if r.status == VulnStatus.REJECTED.value)


__all__ = [
    "FACTOR_FIX_COST",
    "FACTOR_PRIORITY",
    "FACTOR_REACHABILITY",
    "FACTOR_SEVERITY",
    "GRADE_THRESHOLDS",
    "REACHABILITY",
    "SEVERITY_MEDIAN_CVSS",
    "SEVERITY_WEIGHT",
    "STATUS_FACTOR",
    "ScoringInput",
    "build_severity_matrix",
    "build_type_distribution",
    "chapter3_sort_key",
    "compute_security_score",
    "count_changed_lines",
    "count_rejected",
    "fix_cost",
    "priority_of",
    "rank_recommendations",
]
