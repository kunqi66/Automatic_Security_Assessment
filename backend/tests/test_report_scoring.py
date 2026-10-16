"""评分与排序的纯函数测试（B6 设计 §4.3 / §4.4）。

## 这一组测试守的是 L1 最容易被破坏的那一半

L1 说「漏洞是否存在、类型、严重度、CVSS、状态、链的节点与边、评分、整改优先级
全部来自确定性代码」。前面几项由 B4/B5 保证，**评分与整改优先级是在这里保证的** ——
而这两项恰恰是「交给 LLM 看起来最自然」的两项（「让模型判断哪个更该先修」）。

所以本文件的断言全部是**具体的数字与具体的顺序**，不是「大于 0」这种软断言：
排序是报告的结论之一，结论必须能逐位复算。
"""

from __future__ import annotations

import pytest

from app.models.enums import SecurityGrade, VulnStatus
from app.report.scoring import (
    GRADE_THRESHOLDS,
    SEVERITY_MEDIAN_CVSS,
    STATUS_FACTOR,
    ScoringInput,
    build_severity_matrix,
    build_type_distribution,
    chapter3_sort_key,
    compute_security_score,
    count_changed_lines,
    count_rejected,
    rank_recommendations,
)


def row(
    code: str,
    *,
    severity: str = "high",
    status: str = "unverified",
    cvss: float = 8.0,
    vuln_type: str = "sql_injection",
    lines: int = 0,
    has_patch: bool = False,
) -> ScoringInput:
    return ScoringInput(
        code=code,
        severity=severity,
        status=status,
        cvss_score=cvss,
        vuln_type=vuln_type,
        lines_changed=lines,
        has_patch=has_patch,
    )


# ---------------------------------------------------------------------------
# 一、单漏洞罚分与综合评分
# ---------------------------------------------------------------------------


def test_罚分等于_cvss_乘状态折算() -> None:
    assert row("V1", status="verified", cvss=9.8).penalty == pytest.approx(9.8)
    assert row("V1", status="potential", cvss=10.0).penalty == pytest.approx(4.0)
    assert row("V1", status="unverified", cvss=10.0).penalty == pytest.approx(1.0)
    # 已复核排除 = 已判定「不是漏洞」，不该继续扣分
    assert row("V1", status="rejected", cvss=10.0).penalty == 0.0


def test_状态折算表覆盖全部四态() -> None:
    assert set(STATUS_FACTOR) == {s.value for s in VulnStatus}
    # `unverified` 只计 0.1 是防夸大：静态分析能证明「没净化」，
    # 不能证明「真能打」。这个值变了，等于改变了整个系统的报告口径。
    assert STATUS_FACTOR["unverified"] == 0.1


def test_综合评分与等级() -> None:
    rows = [
        row("V1", severity="critical", status="verified", cvss=9.8),
        row("V2", severity="medium", status="unverified", cvss=5.0),
    ]
    score = compute_security_score(rows)

    # 100 - (9.8 * 1.0) - (5.0 * 0.1) = 89.7
    assert score.score == pytest.approx(89.70, abs=0.01)
    assert score.veto is True
    assert score.grade == SecurityGrade.CRITICAL
    assert score.breakdown["critical"] == pytest.approx(9.8)
    assert score.breakdown["total_penalty"] == pytest.approx(10.3)


def test_无来源_score_下限为_0() -> None:
    rows = [row(f"V{i}", severity="critical", status="verified", cvss=9.9) for i in range(20)]
    assert compute_security_score(rows).score == 0.0


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (39.99, SecurityGrade.CRITICAL),
        (40.0, SecurityGrade.HIGH),  # `score < 40` 不成立 → 掉出极高危
        (69.99, SecurityGrade.HIGH),
        (70.0, SecurityGrade.MEDIUM),
        (89.99, SecurityGrade.MEDIUM),
        (90.0, SecurityGrade.SAFE),
    ],
)
def test_等级阈值逐档验边界(score: float, expected: SecurityGrade) -> None:
    """阈值是**报告口径**，不是可调参数 —— 必须逐档钉住边界值。

    只测「高危/低危各一个」的话，`<` 写成 `<=` 这种改动不会被任何用例发现，
    而它会让「恰好 70 分」的项目从「中危」变成「高危」。

    ⚠️ 这里用一个 `severity=low / status=verified / cvss=100-score` 的构造行：
    CVSS 超过 10 是**合成值**，目的只是让罚分精确落在阈值上。
    用真实的 CVSS 组合要凑出「39.99 分」得堆十几行，反而看不出边界在哪。
    严重度取 `low` 是为了避开「已验证的严重/高危」那两个特殊分支。
    """
    rows = [row("V1", severity="low", status="verified", cvss=100 - score)]
    result = compute_security_score(rows)

    assert result.score == pytest.approx(score, abs=0.01)
    assert result.grade == expected
    assert result.veto is False


def test_没有漏洞时满分且等级安全() -> None:
    score = compute_security_score([])
    assert score.score == 100.0
    assert score.grade == SecurityGrade.SAFE
    assert score.veto is False
    assert score.incomplete is False


def test_已验证的严重漏洞一票否决() -> None:
    """**这条是设计里最重要的一条防稀释规则。**

    靶场里只有 1 个 CVSS 9.8 的已验证 RCE 时，`score = 90.2`，
    按分数该判「中危」—— 与事实严重背离。一票否决保证高危事实不被数量稀释。
    """
    rows = [row("V1", severity="critical", status="verified", cvss=9.8)]
    score = compute_security_score(rows)

    assert score.score > GRADE_THRESHOLDS[2], "分数本身在中危区间"
    assert score.veto is True
    assert score.grade == SecurityGrade.CRITICAL


def test_未验证的严重漏洞不触发一票否决() -> None:
    """`potential` / `unverified` 是「可能有问题」。

    让它们触发一票否决，等于把静态误报升格成项目级结论 ——
    而误报是静态分析不可避免的一部分。
    """
    for status in ("unverified", "potential"):
        score = compute_security_score([row("V1", severity="critical", status=status, cvss=9.8)])
        assert score.veto is False


def test_已验证的高危直接把等级抬到高危() -> None:
    rows = [row("V1", severity="high", status="verified", cvss=3.0)]
    score = compute_security_score(rows)
    assert score.score > GRADE_THRESHOLDS[1], "分数在中危区间"
    assert score.grade == SecurityGrade.HIGH


# ---------------------------------------------------------------------------
# 二、CVSS 缺失时的代入
# ---------------------------------------------------------------------------


def test_缺_cvss_时按严重度中位值代入并标记不完整() -> None:
    rows = [row("V1", severity="critical", status="verified", cvss=0.0)]
    score = compute_security_score(rows)

    assert rows[0].cvss_estimated is True
    # 代入的是中位值而不是满分 —— 不把「缺数据」变成「补一刀」
    assert rows[0].effective_cvss == SEVERITY_MEDIAN_CVSS["critical"]
    assert score.incomplete is True
    assert score.score == pytest.approx(100 - 9.5, abs=0.01)


def test_有_cvss_时不标记不完整() -> None:
    score = compute_security_score([row("V1", cvss=7.5)])
    assert score.incomplete is False


# ---------------------------------------------------------------------------
# 三、风险大盘的两个投影
# ---------------------------------------------------------------------------


def test_严重度状态联合分布() -> None:
    rows = [
        row("V1", severity="high", status="verified"),
        row("V2", severity="high", status="unverified"),
        row("V3", severity="low", status="verified"),
    ]
    matrix = build_severity_matrix(rows)

    assert matrix[("high", "verified")] == 1
    assert matrix[("high", "unverified")] == 1
    assert matrix[("low", "verified")] == 1
    # 刻意保留联合分布：报告要能回答「有几条高危**并且已通过验证**」，
    # 拆成两个独立计数就答不了
    assert ("high", "unverified") in matrix


def test_类型占比计算与确定性并列处理() -> None:
    rows = [
        row("V1", vuln_type="sql_injection"),
        row("V2", vuln_type="xss"),
        row("V3", vuln_type="sql_injection"),
    ]
    slices = build_type_distribution(rows, {"sql_injection": "SQL 注入", "xss": "跨站脚本（XSS）"})

    assert [(s.category, s.count) for s in slices] == [("sql_injection", 2), ("xss", 1)]
    assert slices[0].label == "SQL 注入"
    assert slices[0].ratio == pytest.approx(2 / 3, abs=0.001)


def test_类型占比并列时按类名升序() -> None:
    """**并列时不能依赖字典插入顺序。**

    那是个安静的不确定性来源，而且只在并列时出现 —— 靠抽查发现不了，
    但会让「同一份数据两次生成得到同一个饼图」这句话不成立。
    """
    rows = [row("V1", vuln_type="zebra"), row("V2", vuln_type="alpha")]
    assert [s.category for s in build_type_distribution(rows)] == ["alpha", "zebra"]


def test_未分类的漏洞进未分类桶() -> None:
    slices = build_type_distribution([row("V1", vuln_type="")])
    assert slices[0].category == "未分类"


# ---------------------------------------------------------------------------
# 四、排序：第 3 章清单顺序 & 第 5 章整改顺序
# ---------------------------------------------------------------------------


def test_第3章按严重度_cvss_编号三级排序() -> None:
    rows = [
        row("V3", severity="high", cvss=8.0),
        row("V1", severity="critical", cvss=9.0),
        row("V2", severity="critical", cvss=9.8),
        row("V0", severity="critical", cvss=9.8),
    ]
    ordered = [r.code for r in sorted(rows, key=chapter3_sort_key)]
    assert ordered == ["V0", "V2", "V1", "V3"]


def test_整改排序主键是优先级_次键是编号() -> None:
    rows = [
        row("V2", severity="critical", status="verified", cvss=9.8),
        row("V1", severity="critical", status="verified", cvss=9.8),
        row("V3", severity="low", status="unverified", cvss=2.0),
    ]
    ranked = rank_recommendations(rows)
    # V1 / V2 因子完全相同 → 靠 code 升序兜底，结果完全确定
    assert [r.code for r, _ in ranked] == ["V1", "V2", "V3"]


def test_整改排序与输入顺序无关() -> None:
    """**同一份数据两次生成必须得到同一个顺序。**

    这条是「可复现」在排序上的直接体现。故意打乱输入顺序跑两遍 ——
    若实现里依赖了输入顺序（比如用了不稳定的 sort 键），这里会红。
    """
    import random

    rows = [
        row(f"V{i}", severity=s, status=st, cvss=c)
        for i, (s, st, c) in enumerate(
            [
                ("critical", "verified", 9.8),
                ("high", "potential", 8.1),
                ("high", "unverified", 7.5),
                ("medium", "verified", 5.5),
                ("low", "unverified", 3.1),
                ("critical", "unverified", 9.1),
            ]
        )
    ]
    baseline = [r.code for r, _ in rank_recommendations(list(rows))]

    for _ in range(5):
        shuffled = list(rows)
        random.shuffle(shuffled)  # noqa: S311 - 测试里就是要制造顺序扰动
        assert [r.code for r, _ in rank_recommendations(shuffled)] == baseline


def test_已复核排除的条目不进整改清单() -> None:
    """排除是明确的语义，不是排序的副产品。

    报告里出现「已排除的漏洞的整改建议」本身就会让读者困惑 ——
    而它之所以会被排到末尾，只是因为可达性为 0，那是巧合不是设计。
    """
    rows = [
        row("V1", status="rejected"),
        row("V2", status="verified"),
        row("V3", status="rejected"),
    ]
    assert [r.code for r, _ in rank_recommendations(rows)] == ["V2"]
    assert count_rejected(rows) == 2


def test_修复成本以倒数进入优先级() -> None:
    """**这是对设计文档字面写法的一处刻意收紧。**

    设计 §4.4 字面写「等级 × 可达性 × 修复成本」。若直接相乘，语义会反过来 ——
    「改起来最麻烦的漏洞」会排到最前面，而第 5 章的语义是「先修什么」。
    用 `1/成本` 之后，同等级同可达性时「代价小的先修」这个有用信号被保留，
    而「又危险又好修」的排在前面。
    """
    cheap = row("V1", severity="high", status="verified", lines=2, has_patch=True)
    expensive = row("V2", severity="high", status="verified", lines=400, has_patch=True)
    nopatch = row("V3", severity="high", status="verified")

    ranked = [r.code for r, _ in rank_recommendations([expensive, nopatch, cheap])]
    # 无补丁的成本 2.5，落在「2 行」与「400 行」之间
    assert ranked == ["V1", "V3", "V2"]


def test_优先级因子明细可当场复算() -> None:
    rows = [row("V1", severity="critical", status="verified", cvss=9.8, lines=10, has_patch=True)]
    _, factors = rank_recommendations(rows)[0]

    assert factors["等级权重"] == 4.0
    assert factors["可达性"] == 1.0
    assert factors["修复成本"] == pytest.approx(1 + 10 / 40)
    assert factors["优先级"] == pytest.approx(
        factors["等级权重"] * factors["可达性"] / factors["修复成本"]
    )


# ---------------------------------------------------------------------------
# 五、diff 行数统计
# ---------------------------------------------------------------------------


def test_diff_行数统计排除文件头() -> None:
    diff = "\n".join(
        [
            "diff --git a/app/x.py b/app/x.py",
            "index 111..222 100644",
            "--- a/app/x.py",
            "+++ b/app/x.py",
            "@@ -1,3 +1,4 @@",
            "-old",
            "+new",
            "+added",
            " context",
        ]
    )
    # 把 +++ / --- 算进去会让每个补丁凭空多出 2 行 —— 它出现在报告的成本估算里，
    # 属于「一眼能看出算错了」的那种错
    assert count_changed_lines(diff) == 3
    assert count_changed_lines(None) == 0
    assert count_changed_lines("") == 0
