"""B3 ↔ B5 的接缝：递过去的每个 Finding 都必须带着真实主键。

## 这个文件钉的是什么

B5 用 `vuln_id` 把探针结果对回 `vulnerabilities` 行。而 B4 的 `Finding`
**没有** `vuln_id` 字段（`runner._vuln_id` 的 docstring 明写了这点，
并说「落库前 B3 必然已经知道真实 id」）。B3 这一侧原先直接把裸 `Finding`
递了过去，于是 `_vuln_id` 退化成 0：

    实测（2026-10-16，靶场 vulnerable-demo-app —— 本仓库最早的那个靶场，
    现由 `ranges/ecommerce` 取代，原文件保留在 `demo/vulnerable-demo-app/`
    供复核，见 `demo/README.md`）：
    探针真的跑了（容器确实起来，每条约 9 秒），但回来时全是 id=0，
    `poc_verify._persist` 一条都对不上，日志刷了 7 行
    「验证结果里的漏洞 0 不属于评估 N，已忽略」，
    最终 7 条漏洞全 `unverified`，而**阶段状态是 completed**。

这条特别值得钉住的原因：失败是「静默 + 状态正常」。总状态 `completed`、
阶段 `completed`、报告正常生成，只有打开漏洞列表才会发现每条都是
「未验证」—— 而「未验证」本身又是一个完全合理的状态（沙箱不可用时会
统一标成它，见 `poc_verify` 的降级路径）。**两种完全不同的成因
（真降级 / id 丢了）产出同一个可见结果。**
"""

from __future__ import annotations

from typing import Any

import pytest

from app.agents.poc_verify import _FindingWithId, _to_finding
from app.analysis.types import VulnType
from app.verify.runner import _vuln_id


class _Row:
    """`Vulnerability` ORM 行的最小替身。

    只放 `_to_finding` 真正读的字段。不用真 ORM 对象是刻意的：
    这条接缝出问题时和数据库无关，把它绑上 MySQL 只会让测试变慢、变脆。
    """

    def __init__(self, row_id: int, vuln_type: str = "sql_injection") -> None:
        self.id = row_id
        self.vuln_type = vuln_type
        self.severity = "critical"
        self.file_path = "app.py"
        self.line_start = 73
        self.line_end = 73
        self.sink_symbol = "execute"
        self.cvss_vector = ""
        self.cvss_score = 9.8
        self.confidence = 0.8
        self.taint_paths: list[Any] = []
        self.title = "SQL 注入"
        self.detection_method = None
        self.code_snippet = "cursor.execute(...)"


def test_B5_能从递给它的对象上取到真实主键() -> None:
    """**这就是那个 bug 的最小复现。**

    修好之前这里拿到的是 0，而不是 42 / 43。
    """
    for row_id in (42, 43, 1, 9999):
        finding = _to_finding(_Row(row_id), VulnType.SQL_INJECTION, None)
        assert _vuln_id(finding) == row_id, (
            f"B5 取到的 id 是 {_vuln_id(finding)}，不是 {row_id} —— "
            f"探针结果会对不回任何一行，而阶段仍然报 completed"
        )


def test_主键为_0_是不可能出现的() -> None:
    """0 是「取不到」的哨兵值，不是合法主键。

    自增主键从 1 起，所以只要 `_vuln_id` 返回 0，就一定是接缝断了。
    把它写成一条独立断言，是为了让失败信息直接说出结论，
    而不是让人去比对一堆数字。
    """
    finding = _to_finding(_Row(7), VulnType.SQL_INJECTION, None)
    assert _vuln_id(finding) != 0


@pytest.mark.parametrize("attr", ["file_path", "line_start", "sink_symbol", "confidence"])
def test_B4_的字段照常透传(attr: str) -> None:
    """包装对象必须**透明**：B5 读 Finding 的其余字段不能受影响。

    这条防的是「修 id 的时候把别的字段挡住了」—— 那会从
    「结果对不上」变成「结果算错」，更难发现。
    """
    row = _Row(42)
    finding = _to_finding(row, VulnType.SQL_INJECTION, None)
    assert getattr(finding, attr) == getattr(row, attr)


def test_B5_读不到的属性照样抛_AttributeError() -> None:
    """不能把「不存在」伪装成「存在且为 None」。

    `runner._vuln_id` 依赖 `getattr(..., None)` 的默认值语义来依次回退
    `vuln_id` / `id` / `vulnerability_id`。若包装层把未知属性返回 None，
    回退逻辑仍然对；但 B5 里任何 `hasattr` 判断都会被骗过 ——
    所以这里钉住「透传真实的 AttributeError」。
    """
    finding = _to_finding(_Row(42), VulnType.SQL_INJECTION, None)
    with pytest.raises(AttributeError):
        _ = finding.这个字段不存在


def test_没有_finding_时不会无限递归() -> None:
    """`__getattr__` + 代理对象最容易踩的坑。

    `_finding` 尚未赋值时若走转发分支，`getattr(self._finding, ...)`
    会再触发一次 `__getattr__` —— 报出来的是 RecursionError，
    而病因是「少赋了一个字段」，两个信息对不上。
    """
    fresh = object.__new__(_FindingWithId)
    with pytest.raises(AttributeError):
        _ = fresh._finding
