"""`report_gen` 阶段：填表达层文案 + 装配报告（B3 设计 §4.5）。

## 本阶段是整个系统里唯一「可以没有 LLM」的地方，也是唯一「必须有 LLM」的地方

说它**可以没有**：所有文案都有确定性模板的等价产物（`app/llm/fallback.py`），
`DEEPSEEK_API_KEY` 为空时报告照样出，只是 `llm_model` 标 `template`。
说它**必须有**：用点 ① 的漏洞描述（`vulnerabilities.description`）除了这里
没有任何其它写入方 —— 不填的话，报告里每条漏洞的「描述」那一栏是空的。

这两句话不矛盾：**必须有的是「文案」，不是「模型」**。模板兜底保证了后者可以缺席。

## 为什么漏洞描述在这里填，而不是在 `code_audit`

`code_audit` 的职责边界是「调 B4、搬 Finding、落库」，它是**纯计算**的 ——
模块 docstring 里写死了这一条，为的是让「拿掉 LLM，这一阶段的结论一字不变」
在阶段粒度上直接成立（那一阶段根本没接 LLM）。

把用点 ① 放在审计阶段会破坏这个性质：审计阶段从此有了一个网络依赖，
而它跑在最前面 —— 一次 LLM 抖动会让整轮评估的第一步就慢下来。
放在最后（本阶段）则相反：前面四个阶段全是确定性的、可以在没有网络的环境里
完整跑通，表达层集中在收尾一次性做完，失败了也只是报告措辞退化成模板。

## 事务

**不 commit**（T4）。`ReportService.generate(commit=False)` 就是为这个场景留的
参数 —— 落盘（写文件）与写库（`reports` 行、`assessments` 评分两列）
必须和阶段行一起提交，否则崩溃后会留下「文件在、行不在」或反过来的中间态。
"""

from __future__ import annotations

import asyncio
from typing import Any

from sqlalchemy import select

from app.agents.base import BaseAgent, FaultTolerance
from app.core.logging import get_logger
from app.models.enums import StageName
from app.orchestrator.context import AssessmentContext
from app.orchestrator.events import LogLevel

logger = get_logger(__name__)

#: 一次评估最多为多少条漏洞生成描述文案。
#:
#: 超过这个数就**只给前 N 条生成、其余用模板** —— 而「前 N 条」按严重度降序，
#: 因为高危漏洞的描述才是报告里真正会被读的部分。对第 200 条中危漏洞
#: 花掉一次模型调用，是在用预算换没人看的内容。
_MAX_DESCRIBED = 40


class ReportGenAgent(BaseAgent[AssessmentContext, dict[str, Any]]):
    """报告生成。**致命档** —— 报告是这条流水线的交付物。

    `SKIPPABLE` 意味着「跑完全程但没交东西」，用户等了二十分钟得到一个
    状态为「成功」的空评估。这是本系统里最没有价值的一种失败。
    """

    name = "报告生成"
    stage = StageName.REPORT_GEN
    fault_tolerance = FaultTolerance.FATAL

    async def run(self, ctx: AssessmentContext, inp: AssessmentContext) -> dict[str, Any]:
        await self.emit(LogLevel.INFO, "开始装配评估报告")

        described = await self._fill_descriptions(ctx)
        if described:
            await self.emit(LogLevel.INFO, f"已为 {described} 条漏洞生成描述文案")

        draft = await self._generate(ctx)
        await self._report_summary(ctx, draft)
        return _summary(draft)

    def apply_output(self, ctx: AssessmentContext, out: dict[str, Any]) -> None:
        """报告内容不落上下文。

        `ReportDraft` 里有 `html` / `markdown` 两个完整文档（几十 KB 到几 MB）——
        塞进 `result_ref` 会直接把那个 JSON 列撑爆，而它的唯一用途是续跑时
        还原状态，没有任何一个后续阶段需要读报告正文。快照里只标一句
        「报告已生成」，正文在 `reports` 表与磁盘上。
        """
        ctx.stage_outputs[self.stage.value] = "报告已生成"

    # ------------------------------------------------------------------
    # 用点 ①：漏洞描述
    # ------------------------------------------------------------------

    async def _fill_descriptions(self, ctx: AssessmentContext) -> int:
        """给 `description` 为空的漏洞补一段中文描述。

        **只补空的**（`description == ""`）：重跑本阶段时不该把上一轮已经
        写好的文案推倒重来 —— 那既浪费预算，又会让「同一份报告重跑两次
        措辞不一样」，而报告是给人比对的东西。

        按严重度降序取前 `_MAX_DESCRIBED` 条：见该常量的说明。
        """
        from app.llm.expressions import DEFAULT_CONCURRENCY, describe_finding
        from app.models.vulnerability import Vulnerability

        rows = list(
            await self.deps.session.scalars(
                select(Vulnerability)
                .where(
                    Vulnerability.assessment_id == ctx.assessment_id,
                    Vulnerability.description == "",
                )
                .order_by(Vulnerability.id)
            )
        )
        if not rows:
            return 0

        rows.sort(key=lambda row: _severity_rank(row.severity), reverse=True)
        targets = rows[:_MAX_DESCRIBED]
        if len(rows) > _MAX_DESCRIBED:
            # 说清楚剩下的去哪了。**不静默截断** —— 一份「只有前 40 条有描述」
            # 的报告会让人以为后面那些漏洞不重要。
            await self.emit(
                LogLevel.INFO,
                f"漏洞数超过文案预算，仅前 {_MAX_DESCRIBED} 条（按严重度排序）"
                "生成模型描述，其余使用模板文案",
            )

        # 并发闸：2 vCPU 上开大只会互相拖慢，且降级模板拼接本身是 CPU 活。
        # 用 `expressions` 的常量而不是自己写一个 4 —— 两处各写一个数字，
        # 改动时漏掉一处就会得到「报告阶段比设计文档说的更激进」这种问题。
        limit = asyncio.Semaphore(DEFAULT_CONCURRENCY)

        async def fill(row: Any) -> None:
            async with limit:
                result = await describe_finding(row)
            # `TextResult` 的构造器保证了 text 非空（模板也必须给可读文案），
            # 所以这里拿到的永远是一段能写进报告的话。
            row.description = result.text

        await asyncio.gather(*(fill(row) for row in targets))
        await self.deps.session.flush()
        return len(targets)

    # ------------------------------------------------------------------
    # 装配
    # ------------------------------------------------------------------

    async def _generate(self, ctx: AssessmentContext) -> Any:
        """装配 → 渲染 → 落盘。**不 commit**（见模块 docstring）。"""
        from app.report.service import ReportService

        return await ReportService(self.deps.session).generate(ctx.assessment_id, commit=False)

    async def _report_summary(self, ctx: AssessmentContext, draft: Any) -> None:
        summary = draft.summary
        by_severity = summary.by_severity or {}
        await self.emit(
            LogLevel.INFO,
            f"报告已生成：{summary.total} 条漏洞"
            f"（严重 {by_severity.get('critical', 0)}、"
            f"高危 {by_severity.get('high', 0)}），"
            f"综合评分 {summary.score}（{summary.grade_cn}）",
        )

        if draft.degraded:
            # 降级清单必须转述。它记的是「报告里哪几章是模板生成的」——
            # 不说的话，用户会把模板措辞当成模型分析的结果。
            await self.emit(
                LogLevel.WARN,
                "报告部分内容为模板生成（LLM 不可用或输出未通过校验）："
                + "、".join(draft.degraded),
            )


# ---------------------------------------------------------------------------
# 纯函数
# ---------------------------------------------------------------------------

#: 严重度排序权重。用一张显式的表而不是 `Severity` 枚举的定义顺序 ——
#: 枚举顺序是「声明顺序」，把它当排序依据会让「有人在枚举中间插一个成员」
#: 变成一次静默的行为变更。
_SEVERITY_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def _severity_rank(severity: Any) -> int:
    """未知严重度按 0 —— 排在最后。

    排序兜底的方向很重要：判错时把一条漏洞排到**后面**，
    代价是它的描述走模板；排到前面则会挤掉一条真正高危的模型描述。
    """
    return _SEVERITY_RANK.get(str(getattr(severity, "value", severity)), 0)


def _summary(draft: Any) -> dict[str, Any]:
    summary = draft.summary
    return {
        "total": summary.total,
        "score": summary.score,
        "grade": str(summary.grade),
        "chain_count": summary.chain_count,
        # 降级清单是这一阶段**唯一**需要引擎知道的产出：报告生成成功但
        # 部分章节是模板产的，这个事实得能出现在阶段行的 note 里。
        "degraded": list(draft.degraded),
    }


__all__ = ["ReportGenAgent"]
