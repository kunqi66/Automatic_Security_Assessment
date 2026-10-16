"""四个封闭使用点的门面 —— 本包**唯一**对外的调用面（契约 3）。

```
① describe_finding      Finding          → 一段中文描述
② suggest_patch         Finding + 源码    → unified diff / None + 通用修复建议
③ narrate_chain         链的节点与边      → 一段中文叙述
④ suggest_remediation   Finding          → 一段整改建议
```

## 每个函数的骨架都一样，而且是刻意的

```text
try:  调模型
except 任何异常:  → 模板（reason 记录原因）      ← L4
校验输出（实体白名单）→ 不过:  → 模板（reason=guard_rejected）  ← L3
```

**没有第二条路径能让异常逃出去。** 这是「可降级不阻断」在代码上的唯一保证方式：
不靠「调用方记得 try」，而是在函数内部兜死。上层（B3 编排、B6 报告）因此可以像
调用一个纯函数那样调用它 —— 它永远返回一个可渲染的对象。

## 四个用点都不会碰控制流

返回类型 `TextResult` / `PatchDraft` 里只有文本与来源标注。**调用方拿不到
任何可判断的字段** —— 想让 LLM 的产出影响阶段跳转或排序，得先改这个模块的类型定义，
而那种改动在 review 里一眼就能看见。这是 L1 在类型层面的落点。

## 并发与预算

`describe_findings` / `suggest_remediations` 是**同用点的批量版本**，
不是新增用点（不新增 prompt、不新增输出种类）。它们存在的唯一理由是：
一次评估可能有几十条漏洞，逐条串行调 LLM 会直接撞穿「报告生成 ≤30s」
（PRD §1.2）。批量版本有三道闸：

1. 并发上限 `DEFAULT_CONCURRENCY`（2 vCPU 机器上开大只会互相拖慢）；
2. 总预算 `DEFAULT_BUDGET_SECONDS` —— 超出预算的**剩余项整体走模板**；
3. 单次调用自身 15s 超时 × 最多 2 次尝试（`client.py`）。

预算耗尽只影响措辞，不影响任何结论（结论根本不来自这里）。
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger
from app.llm import fallback, prompts
from app.llm.client import get_default_client
from app.llm.guard import EntityWhitelist, check_entities
from app.llm.types import (
    TEMPLATE_MODEL,
    ChainView,
    FindingView,
    PatchDraft,
    TextCompleter,
    TextResult,
)

logger = get_logger(__name__)

#: 报告层给整批 LLM 文案的总预算（秒）。取 20s 是因为「报告生成 ≤30s」是硬指标，
#: 而渲染 + 落盘 + 写库还要占掉一部分；把大头留给确定性步骤，表达层只拿剩下的。
DEFAULT_BUDGET_SECONDS = 20.0

#: 并发上限。阿里云那台是 2 vCPU，LLM 调用本身是 IO 等待，但降级模板拼接是 CPU 活；
#: 4 是个既能压住总墙钟、又不会把事件循环排满的数。
DEFAULT_CONCURRENCY = 4

#: 统一的降级日志级别：**INFO 而不是 WARNING**。
#: 「系统自动降级为模板」是设计内的行为（PRD §7.6.2 L4），把它打成 WARNING
#: 会让日志里全是「告警」，真正的告警反而被淹没。原因码写在正文里，需要时能筛。
_DEGRADE_LOG = "LLM 用点%s降级为模板：%s"


def _view(obj: Any) -> FindingView:
    """幂等归一化：已经是 `FindingView` 就原样返回。"""
    return obj if isinstance(obj, FindingView) else FindingView.of(obj)


def _chain_view(obj: Any) -> ChainView:
    return obj if isinstance(obj, ChainView) else ChainView.of(obj)


def _client(explicit: TextCompleter | None) -> TextCompleter:
    """注入优先，否则取进程级默认客户端。

    默认客户端在未配 key 时**不会发请求**，第一次 `complete()` 就抛
    `LlmNotConfiguredError`，由下面的 except 立刻转模板 —— 不重试、不告警、
    不打网络。未配 key 是合法的开发态配置。
    """
    return explicit if explicit is not None else get_default_client()


def _model_of(client: TextCompleter) -> str:
    return getattr(client, "model_name", None) or settings.llm_model


# ===========================================================================
# ① 漏洞描述
# ===========================================================================


async def describe_finding(
    finding: FindingView | Any, *, client: TextCompleter | None = None
) -> TextResult:
    """用点 ①：把已判定的漏洞事实写成一段中文描述。

    `severity` / `status` / `guard_blocked` / 污点每一跳都作为**已知输入**进 prompt，
    模型只负责措辞。它永远没有机会说「我认为这是低危」—— 因为严重度不进它的输出，
    输出里只有文本，而文本会被 `guard.py` 按实体白名单核一遍。
    """
    view = _view(finding)
    completer = _client(client)

    # 捕获 `Exception` 而不是 `LlmError` 是有意的：注入的假客户端、别人换的实现、
    # 甚至 httpx 未来多抛的一种异常，都不该让报告生成中断。L4 的「不阻断」
    # 在代码上就体现为这一行足够宽。
    # （`CancelledError` 继承自 `BaseException`，不会被吞掉 —— 取消仍然生效。）
    try:
        raw = await completer.complete(prompts.build_description_messages(view))
    except Exception as exc:  # noqa: BLE001 —— L4：任何失败都不许阻断流水线
        return _degrade(1, fallback.describe_finding(view), exc)

    verdict = check_entities(raw, _finding_whitelist(view))
    if not verdict.ok:
        return _degrade(
            1,
            fallback.describe_finding(view),
            None,
            reason="guard_rejected",
            detail=f"{verdict.kind}={verdict.offending}",
        )

    return TextResult(text=raw.strip(), llm_model=_model_of(completer), degraded=False)


# ===========================================================================
# ② Diff 补丁
# ===========================================================================


async def suggest_patch(
    finding: FindingView | Any, *, client: TextCompleter | None = None
) -> PatchDraft:
    """用点 ②：生成补丁**草案**。

    ⚠️ 本函数**不校验补丁**。四道校验（合法 unified diff / ±20 行窗口 /
    `git apply --check` / 重跑污点引擎确认路径消失）全在 `app/verify/patch_guard.py`，
    归 B5。这里只做一次廉价的形状预筛，避免把一段散文当成 diff 递给下游 ——
    预筛不过等于降级，等于 `diff=None`。

    降级产物是「无补丁 + 通用修复建议」（契约 3 的降级列 + PRD §7.6.3）。
    """
    view = _view(finding)
    completer = _client(client)
    advice = fallback.patch_advice(view)

    try:
        raw = await completer.complete(prompts.build_patch_messages(view))
    except Exception as exc:  # noqa: BLE001
        return _degrade_patch(view, advice, exc)

    text = _strip_code_fence(raw)
    if not _looks_like_diff(text):
        return _degrade_patch(
            view,
            advice,
            None,
            reason="not_a_diff",
            detail="模型未返回可识别的 unified diff",
        )
    # 补丁只允许改**这一个文件**：模型「顺手」改了另一个文件，即便那个改动是对的，
    # 也不在接受范围内（第 2 道校验的另一半）。这里先挡一次，省掉下游一次 git apply。
    touched = _diff_paths(text)
    if touched and not touched <= {view.file_path}:
        return _degrade_patch(
            view,
            advice,
            None,
            reason="guard_rejected",
            detail=f"补丁涉及未授权文件：{sorted(touched - {view.file_path})}",
        )

    return PatchDraft(
        diff=text,
        llm_model=_model_of(completer),
        degraded=False,
        advice=advice,
        target_file=view.file_path,
    )


# ===========================================================================
# ③ 攻击链叙事
# ===========================================================================


async def narrate_chain(
    chain: ChainView | Any, *, client: TextCompleter | None = None
) -> TextResult:
    """用点 ③：把 B5 已推演好的链写成中文叙事。

    校验基准是 PRD §7.6.3 用点③的原话：「叙事中提到的漏洞编码集合
    **⊆ 该链的实际节点集合**」。节点与边都由 B5 的规则引擎产出，模型只讲述。
    """
    view = _chain_view(chain)
    completer = _client(client)

    try:
        raw = await completer.complete(prompts.build_chain_messages(view))
    except Exception as exc:  # noqa: BLE001
        return _degrade(3, fallback.narrate_chain(view), exc)

    whitelist = EntityWhitelist.for_chain(
        paths=frozenset(),
        codes=frozenset(view.vuln_codes),
    )
    verdict = check_entities(raw, whitelist)
    if not verdict.ok:
        return _degrade(
            3,
            fallback.narrate_chain(view),
            None,
            reason="guard_rejected",
            detail=f"{verdict.kind}={verdict.offending}",
        )

    return TextResult(text=raw.strip(), llm_model=_model_of(completer), degraded=False)


# ===========================================================================
# ④ 整改建议文案
# ===========================================================================


async def suggest_remediation(
    finding: FindingView | Any,
    *,
    rank: int = 1,
    total: int = 1,
    client: TextCompleter | None = None,
) -> TextResult:
    """用点 ④：为**已经排好序**的整改项写文案。

    `rank` / `total` 是**输入**：顺序由 `app/report/scoring.py` 的确定性公式
    （等级 × 可达性 × 修复成本）产出。模型拿到的是「这是第 1/7 项」这个事实，
    而不是「请判断谁最该先修」这个任务 —— 后者会让同一份数据两次生成得到两份
    不同的排序，可复现性当场失效（PRD §7.6.3 括注：顺序不校验，因为不由 LLM 决定）。
    """
    view = _view(finding)
    completer = _client(client)

    try:
        raw = await completer.complete(
            prompts.build_remediation_messages(view, rank=rank, total=total)
        )
    except Exception as exc:  # noqa: BLE001
        return _degrade(4, fallback.suggest_remediation(view, rank=rank, total=total), exc)

    verdict = check_entities(raw, _finding_whitelist(view))
    if not verdict.ok:
        return _degrade(
            4,
            fallback.suggest_remediation(view, rank=rank, total=total),
            None,
            reason="guard_rejected",
            detail=f"{verdict.kind}={verdict.offending}",
        )

    return TextResult(text=raw.strip(), llm_model=_model_of(completer), degraded=False)


# ===========================================================================
# 批量版本（同用点，不是新用点）
# ===========================================================================


async def suggest_remediations(
    findings: Sequence[FindingView | Any],
    *,
    client: TextCompleter | None = None,
    budget_seconds: float = DEFAULT_BUDGET_SECONDS,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> list[TextResult]:
    """用点 ④ 的批量版本，**返回顺序与入参一致**。

    用 `list` 而不是按 `code` 索引的 dict：`code` 可能为空（分析阶段还没分配编号），
    用它做键会静默合并两条漏洞。顺序即语义，调用方按位置取值。
    """
    if not findings:
        return []

    views = [_view(f) for f in findings]
    total = len(views)
    completer = _client(client)

    # 未配 key 时**在批量层就短路**：省掉 N 次必然失败的调用尝试与 N 行降级日志。
    # （即便不短路，结果也完全相同 —— 只是日志更吵、模板拼接更晚。）
    if not getattr(completer, "is_configured", True):
        logger.info("未配置 DEEPSEEK_API_KEY，%d 条整改文案全部使用确定性模板", total)
        return [
            TextResult(
                text=fallback.suggest_remediation(v, rank=i + 1, total=total),
                llm_model=TEMPLATE_MODEL,
                degraded=True,
                reason="no_api_key",
            )
            for i, v in enumerate(views)
        ]

    deadline = time.monotonic() + max(0.0, budget_seconds)
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def one(index: int, view: FindingView) -> TextResult:
        if time.monotonic() >= deadline:
            return TextResult(
                text=fallback.suggest_remediation(view, rank=index + 1, total=total),
                llm_model=TEMPLATE_MODEL,
                degraded=True,
                reason="budget_exceeded",
            )
        async with semaphore:
            return await suggest_remediation(view, rank=index + 1, total=total, client=completer)

    results = await asyncio.gather(*(one(i, v) for i, v in enumerate(views)))
    degraded = sum(1 for r in results if r.degraded)
    if degraded:
        logger.info("整改文案：%d/%d 条由确定性模板生成", degraded, total)
    return list(results)


# ===========================================================================
# 内部工具
# ===========================================================================


def _finding_whitelist(view: FindingView) -> EntityWhitelist:
    return EntityWhitelist.for_finding(
        file_path=view.file_path,
        line_start=view.line_start,
        line_end=view.line_end,
        taint_lines=frozenset(s.line for s in view.taint_path),
        code=view.code,
        cwe_id=view.cwe_id,
    )


def _degrade(
    use_point: int,
    text: str,
    exc: Exception | None,
    *,
    reason: str | None = None,
    detail: str = "",
) -> TextResult:
    if exc is None:
        logger.info(_DEGRADE_LOG, use_point, f"{reason} {detail}".strip())
        return TextResult(text=text, llm_model=TEMPLATE_MODEL, degraded=True, reason=reason)

    reason_code = getattr(exc, "reason_code", exc.__class__.__name__)
    logger.info(_DEGRADE_LOG, use_point, reason_code)
    return TextResult(text=text, llm_model=TEMPLATE_MODEL, degraded=True, reason=reason_code)


def _degrade_patch(
    view: FindingView,
    advice: str,
    exc: Exception | None,
    *,
    reason: str | None = None,
    detail: str = "",
) -> PatchDraft:
    if exc is None:
        logger.info(_DEGRADE_LOG, 2, f"{reason} {detail}".strip())
    else:
        reason = getattr(exc, "reason_code", exc.__class__.__name__)
        logger.info(_DEGRADE_LOG, 2, reason)
    return PatchDraft(
        diff=None,
        llm_model=TEMPLATE_MODEL,
        degraded=True,
        advice=advice,
        reason=reason,
        target_file=view.file_path,
    )


def _strip_code_fence(text: str) -> str:
    """剥掉模型爱加的 ```diff 围栏。

    这不是「猜」，unified diff 本身就是一段纯文本，围栏是纯噪声：
    留着它会让第 1 道校验（合法 unified diff）在**格式**上失败，
    而失败原因是围栏而不是补丁内容 —— 那样的降级毫无信息量。
    """
    body = text.strip()
    if not body.startswith("```"):
        return body
    lines = body.splitlines()
    lines = lines[1:]  # 去掉开围栏（可能带语言标注，无需区分）
    while lines and lines[-1].strip().startswith("```"):
        lines.pop()
    return "\n".join(lines).strip()


def _looks_like_diff(text: str) -> bool:
    """廉价形状预筛：有 `---` / `+++` 头与至少一个 `@@` 块。

    **明确不是校验**（第 1 道校验的完整实现归 B5 的 `patch_guard.py`）。
    这里只回答「这东西像不像 diff」，答案是否的时候我们连递都不递。
    """
    if "NO_PATCH" in text:
        return False
    has_header = any(ln.startswith("---") for ln in text.splitlines()) and any(
        ln.startswith("+++") for ln in text.splitlines()
    )
    has_hunk = any(ln.startswith("@@") for ln in text.splitlines())
    return has_header and has_hunk


def _diff_paths(text: str) -> set[str]:
    """从 `---` / `+++` 头里解出被改动的文件（剥掉 `a/` `b/` 前缀）。

    `git diff` 的习惯写法是 `--- a/x.py` / `+++ b/x.py`，而 git apply 接受
    带不带前缀两种写法，所以两种都要能认出来。
    """
    paths: set[str] = set()
    for line in text.splitlines():
        if line.startswith("--- ") or line.startswith("+++ "):
            raw = line[4:].split("\t")[0].strip()
            if raw in ("/dev/null", ""):
                continue
            for prefix in ("a/", "b/"):
                if raw.startswith(prefix):
                    raw = raw[len(prefix) :]
                    break
            paths.add(raw)
    return paths


__all__ = [
    "DEFAULT_BUDGET_SECONDS",
    "DEFAULT_CONCURRENCY",
    "describe_finding",
    "narrate_chain",
    "suggest_patch",
    "suggest_remediation",
    "suggest_remediations",
]
