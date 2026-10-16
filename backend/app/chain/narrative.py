"""攻击链叙事的 LLM 用点与 L3 校验（B5 设计 §4.8，契约 3 用点 ③）。

## 叙事是本模块唯一不由代码直接产出的文本 —— 因此它必须被"关在笼子里"

三条约束，一条都不能少：

* **L2（输入侧）**：prompt 只喂**规则引擎已经确定的事实**（节点集合、命中的规则编号、
  权限跃迁），不把源码交给模型让它自己分析。这一步由 `app/llm/prompts.py` 负责，
  B5 不越界。
* **L3（输出侧）**：叙事里出现的**漏洞编码集合必须 ⊆ 该链的节点编码集合**。
  破了就整段拒收，回落模板。校验不是在 B5 重写一遍，而是调 B6 的
  `app.llm.guard`（L3 的实现只有一份，两处实现迟早会漂移出两个标准）。
* **L4（降级）**：无 key、超时、校验不过 —— 三类都**不中断流水线**，
  统一回落 `builder._template_narrative` 的确定性文本，并把
  `narrative_source` 标成 `template`，让报告能写"本段由模板生成"。

## 为什么"拒收"而不是"把提到的那句删掉"

删掉会让文案读起来仍然通顺 —— 于是幻觉的痕迹消失了，而读者不知道少了什么。
拒收的代价已知且可控（措辞变差），改写的代价是"我们发明了一段既不是模型说的、
也不是模板说的文本"，它无法解释、无法复现。**降级是允许的，发明是不允许的。**
"""

from __future__ import annotations

from typing import Any

from app.chain.builder import ChainBuilder
from app.chain.types import AttackChain, ChainDraft
from app.core.logging import get_logger

logger = get_logger(__name__)


async def narrate_chain(chain: AttackChain, *, client: Any = None) -> AttackChain:
    """给一条链补上叙事。**原地返回同一条链的副本**，`narrative_source` 标明来源。

    永远不抛异常：叙事是表达层，它出问题不该让一次评估失败（L4）。
    """
    template = chain.narrative or ""
    try:
        from app.llm.expressions import narrate_chain as llm_narrate
    except ImportError as exc:  # B6 未落地 / 模块改名
        logger.info("LLM 表达层不可用（%s），攻击链叙事使用模板", exc)
        return chain.model_copy(update={"narrative_source": "template", "narrative": template})

    try:
        result = (
            await llm_narrate(chain, client=client)
            if client is not None
            else await llm_narrate(chain)
        )
    except Exception as exc:  # noqa: BLE001 - 表达层任何异常都走模板
        logger.warning("攻击链叙事生成失败（%s），回落模板", exc)
        return chain.model_copy(update={"narrative_source": "template", "narrative": template})

    if getattr(result, "degraded", True):
        # 契约 3 的判据：拿掉 LLM，**结论**不变、只有措辞变。
        # 这里的"结论"就是节点/边/环级验证状态 —— 它们在 `builder` 里就已经定稿了。
        logger.info("攻击链叙事降级为模板（reason=%s）", getattr(result, "reason", "unknown"))
        return chain.model_copy(update={"narrative_source": "template", "narrative": template})

    text = str(getattr(result, "text", "") or "").strip()
    if not text:
        return chain.model_copy(update={"narrative_source": "template", "narrative": template})

    # 二次自检：即便 B6 说它过了，也再核对一次"叙事里出现了本链没有的编号吗"。
    # 一行的代价，换的是"L3 在 B5 这一侧也被执行过"这件事 —— 而 L3 的要求
    # 恰恰是"**输出必校验**"，不是"相信上游校验过了"。
    offending = _offending_codes(text, chain.vuln_codes)
    if offending:
        logger.warning("攻击链叙事里出现本链之外的漏洞编码 %s，拒收并回落模板", offending)
        return chain.model_copy(update={"narrative_source": "template", "narrative": template})

    return chain.model_copy(update={"narrative_source": "llm", "narrative": text})


async def narrate_draft(draft: ChainDraft, *, client: Any = None) -> ChainDraft:
    """给整份推演结果补叙事（逐链处理，**一条链失败不影响其它链**）。"""
    if not draft.chains:
        return draft
    narrated = [await narrate_chain(chain, client=client) for chain in draft.chains]
    return draft.model_copy(update={"chains": narrated})


async def build_chain_narrated(
    findings: Any, *, client: Any = None, **builder_kwargs: Any
) -> ChainDraft:
    """一步到位：推演 **+** 叙事。

    与契约 4 的 `build_chain(findings)` 分开，是为了让"图结构"与"叙事"的边界
    落在函数边界上：前者同步、无 IO、无 LLM；后者才可能碰到模型。
    B3 想只拿结论就调前者，想要叙事就调这个。
    """
    draft = ChainBuilder(**builder_kwargs).build(findings)
    return await narrate_draft(draft, client=client)


def _offending_codes(text: str, allowed: frozenset[str]) -> list[str]:
    """叙事里出现的、**不在本链节点集合内**的漏洞编码。

    抽编码这件事自己有实现，不依赖上游 —— 因为这里要防的正是"上游校验被绕过"
    （例如别人换了校验实现、或校验的允许集合被放宽）。
    """
    import re

    found = {
        m.group(0).upper() for m in re.finditer(r"\bVULN-\d{4}-\d{4,6}\b", text, re.IGNORECASE)
    }
    return sorted(found - {c.upper() for c in allowed})
