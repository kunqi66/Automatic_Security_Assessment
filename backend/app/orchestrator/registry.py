"""`Stage → BaseAgent` 注册表（B3 设计 §2、T9）。

**静态枚举注册，不做插件发现**（T9）：作品集规模下，入口点发现（entry points）
带来的是「装了一个包就多出一个阶段」这种难以推理的行为，而代价是类型不可检查。
静态注册的代价是新增 Agent 要改这里一行 —— 但**不需要改引擎逻辑**，
这才是「可插拔」真正要保证的事。

---

**默认注册是惰性的**（首次查表时才 import 五个 Agent）。理由有两条：

1. `registry` 被 `engine` import，而五个 Agent 又 import 引擎要用的上下文 ——
   在模块级 import 会绕成一个环（Python 能解，但解出来的顺序很脆）。
2. 测试要能登记替身 Agent 而不触发真 Agent 的 import（它们依赖沙箱、LLM 等外部物）。
"""

from __future__ import annotations

from collections.abc import Iterable

from app.agents.base import AgentDeps, BaseAgent
from app.models.enums import StageName

_REGISTRY: dict[StageName, type[BaseAgent]] = {}
_defaults_loaded = False


def register(stage: StageName, agent_cls: type[BaseAgent], *, replace: bool = False) -> None:
    """绑定阶段与 Agent 类。

    `replace=False` 时重复登记会抛错。**这是刻意的**：重复登记几乎总是
    「两个模块都以为这个阶段归自己」，静默后者覆盖前者的症状是
    「某个 Agent 从来没被执行过」—— 而它的代码看起来完全正常。
    """
    if stage in _REGISTRY and not replace:
        existing = _REGISTRY[stage].__name__
        raise ValueError(
            f"阶段 {stage} 已绑定 {existing}，"
            f"要覆盖请显式传 replace=True（当前试图绑定 {agent_cls.__name__}）"
        )
    if agent_cls.stage != stage:
        # 绑错阶段不会立刻出错，而是在某个阶段悄悄跑了另一个 Agent 的逻辑 ——
        # 症状是「recon 阶段产出了 findings」。这里拦掉。
        raise ValueError(f"{agent_cls.__name__} 声明自己负责 {agent_cls.stage}，却被登记到 {stage}")
    _REGISTRY[stage] = agent_cls


def agent_class(stage: StageName) -> type[BaseAgent]:
    _ensure_defaults()
    try:
        return _REGISTRY[stage]
    except KeyError as exc:
        raise LookupError(
            f"阶段 {stage} 没有注册 Agent —— 评估跑到这一步会无从执行。"
            f"已注册：{sorted(s.value for s in _REGISTRY)}"
        ) from exc


def build(stage: StageName, deps: AgentDeps) -> BaseAgent:
    """实例化某个阶段的 Agent。**每个阶段一个新实例** —— Agent 不跨阶段复用，
    免得上一阶段的状态漏进下一阶段。"""
    return agent_class(stage)(deps)


def registered_stages() -> tuple[StageName, ...]:
    _ensure_defaults()
    return tuple(_REGISTRY)


def assert_complete(order: Iterable[StageName]) -> None:
    """启动时校验：`STAGE_ORDER` 里每个阶段都有 Agent。

    **必须在启动时查，不能等跑到才发现**。并发度恒为 1（T3），
    一个评估占住 worker 直到跑完 —— 如果第 4 个阶段没有 Agent，
    这件事会在评估跑了 20 分钟之后才暴露，而那时前三个阶段的开销已经付了。
    """
    _ensure_defaults()
    missing = [s.value for s in order if s not in _REGISTRY]
    if missing:
        raise LookupError(
            f"以下阶段没有注册 Agent：{missing}。"
            f"评估一旦进入这些阶段将无法继续 —— 请检查 agents/ 与 registry.py。"
        )


def reset_for_tests() -> None:
    """清空注册表。测试专用。

    有了它，测试可以用替身 Agent 跑完整的引擎流程，而不必真的去调沙箱和 LLM ——
    这是能把「阶段边界提交」「容错分档」「协作式取消」这些引擎行为
    单独测出来的前提。
    """
    global _defaults_loaded
    _REGISTRY.clear()
    _defaults_loaded = False


def _ensure_defaults() -> None:
    global _defaults_loaded
    if _defaults_loaded:
        return
    _defaults_loaded = True

    # 惰性 import：见模块顶部说明。顺序即 STAGE_ORDER，但注册表本身无序，
    # 真正的顺序由 engine.STAGE_ORDER 决定。
    from app.agents.code_audit import CodeAuditAgent
    from app.agents.exploit_chain import ExploitChainAgent
    from app.agents.poc_verify import PocVerifyAgent
    from app.agents.recon import ReconAgent
    from app.agents.report_gen import ReportGenAgent

    for cls in (
        ReconAgent,
        CodeAuditAgent,
        PocVerifyAgent,
        ExploitChainAgent,
        ReportGenAgent,
    ):
        register(cls.stage, cls, replace=True)
