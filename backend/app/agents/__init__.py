"""五个阶段 Agent（L2 编排层）。

每个 Agent 的领域算法都委托给对应的 L3 引擎（B4/B5/B6），自己只负责
「取输入 → 调引擎 → 落库 → 写回上下文」。**Agent 里不该有分析逻辑** ——
一旦有，那些逻辑就既不能被单独测试，也不能被别的 Agent 复用。

| Agent | 阶段 | 委托给 |
|---|---|---|
| `ReconAgent` | `recon` | 无（技术栈识别在 B3 内，见 B1 设计 §1.2 的划界） |
| `CodeAuditAgent` | `code_audit` | B4 + LLM（描述/补丁，含校验与降级） |
| `PocVerifyAgent` | `poc_verify` | B5 + B2 |
| `ExploitChainAgent` | `exploit_chain` | B5（攻击链部分） |
| `ReportGenAgent` | `report_gen` | B6 + LLM（叙事/建议） |

`__init__` 不 import 五个 Agent：`registry` 已经用惰性 import 处理了这件事，
在这里再 import 一次会把惰性抵消掉（`registry` 被 `engine` import，
而 `engine` 又在启动路径上）。
"""

from app.agents.base import AgentDeps, BaseAgent, FaultTolerance

__all__ = ["AgentDeps", "BaseAgent", "FaultTolerance"]
