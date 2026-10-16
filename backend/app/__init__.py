"""自动化安全评估系统 —— 后端应用包。

分层（总纲 §3.4，**禁止反向依赖**）：

| 层 | 内容 | 允许依赖 |
|---|---|---|
| L1 接口层 | `api/` | L2、L3、L4 |
| L2 编排层 | `orchestrator/`、`agents/` | L3、L4 |
| L3 领域引擎层 | `analysis/`、`verify/`、`chain/`、`sandbox/`、`report/`、`projects/` | L4 |
| L4 基础设施层 | `core/`、`db/`、`llm/`、`models/`、`schemas/` | 无 |

两条最容易违反的边界：
- `analysis/`（污点引擎）是**纯函数库**，连 `db/` 都不 import ——
  这让它可以被单元测试直接驱动，是 `tests/test_taint.py` 能写出来的前提。
- `analysis/`、`verify/` 等引擎**不得 import FastAPI 的任何东西**。
"""

__version__ = "0.1.0"
