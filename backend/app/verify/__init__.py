"""B5 前半区：无害化验证引擎。

**本包不 re-export 任何东西**（与 `app/projects/` 的约定一致）：`from app.verify
import verify_finding` 会让调用方看不见它究竟来自哪个文件，而"验证结论是哪段
代码判的"在这类系统里必须一眼可查。请显式写 `from app.verify.runner import
verify_finding`。

包内分工：

| 文件 | 职责 |
|---|---|
| `types.py` | 数据契约：探针、闸门结论、验证结果、跨模块 Protocol |
| `probe.py` | 从 Finding 推出探针（**确定性模板，无 LLM**） |
| `guard.py` | 无害化前三道闸门（行为 / 载荷 / 网络） |
| `fingerprints.py` | 第 ④ 道闸门：判定响应、给出「是否足以证伪」 |
| `runner.py` | 执行编排与状态裁决（`verify_finding` / `verify_findings`） |
| `patch_guard.py` | 修复补丁的四道校验 |

分层铁律（L1）：本包**不 import** `fastapi`、`app.orchestrator`、`app.db`，
也不 import `app.llm`。沙箱只通过契约 1 的 `app.sandbox.ports` 访问。
"""
