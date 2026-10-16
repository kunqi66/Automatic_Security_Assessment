"""B2 沙箱隔离模块（L3 领域引擎层）。

职责：把「一段命令要在隔离环境里跑」变成「一次可观测、可配额约束、可强制终止的
受控执行」。**运行的「内容」它一概不问** —— 入参只有「镜像 + 挂载 + 配额 + 命令」。

对外唯一门面是 `service.SandboxService`，对 B5 暴露的契约类型定义在 `ports.py`。

**边界**（B2 模块设计 §1.2）：
- 不 import `fastapi`、不 import `app/orchestrator/`（总纲 §3.4 禁止反向依赖）；
- **不判断载荷合法性**（黑名单 / 反弹 shell / 副作用命令）—— 那是 B5 的 `verify/guard.py`；
- 不读写 Redis、不写 `vulnerabilities` / `poc_attempts` / `taint_paths`（证据层属 B4/B5），
  也不做编排决策（阶段推进 / 取消标志位属 B3）。

**刻意不做 re-export**：`from app.sandbox import SandboxService` 看着方便，但它让包导入
与子模块导入顺序绑定（同 B1 `projects/__init__.py`）。调用方请写
`from app.sandbox.service import SandboxService`，协议类型写 `from app.sandbox.ports import ...`。
"""
