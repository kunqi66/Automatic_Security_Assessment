"""LLM 表达层（L4 基础设施层）。

职责：把**已经由确定性代码判定好的事实**翻译成中文文案，一共**四个封闭使用点**。
依据：[模块间契约 §3](../../../vibecoding_doc/模块间契约.md)、
[PRD §7.6.3](../../../vibecoding_doc/PRD.md)。

| # | 用点 | 入口函数（`expressions.py`） | 降级 |
|---|---|---|---|
| ① | 漏洞描述 | `describe_finding` | 类型模板拼接 |
| ② | Diff 补丁 | `suggest_patch` | 无补丁（`diff=None`）+ 通用修复建议 |
| ③ | 攻击链叙事 | `narrate_chain` | 模板拼接 |
| ④ | 整改建议文案 | `suggest_remediation` | 类型模板拼接 |

**多一个都不许加**。新增用点必须先在 PRD §7.6.3 登记并经评审。

**分层铁律**：本包属 L4，**不得 import `fastapi`**、不得 import `app.orchestrator/`
（不存在）、不得 import 任何 L3 领域引擎（`app/analysis/` / `app/report/` / `app/verify/`）。
依赖方向是 L3 → L4，反过来就是环。

**L1 落点**：本包不接受「请判断这个漏洞有多严重」这类请求。调用方必须把 `severity` /
`status` / `cvss_score` / `guard_blocked` 等**已判定的值**作为输入喂进来（见
`prompts.py` 每个 prompt 的注释），本包只负责措辞。`expressions.py` 的返回结构里
只有文本与来源标注，没有任何影响控制流的字段。

**L4 落点**：无 key / 超时 / 限流 / 响应畸形 / 实体白名单不过 —— 一律降级，
**不抛异常给调用方**，`llm_model` 标 `template`。

**刻意不做 re-export**（与 `app/projects/__init__.py` 同一理由）：
`from app.llm import describe_finding` 会把包导入与 httpx 客户端初始化绑在一起，
调用方请写 `from app.llm.expressions import describe_finding`。
"""
