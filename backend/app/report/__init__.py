"""B6 报告汇编模块（L3 领域引擎层）。

职责：**从数据库快照**生成一份可复现的安全评估报告，产出 Markdown / HTML / PDF。
依据：[B6 模块概要设计](../../../vibecoding_doc/模块概要设计/B6-报告汇编模块.md)、
[模块间契约 §4](../../../vibecoding_doc/模块间契约.md)。

## 内部结构

| 文件 | 职责 |
|---|---|
| `assembler.py` | 快照 → `ReportData`（**契约 4 的 `build_report` 在这里**） |
| `scoring.py` | 评分与整改排序的纯函数（L1 最容易被破坏的那一半） |
| `charts.py` | 内联 SVG（零外部资源，Markdown 里降级为表格） |
| `render.py` | Jinja2 渲染 HTML / Markdown |
| `exporter.py` | 落盘与 `reports` 行 |
| `pdf.py` | Playwright → PDF（可选，失败即降级） |
| `repository.py` | `reports` 表 + `assessments` 两列回写（**不 commit**） |
| `service.py` | `ReportService` 门面 |

## 「拿掉 LLM，结论一字不变」在本模块的落点

报告里**没有一处结论来自 LLM**。漏洞清单、严重度、CVSS、验证状态、污点路径、
评分、等级、攻击链结构、整改顺序 —— 全部来自 `scoring.py` 的纯函数与数据库里
已经落定的行。LLM 只出现在 `app/llm/` 的四个用点（描述、补丁、链叙事、整改文案），
且**每一个都有确定性模板的等价产物**。

因此：`DEEPSEEK_API_KEY` 为空时，报告照样出，`llm_model` 字段标 `template`，
三个格式都完整，只有措辞从「模型写的」换成「模板写的」。

## 分层铁律

本包属 L3，**不得 import `fastapi`**、不得 import `app.orchestrator/`。
可以 import L4（`app.llm`），反向不行。

**刻意不做 re-export**（与 `app/projects/__init__.py` 同一理由）：
`from app.report import ReportService` 会让包导入与数据库依赖绑在一起，
调用方请写 `from app.report.service import ReportService`。
"""
