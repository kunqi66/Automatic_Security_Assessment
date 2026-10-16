"""B4 污点追踪引擎。

**一句话职责**：吃「源码清单 + 读取回调」，吐出**确定性的**漏洞 Finding 列表。
本包不写数据库、不调 LLM、不碰 HTTP —— 它是纯计算层（总纲 L3），
因此「拿掉 LLM 与数据库，这里的结论一字不变」是可验证的，而不是口号。

```
                 ┌─────────────┐
  源码文本  ───▶  │ parser      │ tree-sitter 解析（容错）
                 └──────┬──────┘
                        ▼
                 ┌─────────────┐    ┌──────────────┐
                 │ symbols     │───▶│ summary      │ 一层跨函数摘要
                 └──────┬──────┘    └──────┬───────┘
                        ▼                  │
  规则库：sources / sinks / sanitizers     │
                        ▼                  ▼
                 ┌─────────────────────────────┐
                 │ taint  传播（函数内 + 调用点）│
                 └──────────────┬──────────────┘
                                ▼
                 ┌─────────────┐   ┌──────────┐
                 │ patterns    │   │ cvss     │
                 └──────┬──────┘   └────┬─────┘
                        ▼               ▼
                 ┌─────────────────────────────┐
                 │ finding  组装（唯一出口）    │───▶ AnalysisResult
                 └─────────────────────────────┘
```

**对外入口只有四个**（其余都是内部词汇，B3 不该 import）：
`analyze(manifest, read_source)`（契约 4，B3 用）、
`analyze_project(root)` / `analyze_file(path)`（靶场回归与单测用）、
`analyze_sources({路径: 源码})`（单测直接注入样例代码用）。

**已知精度边界**（汇总，逐条的详细说明写在各自实现处）：

| 边界 | 表现 | 方向 |
| --- | --- | --- |
| 跨函数只展开一层 | 第二层只标 `unexpanded=True` | 漏 |
| 不建模闭包/类属性/别名 | `f = handler; f(uid)` 追不到 | 漏 |
| 未知调用按污点穿过 | 自建净化器 `quote(x)` 不被识别 | 报多 |
| 返回值的形参来源不区分 | `f(脏, 脏)` 任一脏即结果脏 | 报多 |
| 不展开递归 | 递归函数只标未展开 | 漏 |
| 比较/算术结果不传播 | `if uid == "1"` 之后的布尔值干净 | 漏 |
| IDOR 靠命名判鉴权 | 路由**级**（`APIRouter(dependencies=[...])`）与自定义中间件认不出 | 报多 |
| 硬编码凭据只扫模块级 | 函数体内的硬编码凭据不报 | 漏 |
| 二阶注入依赖 `cursor.fetchone` 这个字面名 | 连接变量叫别的名字（`cur`）时追不到 | 漏 |
| `escape` 按后缀匹配 | `re.escape()` 会被当成 HTML 转义（XSS 漏报） | 漏 |

方向那一列是刻意标出来的：**「报多」与「漏」在安全工具里代价不对称**，
规则每次取舍都要说清偏向了哪一边，否则「为什么这条没报/报了」无从复核。
"""

from __future__ import annotations

from app.analysis.taint import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_SECONDS,
    analyze,
    analyze_file,
    analyze_project,
    analyze_sources,
)
from app.analysis.types import AnalysisResult, Finding, SkipRecord, TaintStep, VulnType

__all__ = [
    "DEFAULT_MAX_FILES",
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_SECONDS",
    "AnalysisResult",
    "Finding",
    "SkipRecord",
    "TaintStep",
    "VulnType",
    "analyze",
    "analyze_file",
    "analyze_project",
    "analyze_sources",
]
