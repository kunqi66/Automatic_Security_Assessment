"""B4 对外值对象 —— **契约 2 的权威落点**（`vibecoding_doc/模块间契约.md`）。

本模块只放**不可变数据**，不含任何算法。三条刻意的约束：

1. **字段名照抄 `app/models/vulnerability.py` 的列名语义**（PRD §6 命名 SSOT）。
   `vuln_type` / `severity` / `file_path` / `line_start` / `line_end` / `cvss_score` /
   `cvss_vector` / `confidence` / `guard_blocked` 都能一一对到 ORM 列，B3 落库是
   纯搬运，不需要「DTO 叫 A、列叫 B」的翻译层 —— 字段错位最容易藏身的就是那一层。

2. **全部 `frozen=True`**。B4 是纯函数库：一个 `Finding` 一旦产出就不该再被谁改写。
   冻结不是为了好看，是为了让「B4 的结论由确定性规则算出」这句话在类型层面
   就不可违反 —— 拿到 `Finding` 的下游（含 LLM 文案环节）改不动它。

3. **不产出任何漏洞状态字段**（`unverified` / `verified` / `potential` / `rejected`）。
   状态是生命周期概念：`unverified` 只由静态阶段产出，其余三态只由动态阶段产出。
   把状态塞进纯函数库，等于让「静态分析的结论」与「验证阶段的事实」共用一种表达，
   而这正是设计文档 §7.2 取舍 9 与 PRD §6 明确否决的做法。
   「部分净化」这个信号改由 `confidence ×0.6` + `guard_blocked` 承载。

**与契约 2 的差异（唯一的差异，且「只增不改」）**：契约 2 列了 15 个 `Finding`
字段、5 个 `AnalysisResult` 字段、7 个 `TaintStep` 字段，本文件**逐字照抄、顺序不变**；
另有 6 个**带默认值**的附加字段：

- `Finding.title` / `.detection_method` / `.unexpanded` / `.code_snippet`
- `AnalysisResult.files_skipped` / `.unexpanded_calls`

前四个是 `vulnerabilities` / `report_findings` 的 `NOT NULL` 列所必需（B3 若自己去算，
就得重新读源码、重判 intra/inter —— 那是把 B4 的判定逻辑抄第二遍）；
后两个对应设计文档 §5.1 的「跳过原因拼进 log_excerpt」与 §3.3 的 `TaintReport`
（逐文件跳过清单、「未展开」调用点计数），同样只有 B4 算得出来。

六个字段全部有默认值、全部排在契约字段之后，所以**按位置构造的调用方一行都不用改**，
也不构成破坏性变更。判据是「B3 能否只搬运不重算」，不是「越多越好」。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from app.models.enums import DetectionMethod, Severity, TaintStepType


class VulnType(StrEnum):
    """B4 规则库能产出的漏洞类型。

    **为什么不复用 `vulnerabilities.vuln_type` 的字符串裸值**：那一列是
    `String(64)`（取值随规则库演进，刻意不用数据库 ENUM），代码侧如果没有一个
    封闭集合，「规则表里写错一个类型名」这种错只会在落库后读回时才炸。
    在这个枚举里写错，导入期就炸。

    取值的选取口径是 **PRD §10 靶场漏洞清单 ∪ PRD §7.1 列出的 sink 族**，
    不多造：PRD 把 `eval` / `exec` 归入「命令执行」，这里就跟着归到
    `COMMAND_INJECTION`，而不是另立一个 `code_injection`。
    """

    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    FILE_UPLOAD = "file_upload"
    DESERIALIZATION = "deserialization"
    XSS = "xss"
    IDOR = "idor"  # 平行越权
    UNAUTH_ACCESS = "unauth_access"  # 未授权访问（整表暴露，不带 id 形参）
    INFO_DISCLOSURE = "info_disclosure"
    HARDCODED_SECRET = "hardcoded_secret"  # noqa: S105 —— 枚举成员名，不是口令


#: vuln_type → CWE 编号。报告与前端详情页要展示，且**同一类型必须永远同一个 CWE**
#: （LLM 不许碰这两个字段，见契约 2 的 L1 落点）。
#:
#: 映射依据：CWE-89 SQL 注入、CWE-78 OS 命令注入、CWE-22 路径穿越、
#: CWE-434 不受限文件上传、CWE-502 不可信数据反序列化、CWE-79 XSS、
#: CWE-639 通过用户可控键的越权访问、CWE-200 敏感信息暴露、CWE-798 硬编码凭证。
CWE_BY_VULN: dict[VulnType, str] = {
    VulnType.SQL_INJECTION: "CWE-89",
    VulnType.COMMAND_INJECTION: "CWE-78",
    VulnType.PATH_TRAVERSAL: "CWE-22",
    VulnType.FILE_UPLOAD: "CWE-434",
    VulnType.DESERIALIZATION: "CWE-502",
    VulnType.XSS: "CWE-79",
    VulnType.IDOR: "CWE-639",
    # CWE-306「关键功能缺少身份认证」—— 与 CWE-639 的区别是：
    # 639 是**认了人但没校验归属**，306 是**压根没验证来人是谁**。
    VulnType.UNAUTH_ACCESS: "CWE-306",
    VulnType.INFO_DISCLOSURE: "CWE-200",
    VulnType.HARDCODED_SECRET: "CWE-798",
}


@dataclass(frozen=True, slots=True)
class TaintStep:
    """污点路径上的一跳。前端 F3 的时间轴直接按这个数组渲染。

    `file_path` 一律为**工作区根相对 POSIX 路径**（`app/api/order.py`），
    绝不带盘符或 Windows 反斜杠 —— 绝对路径的换算是 `projects/workspace.py` 与
    `sandbox/` 的职责，B4 只认工作区根（总纲 §7.4、契约 5）。

    `step_kind` 用 `TaintStepType` 而不是裸 `str`：契约 2 写的是 `str`，
    而 `TaintStepType` 是 `StrEnum`（值就是 `"source"`/`"sanitize"` 那几个字符串），
    比 `str` 更窄、且能直接对到 ORM 的 `taint_paths.step_type` 列。
    """

    step_index: int
    file_path: str  # 相对工作区根的 POSIX 路径
    line: int
    column: int
    symbol: str
    step_kind: TaintStepType  # source | propagate | sanitize | sink
    snippet: str  # 该行的源码片段，供前端高亮


@dataclass(frozen=True, slots=True)
class Finding:
    """一条疑似漏洞。**字段顺序与契约 2 完全一致**，附加字段一律排在最后。

    `guard_blocked` 的语义要说清楚，否则会被误读成「被拦下了为什么还报」：

    - **完全净化**（路径上存在强度 `full` 且覆盖该 `vuln_type` 的 sanitizer）
      ⇒ **不产出 Finding**（设计文档 §4.4），所以不存在「被完全拦下却仍有记录」的情况。
    - `guard_blocked=True` 表示路径上存在**已命中但不足以完全中和**的净化
      （部分强度、或覆盖不到该漏洞类型），等价于设计文档的 `partially_sanitized`：
      **仍然报**，但 `confidence` 已按 `×0.6` 打过折，供人工优先复核。
    """

    rule_id: str
    vuln_type: VulnType
    severity: Severity
    file_path: str
    line_start: int
    line_end: int
    symbol: str  # 下沉点符号名（对应 ORM 的 sink_symbol，是补丁复验的身份锚）
    cwe_id: str | None
    cvss_vector: str
    cvss_score: float
    confidence: float  # 0.0–1.0，**由确定性规则算出，不是 LLM 给的**
    #: 输入**通道**（`sources.CHANNELS` 之一：http_param / http_body / cookie /
    #: header / env / argv / stdin / db_read）。存通道而不是 source 符号名，
    #: 是因为符号名已经在 `taint_path[0].symbol` 里了，再存一遍纯属冗余；
    #: 而「这条漏洞是从哪种输入进来的」是报告与前端筛选真正需要、
    #: 又无法从别处推出来的信息。pattern 类规则用 `source_code` / `route_param`
    #: 两个通道外的取值，因为它们本就没有数据流入口（见 `patterns.py`）。
    source_kind: str
    sink_kind: str  # sink 符号，如 "cursor.execute"（与 symbol 同值，见下）
    guard_blocked: bool  # 路径上存在生效但不足以中和的净化函数
    taint_path: tuple[TaintStep, ...]
    # --- 以下为契约 2 之外的附加字段（均有默认值），落 places 必需 ---
    #: 中文标题，由 vuln_type × sink 符号确定性拼出（B4 内不含任何 LLM）
    title: str = ""
    #: taint_intra / taint_inter / pattern —— 决定 B3 落库的 detection_method 列
    detection_method: DetectionMethod = DetectionMethod.TAINT_INTRA
    #: 「调用链更深、静态未展开」的显式标注（设计文档 §3.2 取舍 8）
    unexpanded: bool = False
    #: 触发行 ±20 行的源码片段，供 LLM 文案与前端高亮
    code_snippet: str = ""

    @property
    def sink_symbol(self) -> str:
        """ORM 列名的别名读法。`symbol` 与 `sink_kind` 同值（契约 2 同时冻结了这两个
        名字），这里给一个语义明确的名字，B3 落 `sink_symbol` 列时用它更不容易错位。"""
        return self.symbol


@dataclass(frozen=True, slots=True)
class SkipRecord:
    """被跳过的文件。对应设计文档 §6 的「跳过 + 记录」，永不因此中断整轮扫描。

    `level` 用总纲 §9.1 的级别（`L1` / `L2`）：静态分析的产出是统计量
    （召回率 / 误报数），少一个文件只是少一点覆盖，不该让整次评估作废。
    """

    path: str
    reason: str
    level: str


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """`analyze()` 的产出。**契约 4 规定的 B3 入口返回值。**

    `duration_ms` 是实测耗时，因此**不参与确定性契约**：确定性只承诺
    `findings` 逐字段可复现（同一个输入跑两次必须完全相等），耗时天然不可复现。
    把耗时也纳进确定性是在承诺一件做不到的事，不如把边界写清楚。
    """

    findings: tuple[Finding, ...]
    files_scanned: int
    total_loc: int
    duration_ms: int
    #: 触发 `max_files` / `max_seconds` 上限，或输入清单本身已被 B1 截断。
    #: 为 True 时报告必须注明「本次只分析了前 N 个文件」——否则用户会把
    #: 「没扫到」误读成「没有漏洞」。
    truncated: bool
    #: 附加字段：逐文件的跳过原因（设计文档 §5.1 要求拼进 assessment_stages.log_excerpt）
    files_skipped: tuple[SkipRecord, ...] = ()
    #: 附加字段：「调用链更深、未展开」的调用点计数（设计文档 §3.3 TaintReport）
    unexpanded_calls: int = 0
