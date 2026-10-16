"""B6 的数据结构（B6 模块设计 §3.3）。

## 一条贯穿全包的原则：`ReportData` 只构建一次

报告有 HTML / Markdown / PDF 三种格式，全部由**同一个 `ReportData` 实例**渲染
（B6 设计 §4.1「两条不可违背」）。三次查库会让同一份报告的三个格式里出现不同的
数字 —— 而安全报告里「HTML 说 3 个高危、PDF 说 4 个」是致命的可信度问题。
因此：**模板里不查库、不聚合、不排序，只做呈现。**

## 枚举一律复用 `models/enums.py`

设计文档 §3.3 就地定义了 `ExportFormat` 与 `SecurityGrade`，但 `models/enums.py`
里已经有 `ReportFormat` 与 `SecurityGrade`（PRD §6 的行列取值 SSOT）。这里**复用后者**，
不新建同名两套 —— 两套枚举的后果是「`reports.format` 存的值」与「代码里判的值」
在某个分支上对不上，而那种错不会报错，只会静默走错分支。
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import (
    ChainNodeType,
    DetectionMethod,
    PatchSource,
    PatchStatus,
    ReportFormat,
    SecurityGrade,
    Severity,
    StageName,
    StageStatus,
    VerificationStatus,
    VulnStatus,
)

#: 项目综合等级的中文展示名（B6 设计 §3.3 GRADE_LABEL）。
#: ⚠️**项目级一律称「项目综合等级」**，漏洞级一律称「漏洞严重度」，两者不可混用
#: （PRD §6 关键设计说明 2）。
GRADE_LABEL: dict[str, str] = {
    SecurityGrade.CRITICAL.value: "极高危",
    SecurityGrade.HIGH.value: "高危",
    SecurityGrade.MEDIUM.value: "中危",
    SecurityGrade.SAFE.value: "安全",
}

#: 「评分不完整」的标记值：`vulnerabilities.cvss_score` 为 NULL 时，
#: 评分按 severity 中位值代入（B6 设计 §4.3 边界处理），报告必须标注这件事。
INCOMPLETE_GRADE_NOTE = "部分漏洞缺少 CVSS 评分，已按漏洞严重度中位值代入，评分不完整"


#: 单漏洞严重度的中文展示名。
#: ⚠️ 与 `GRADE_LABEL`（项目综合等级）**不是一套术语**：这里是漏洞级，那里是项目级，
#: 报告里不得互相套用（PRD §6 关键设计说明 2）。
SEVERITY_LABEL: dict[str, str] = {
    Severity.CRITICAL.value: "严重",
    Severity.HIGH.value: "高危",
    Severity.MEDIUM.value: "中危",
    Severity.LOW.value: "低危",
}

#: 漏洞四态的中文口径。**`skipped` 刻意没有对应值** —— 它是**阶段**状态。
#: 把「跳过」写进漏洞状态栏，就会出现「未验证 = 无风险」这种报告里最常见的误读。
#:
#: ⚠️ `rejected` 的措辞改过一次，改的理由值得留着：原先是「已复核排除」，
#: 而**没有任何人工复核发生在这一步**——它是 `verify` 阶段全自动产出的，
#: 入口只有 `fingerprints.can_conclude_absence` 一个。用「已复核」描述机器结论，
#: 等于替读者的怀疑做了担保，而这一步恰恰是全链路**最容易出错**的地方：
#: 实测跑出过两条真 SQL 注入被标成 `rejected`（参数名推导错了，探针打在一个
#: 不读该参数的路由上，布尔差分如实报告「无差异」）。报告的措辞若说
#: 「人工已排除」，读者就不会去复核它 —— 这正是假阴性得以存活的方式。
STATUS_LABEL: dict[str, str] = {
    VulnStatus.VERIFIED.value: "已通过动态验证",
    VulnStatus.POTENTIAL.value: "存在利用线索，未完全坐实",
    VulnStatus.UNVERIFIED.value: "未经验证（仅静态分析结论）",
    VulnStatus.REJECTED.value: "动态未复现（机器判定，待人工确认）",
}


def grade_label(grade: SecurityGrade | str) -> str:
    value = getattr(grade, "value", grade)
    return GRADE_LABEL.get(str(value), str(value))


def severity_label(severity: Severity | str) -> str:
    value = getattr(severity, "value", severity)
    return SEVERITY_LABEL.get(str(value), str(value))


def status_label(status: VulnStatus | str) -> str:
    value = getattr(status, "value", status)
    return STATUS_LABEL.get(str(value), str(value))


# ---------------------------------------------------------------------------
# 第 1 章：项目概况与执行信息
# ---------------------------------------------------------------------------


class StageSummary(BaseModel):
    """五 Agent 执行摘要表的一行。`status` 含 `skipped` —— **降级不是失败**。"""

    stage: StageName
    status: StageStatus
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    #: 失败或 skip 的原因（`assessment_stages.note`）。**不叫 error_message**：
    #: skip 是降级而非错误（总纲 §9.1 L3）
    note: str | None = None


class ReportMeta(BaseModel):
    assessment_id: int
    project_id: int
    project_name: str
    project_description: str | None = None
    source_type: str
    source_url: str | None = None
    source_branch: str | None = None
    tech_stack: dict[str, str] = Field(default_factory=dict)
    total_loc: int
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    stages: list[StageSummary] = Field(default_factory=list)
    #: 数据缺失的降级标记（如 `tech_stack` 为空、`total_loc` 未知）
    degraded: list[str] = Field(default_factory=list)
    generated_at: datetime


# ---------------------------------------------------------------------------
# 第 2 章：安全评分与风险大盘
# ---------------------------------------------------------------------------


class SecurityScore(BaseModel):
    """由 `scoring.py` 纯函数产出（PRD §6 的两个回写列）。"""

    score: float = Field(ge=0.0, le=100.0)
    grade: SecurityGrade
    #: 是否触发「一票否决」（存在 verified 的 critical）
    veto: bool
    #: 各级别罚分明细，「评分是怎么来的」必须能被当场复算
    breakdown: dict[str, float] = Field(default_factory=dict)
    #: 是否有漏洞缺 CVSS 而被迫代入中位值
    incomplete: bool = False

    @property
    def grade_cn(self) -> str:
        return grade_label(self.grade)


class TypeSlice(BaseModel):
    """漏洞类型占比切片。`ratio` 由代码算，模板不做除法。"""

    category: str
    label: str
    count: int
    ratio: float


# ---------------------------------------------------------------------------
# 第 3 章：漏洞清单
# ---------------------------------------------------------------------------


class TaintStepEntry(BaseModel):
    step_index: int
    step_type: str  # 沿用 ORM 列名 `taint_paths.step_type`（PRD §6 命名 SSOT）
    file_path: str
    line: int
    symbol: str | None = None
    code_snippet: str | None = None
    note: str | None = None


class PocEvidence(BaseModel):
    """一次无害化探针的执行记录。**只收 `harmless_guard_passed=true` 的记录** ——
    被闸门拦下的尝试不是验证依据（B6 设计 §5.1、PRD §7.3）。"""

    technique: str | None = None
    payload: str
    request_raw: str | None = None
    response_raw: str | None = None
    expected_pattern: str | None = None
    matched: bool
    http_status: int | None = None
    elapsed_ms: int | None = None
    failure_reason: str | None = None
    #: 探针是不是打在**本条 finding 自己的端点**上（`verify.routes` 反查所得）。
    #:
    #: ⚠️ 这个字段决定报告里那句「已通过动态验证」**到底证明了什么**：
    #: `True` = 这一行所在的端点确实被跑通了；
    #: `False` = 只证明了「该类漏洞在本目标上存在」，本条**没有被逐点验证**。
    #: 靶场实测 15 条 finding 里 10 条是后者 —— 所以这一格必须印出来，
    #: 否则报告会把两种强度完全不同的结论写成同一句话。
    #: ⚠️ 由**漏洞状态**推出（`status == verified`），不是另存一列。
    #:
    #: 理由有两条，都是硬的：
    #: ① 不变量：`runner` 里只有"绑上了本条自己的端点且命中"才落 `verified`，
    #:    所以 `verified ⟺ 逐点确认` 成立，报告不需要为此再存一份；
    #: ② `poc_attempts` 加列要先改 PRD §6（本项目列名 SSOT），
    #:    而这一格不带来新事实 —— 真正逐点的那条请求路径在 `request_raw` 里。
    bound_to_finding: bool = False


class PatchEntry(BaseModel):
    """修复建议补丁。**绝不自动应用** —— 由开发者复核后手动采纳（需求 2.5.2）。"""

    target_file: str
    diff: str
    status: PatchStatus
    #: 产出源：`llm` / `template` / `validate_failed`。
    #: `validate_failed` 表示四道校验未过、已降级为**人工参考** —— 报告必须显式标注
    source: PatchSource
    llm_model: str | None = None
    rationale: str | None = None
    #: 四道校验逐道结果（总纲 §8.5）。逐道给出才能说清「卡在哪一道」。
    valid_diff: bool
    window_ok: bool
    apply_check_ok: bool
    taint_cleared: bool
    failure_reason: str | None = None

    @property
    def all_gates_passed(self) -> bool:
        return self.valid_diff and self.window_ok and self.apply_check_ok and self.taint_cleared


class VulnEntry(BaseModel):
    """第 3 章的单元，聚合四张表（B6 设计 §3.3）。"""

    id: int
    code: str
    title: str
    vuln_type: str
    type_label: str
    severity: Severity
    severity_cn: str
    cvss_score: float
    cvss_vector: str | None = None
    #: CVSS 为 NULL、按严重度中位值代入 —— 报告要标「评分不完整」
    cvss_estimated: bool = False
    status: VulnStatus
    status_cn: str
    file_path: str
    line_start: int
    line_end: int
    sink_symbol: str | None = None
    code_snippet: str | None = None
    description: str
    remediation_note: str
    confidence: float
    detection_method: DetectionMethod
    #: 是否有探针被无害化闸门拦下（派生，无对应列）。**必须标出来**：
    #: 它表示「风险存在但未坐实」，与「没发现风险」是完全不同的两件事。
    guard_blocked: bool
    taint_path: list[TaintStepEntry] = Field(default_factory=list)
    poc: PocEvidence | None = None
    patch: PatchEntry | None = None
    #: 单条漏洞的字段缺失标记（无 CVSS / 无污点路径 / 无探针）
    data_incomplete: bool = False


# ---------------------------------------------------------------------------
# 第 4 章：多步攻击路径推演
# ---------------------------------------------------------------------------


class ChainNodeEntry(BaseModel):
    order_index: int
    node_type: ChainNodeType
    label: str
    detail: str | None = None
    stage_name: str | None = None
    precondition: str | None = None
    postcondition: str | None = None
    rule_id: str | None = None
    vuln_code: str | None = None
    #: ★ Q24 定案：`verified` 实线主色 / `inferred` 虚线淡化（B6 设计 §4.5）
    verification_status: VerificationStatus

    @property
    def is_verified(self) -> bool:
        return self.verification_status == VerificationStatus.VERIFIED

    @property
    def mark(self) -> str:
        """无颜色格式（Markdown）用文字前缀替代配色，保证三格式口径一致。"""
        return "[已验证]" if self.is_verified else "[已推演]"


class ChainEntry(BaseModel):
    id: int
    name: str
    description: str | None = None
    severity: Severity | None = None
    entry_point: str | None = None
    target_asset: str | None = None
    confidence: float
    nodes: list[ChainNodeEntry] = Field(default_factory=list)
    #: 表达层产物（LLM 或模板），**不影响图结构**
    narrative: str
    narrative_model: str
    narrative_degraded: bool = False
    #: 逐链动态生成的脚注（B6 设计 §4.5 第 3 条，**不得写死**）
    verification_footnote: str = ""

    @property
    def verified_count(self) -> int:
        return sum(1 for n in self.nodes if n.is_verified)

    @property
    def inferred_count(self) -> int:
        return len(self.nodes) - self.verified_count


def build_verification_footnote(nodes: list[ChainNodeEntry]) -> str:
    """逐链按**实际**环数生成脚注（B6 设计 §4.5 第 3 条）。

    以 PRD §10.1 的演示链为例输出：
    「第 1–2 环已在沙箱中无害验证，第 3 环由已证实的前置条件推演得出，未实际执行」。
    环数变化时按同一模板改写为「第 X 环未实际执行」。

    ⚠️ 措辞约束：本章用「**验证 / 推演**」二分，**不得**与 `vulnerabilities.status`
    的 `verified` / `unverified` 混用，也不得写「未验证漏洞」这种歧义表述。
    """
    verified = [n.order_index + 1 for n in nodes if n.is_verified]
    inferred = [n.order_index + 1 for n in nodes if not n.is_verified]
    if not nodes:
        return ""
    if not inferred:
        return f"第 {_ranges(verified)} 环已在沙箱中无害验证。"
    if not verified:
        return f"本链 {len(nodes)} 环均由已证实的前置条件推演得出，未实际执行。"
    return (
        f"第 {_ranges(verified)} 环已在沙箱中无害验证，"
        f"第 {_ranges(inferred)} 环由已证实的前置条件推演得出，未实际执行。"
    )


def _ranges(numbers: list[int]) -> str:
    """把 `[1,2,3,5]` 压成 `1–3、5`。脚注里逐环列「第 1、2、3、4、5 环」很啰嗦，
    而演示链恰好是连续环 —— 压一下读起来才像人写的。"""
    if not numbers:
        return ""
    parts: list[str] = []
    start = prev = numbers[0]
    for n in numbers[1:]:
        if n == prev + 1:
            prev = n
            continue
        parts.append(str(start) if start == prev else f"{start}–{prev}")
        start = prev = n
    parts.append(str(start) if start == prev else f"{start}–{prev}")
    return "、".join(parts)


# ---------------------------------------------------------------------------
# 第 5 章：安全整改建议
# ---------------------------------------------------------------------------


class Recommendation(BaseModel):
    """一个整改项。

    **优先级与排序由 `scoring.py` 的确定性公式产出**（等级 × 可达性 × 修复成本），
    LLM 只写 `note` 文案、不参与排序（PRD §7.6.3 用点④）。
    """

    rank: int
    code: str
    title: str
    type_label: str
    severity: Severity
    severity_cn: str
    status: VulnStatus
    status_cn: str
    cvss_score: float
    file_path: str
    line_start: int
    line_end: int
    #: 确定性优先级分（越大越该先修）
    priority: float
    #: 优先级因子的明细，让「为什么它排在前面」可当场复算
    priority_factors: dict[str, float] = Field(default_factory=dict)
    #: 整改建议文案：LLM 或确定性模板（`llm_model` 区分，前端据此标「模板生成」）
    note: str
    note_model: str
    note_degraded: bool = False
    patch: PatchEntry | None = None


# ---------------------------------------------------------------------------
# 渲染输入与产物
# ---------------------------------------------------------------------------


class ReportData(BaseModel):
    """**渲染的唯一输入**。三种格式全部由它派生，模板禁止各自查库。"""

    meta: ReportMeta
    score: SecurityScore
    #: (severity, status) → 计数
    severity_matrix: dict[tuple[str, str], int] = Field(default_factory=dict)
    #: severity → 计数（柱状图用）。与 `severity_matrix` 是同一份事实的两个投影，
    #: 都在装配时算好 —— 模板里做 `sum(...)` 就是在模板里做聚合，违反 §4.1 ②
    severity_counts: dict[str, int] = Field(default_factory=dict)
    #: severity → 该行合计（分布矩阵的最后一行）。同样在装配时算好。
    severity_row_totals: dict[str, int] = Field(default_factory=dict)
    type_distribution: list[TypeSlice] = Field(default_factory=list)
    vulnerabilities: list[VulnEntry] = Field(default_factory=list)
    chains: list[ChainEntry] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)
    #: 如 ["llm", "pdf", "chain", "cvss"]
    degraded: list[str] = Field(default_factory=list)

    # ---- 呈现层的派生字段：**在装配时算好，模板里不做判断**（B6 设计 §4.1 ②）----
    #: 是否存在通过动态验证的漏洞 —— 决定第 3 章是「已验证清单」还是「未验证清单」
    has_verified: bool = False
    chapter3_title: str = "已验证漏洞清单"
    chapter3_note: str = ""
    #: 无攻击链时第 4 章的整章占位说明（L3：exploit_chain skipped）
    chapter4_placeholder: str | None = None
    #: 无漏洞时第 2 章的空态
    empty_state: bool = False
    #: 已复核排除、因此不进第 5 章整改清单的条数（**如实标注，不是悄悄丢掉**）
    excluded_rejected: int = 0
    #: 第 5 章里由确定性模板生成文案的条数 —— 报告要显式标注「模板生成」（PRD §7.6.2 L4）
    notes_template_count: int = 0


class ReportSummary(BaseModel):
    """写入 `reports.summary`。

    大盘页的「平均安全评分」改由 `assessments.security_score` 聚合承担
    （B6 设计 §5.2），这个 JSON 只为报告中心列表服务，免去解析正文。
    """

    assessment_id: int
    project_name: str
    generated_at: datetime
    score: float
    grade: SecurityGrade
    grade_cn: str
    total: int
    by_status: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    chain_count: int
    formats: list[ReportFormat] = Field(default_factory=list)
    degraded: list[str] = Field(default_factory=list)
    #: 置顶的漏洞编码（严格按第 3 章同一个排序取前若干条，**不另立一套排序**）
    top_codes: list[str] = Field(default_factory=list)


class ReportDraft(BaseModel):
    """`report_gen` 阶段的产出：**已装配、已渲染，但尚未落盘**。

    契约 4 规定的入口 `report.build_report(assessment_id, session) -> ReportDraft`
    返回的就是它。落盘与写库是下一步（`exporter.py`）—— 拆开是因为
    **事务边界属于调用方**（总纲 §9.3：阶段边界才是提交点）。
    """

    assessment_id: int
    data: ReportData
    html: str
    markdown: str
    summary: ReportSummary
    degraded: list[str] = Field(default_factory=list)


class ExportResult(BaseModel):
    """单格式导出的结果。"""

    assessment_id: int
    format: ReportFormat
    #: 相对 `REPORT_ROOT` 的 POSIX 路径（总纲 §7.4：入库路径一律相对）
    content_path: str | None
    size_bytes: int | None = None
    #: 该格式是否降级（目前只有 PDF 会：Chromium 未安装 / 打印超时）
    degraded: bool = False
    message: str | None = None


__all__ = [
    "GRADE_LABEL",
    "INCOMPLETE_GRADE_NOTE",
    "SEVERITY_LABEL",
    "STATUS_LABEL",
    "ChainEntry",
    "ChainNodeEntry",
    "ExportResult",
    "PatchEntry",
    "PocEvidence",
    "Recommendation",
    "ReportData",
    "ReportDraft",
    "ReportMeta",
    "ReportSummary",
    "SecurityScore",
    "StageSummary",
    "TaintStepEntry",
    "TypeSlice",
    "VulnEntry",
    "build_verification_footnote",
    "grade_label",
    "severity_label",
    "status_label",
]
