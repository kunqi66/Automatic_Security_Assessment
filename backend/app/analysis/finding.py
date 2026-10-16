"""Finding 组装：把「事实」翻译成契约里的 `Finding`（设计文档 §3.2）。

**为什么单独一个文件**：`Finding` 的字段有 19 个，其中 6 个（severity / cvss_vector /
cvss_score / cwe_id / title / code_snippet）与漏洞事实无关，纯粹由 `vuln_type`
派生。这些派生规则只写一遍、且只写在这里，B4 内部（taint 与 patterns）
就不会各自算一遍再慢慢漂移 —— 两条路径产出的 Finding 字段口径不一致，
是这一层最难查的一类 bug（单测各自都过，合起来对不上）。

**本文件是纯函数**：给定同一组入参必然产出同一个 `Finding`，
没有时间戳、没有随机 ID、没有自增计数器。确定性契约就落在这里。
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from app.analysis.cvss import score_for
from app.analysis.types import CWE_BY_VULN, Finding, TaintStep, VulnType
from app.models.enums import DetectionMethod

#: 漏洞类型 → 报告标题（写入 `vulnerabilities.title`，NOT NULL）。
#:
#: 措辞与 PRD §10.2 的靶场条目（V1「SQL 注入」…）保持一致：
#: 演示时报告里的标题、靶场编号、GROUND_TRUTH 三处对得上，
#: 否则评委要花时间确认「这两个说的是不是同一件事」。
TITLE_BY_VULN: dict[VulnType, str] = {
    VulnType.SQL_INJECTION: "SQL 注入",
    VulnType.COMMAND_INJECTION: "命令注入",
    VulnType.PATH_TRAVERSAL: "路径穿越",
    VulnType.FILE_UPLOAD: "不受限文件上传",
    VulnType.DESERIALIZATION: "不安全反序列化",
    VulnType.XSS: "跨站脚本（XSS）",
    VulnType.IDOR: "越权访问（IDOR）",
    VulnType.UNAUTH_ACCESS: "未授权访问",
    VulnType.INFO_DISCLOSURE: "敏感信息泄露",
    VulnType.HARDCODED_SECRET: "硬编码凭据",
}

#: 基础置信度（设计文档 §4.5）
BASE_CONFIDENCE = 0.9
#: 跨函数传播（一层）：调用点与摘要的匹配存在固有误差，乘 0.9
INTER_CONFIDENCE_FACTOR = 0.9
#: 路径上只有弱净化（`str()` / `json.dumps()` / `.strip()`）
PARTIAL_CONFIDENCE_FACTOR = 0.6
#: RCE 类：能到达 `os.system` / `eval` 这些 sink 的值本身极难是良性的，上调
RCE_CONFIDENCE_FACTOR = 1.1
#: RCE 类的漏洞类型集合（设计文档 §4.5 的 ×1.1 条件）
RCE_TYPES: frozenset[VulnType] = frozenset({VulnType.COMMAND_INJECTION, VulnType.DESERIALIZATION})


def compute_confidence(
    *,
    inter_procedural: bool = False,
    partial: bool = False,
    rce: bool = False,
) -> float:
    """设计文档 §4.5 的置信度公式：`0.9 × 0.9(inter) × 0.6(partial) × 1.1(rce)`。

    上限 1.0、保留 3 位小数。上限这一步不是形式主义：`0.9 × 1.1 = 0.99`，
    再叠一次上调就会越过 1.0，而置信度 >1 在下游（B5 排序、B6 报告）
    会被当成「比确定还确定」，是最容易被追问又最没法解释的取值。
    """
    value = BASE_CONFIDENCE
    if inter_procedural:
        value *= INTER_CONFIDENCE_FACTOR
    if partial:
        value *= PARTIAL_CONFIDENCE_FACTOR
    if rce:
        value *= RCE_CONFIDENCE_FACTOR
    return round(min(value, 1.0), 3)


def _snippet_at(steps: Sequence[TaintStep], fallback: str) -> str:
    """取路径末跳的代码片段作为 `code_snippet`（写入 ORM 的 `code_snippet`）。

    末跳就是 sink —— 复现漏洞时要照抄的那一行在最后，不在开头。
    """
    if steps and steps[-1].snippet:
        return steps[-1].snippet
    return fallback


def make_finding(
    *,
    vuln_type: VulnType,
    file_path: str,
    line_start: int,
    line_end: int,
    symbol: str,
    steps: Sequence[TaintStep],
    source_kind: str,
    sink_kind: str,
    guard_blocked: bool,
    detection_method: DetectionMethod,
    inter_procedural: bool = False,
    partial: bool = False,
    unexpanded: bool = False,
    requires_auth: bool = False,
    remote: bool = True,
    confidence: float | None = None,
) -> Finding:
    """组装一条 Finding。CVSS 与严重度**全部由 `vuln_type` 派生**。

    `confidence` 显式传入时优先（pattern 类规则的置信度不适用 §4.5 的公式，
    它是「有多少同类记录被判过」的先验，不是「路径有多完整」的度量）；
    不传则按公式算 —— 保证两类 Finding 的置信度都来自**可复算的规则**，
    而不是某处的魔数。

    **本函数不产出 `description`**：那是给人读的自然语言，属 B6（LLM）职责。
    B4 只给 `code_snippet` 这类**原始事实**；一旦 B4 开始在结论里写句子，
    「拿掉 LLM 结论不变」就不再成立（总纲 L1）。
    """
    vector, score, severity = score_for(vuln_type, requires_auth=requires_auth, remote=remote)
    resolved_confidence = (
        confidence
        if confidence is not None
        else compute_confidence(
            inter_procedural=inter_procedural,
            partial=partial,
            rce=vuln_type in RCE_TYPES,
        )
    )
    # 步号在这里**统一重排**：`step_index` 是给前端画时间线用的，
    # 必须与元组下标一致。让各调用方自己编号的话，只要有一处漏编或跳号，
    # 前端就会把「形参入口」画到「sink」后面 —— 而且没人会立刻发现。
    normalized = tuple(replace(step, step_index=index) for index, step in enumerate(steps))
    return Finding(
        rule_id=vuln_type.value,
        vuln_type=vuln_type,
        severity=severity,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        symbol=symbol,
        cwe_id=CWE_BY_VULN.get(vuln_type),
        cvss_vector=vector,
        cvss_score=score,
        confidence=resolved_confidence,
        source_kind=source_kind,
        sink_kind=sink_kind,
        guard_blocked=guard_blocked,
        taint_path=normalized,
        title=TITLE_BY_VULN[vuln_type],
        detection_method=detection_method,
        unexpanded=unexpanded,
        code_snippet=_snippet_at(steps, symbol),
    )


def finding_sort_key(finding: Finding) -> tuple[str, int, int, str, int]:
    """Finding 的**全序**排序键。

    排序键必须覆盖「同一位置可能有多条不同类型 Finding」的情况，
    所以结尾带上 `rule_id`。只按 (文件, 行) 排的话，同一行的两条 Finding
    相对顺序取决于稳定排序前列表的构造顺序 —— 那不是一个可复现的承诺。
    """
    return (
        finding.file_path,
        finding.line_start,
        finding.line_end,
        finding.rule_id,
        len(finding.taint_path),
    )


def dedupe(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    """按设计文档 §4.3 的去重键去重并排序。

    去重键是 `(来源行, sink 行, 漏洞类型)`，**不含文件**：同一条路径在
    同一文件里是唯一的，而跨文件重复意味着摘要表把不同文件的同名函数
    当成了同一个 —— 那种情况应当修符号表，不该在这里用「加个文件名」把
    症状盖掉。保留的是**置信度更高**的那条；置信度相同则保留路径更长的
    （信息更多，且这个 tie-break 是确定性的）。
    """
    best: dict[tuple[int, int, str], Finding] = {}
    for finding in findings:
        source_line = finding.taint_path[0].line if finding.taint_path else finding.line_start
        key = (source_line, finding.line_start, finding.rule_id)
        current = best.get(key)
        if current is None or (finding.confidence, len(finding.taint_path)) > (
            current.confidence,
            len(current.taint_path),
        ):
            best[key] = finding
    return tuple(sorted(best.values(), key=finding_sort_key))
