"""四个封闭使用点的 prompt 构造。

## 唯一的写作纪律：**只给已确定的事实，只要求改写为中文**

PRD §7.6.2 的 L1 / L2 在 prompt 层的落点就一句话：

> **不派发开放性任务。** 没有「请分析这段代码有什么问题」，只有
> 「这是代码审计引擎已经判定的结论，请把它写成通顺的中文」。

具体到每一段 prompt：

- `severity` / `status` / `cvss_score` / `guard_blocked` / 链的节点与边 /
  污点路径的每一跳 —— **全部作为 known facts 塞进 user 消息**，
  模型的任务是措辞，不是判定。
- system 消息里明确禁止「新增输入中不存在的文件路径 / 行号 / CVE / 漏洞编码」。
  这条**不能只靠模型自觉**：`guard.py` 会做实体白名单校验，不达标整段拒收走模板。
- 不要求模型输出 JSON 或任何机器可解析的结构 —— 一旦输出变成结构化数据，
  下一个接手的人就会拿它去做判断，L1 就守不住了。

**为什么要把 prompt 单独放一个文件**：这段文本是本系统「可控多智能体」立场的
载体，它需要被单独 review、单独 diff。散在四个函数里就没人能一眼看全
「我们到底让模型做了什么事」。
"""

from __future__ import annotations

import json
from typing import Any

from app.llm.types import ChainView, ChatMessage, FindingView

#: 四个用点共用的 system 消息。**简短是刻意的** —— 约束靠下面的事实清单与
#: 代码里的白名单校验来兜，而不是靠一段越来越长的「请不要…」祈祷。
_BASE_SYSTEM = (
    "你是安全评估报告的中文技术写作助手。"
    "你只负责把用户给出的结构化事实改写为通顺、专业的中文，"
    "不得新增、推断或改写任何事实。"
    "禁止出现用户输入里没有的文件路径、行号、CVE 编号、漏洞编码或函数名。"
    "禁止评价漏洞是否成立、严重度是否合理 —— 这些结论已经由确定性分析给出，"
    "你只需要把它们表述清楚。"
)


def _facts(payload: dict[str, Any]) -> str:
    """把事实清单渲染成 user 消息。

    `ensure_ascii=False`：中文事实原样送出，不要把 prompt 变成一堆 `\\uXXXX` ——
    那既浪费 token，也会让 review prompt 的人看不出到底喂了什么。
    """
    return (
        "以下是已完成分析的事实（全部由确定性代码产出，不需要你复核）：\n"
        f"{json.dumps(payload, ensure_ascii=False, indent=2, default=str)}\n\n"
    )


def _strip_none(payload: dict[str, Any]) -> dict[str, Any]:
    """去掉值为空的字段。

    空字段进 prompt 的代价不只是 token：模型看到 `"cwe_id": null` 容易顺手补一个
    CWE 出来 —— 那正是 L2 禁止的「引入输入里没有的事实」。
    """
    return {k: v for k, v in payload.items() if v not in (None, "", [], {})}


# ---------------------------------------------------------------------------
# ① 漏洞中文描述
# ---------------------------------------------------------------------------


def build_description_messages(finding: FindingView) -> list[ChatMessage]:
    """用点 ①：漏洞描述。"""
    steps = [
        {
            "序号": s.step_index,
            "角色": s.step_kind,
            "位置": f"{s.file_path}:{s.line}",
            "符号": s.symbol,
            "源码": s.snippet,
        }
        for s in finding.taint_path
    ]
    payload = _strip_none(
        {
            "漏洞编号": finding.code,
            "漏洞类型": finding.vuln_type,
            "标题": finding.title,
            "严重度（已判定）": finding.severity,
            "状态（已判定）": finding.status,
            "CVSS": finding.cvss_score,
            "CVSS 向量": finding.cvss_vector,
            "CWE": finding.cwe_id,
            "触发位置": f"{finding.file_path}:{finding.line_start}-{finding.line_end}",
            "下沉符号": finding.symbol,
            "污点来源类别": finding.source_kind,
            "下沉点类别": finding.sink_kind,
            "路径上存在生效的净化函数": finding.guard_blocked,
            "置信度": finding.confidence,
            "污点路径（已判定，按序）": steps,
            "源码片段": finding.source_snippet,
        }
    )
    instruction = (
        "请写一段 120–260 字的中文描述，依次说明："
        "① 该漏洞的位置与类型；② 污点数据从哪里进入、经过哪些跳传播、在哪里汇聚成危险操作；"
        "③ 若路径上存在生效的净化函数，请如实说明「该处输入已被净化，因此风险降低」；"
        "④ 结合上述位置说明潜在危害。"
        "不要罗列 JSON 字段名，不要给出修复代码，不要重复严重度数值以外的判断。"
    )
    return [
        ChatMessage(role="system", content=_BASE_SYSTEM),
        ChatMessage(role="user", content=_facts(payload) + instruction),
    ]


# ---------------------------------------------------------------------------
# ② Diff 修复补丁
# ---------------------------------------------------------------------------


def build_patch_messages(finding: FindingView) -> list[ChatMessage]:
    """用点 ②：补丁草案。

    只送 ±20 行上下文（PRD §7.6.1：「不发送整个文件」）—— 这既是成本考虑，
    也是安全考虑：送得越多，模型「顺手重构」的空间越大，而第 2 道校验
    （只允许改 ±20 行窗口）正是为此设的。
    """
    payload = _strip_none(
        {
            "漏洞类型": finding.vuln_type,
            "严重度（已判定）": finding.severity,
            "文件（仓库根相对 POSIX 路径）": finding.file_path,
            "行号范围": [finding.line_start, finding.line_end],
            "下沉符号": finding.symbol,
            "污点来源类别": finding.source_kind,
            "下沉点类别": finding.sink_kind,
            "源码片段（含上下文）": finding.source_snippet,
        }
    )
    instruction = (
        "请只输出一个 unified diff（不要解释、不要 markdown 代码围栏），"
        "修改范围必须严格落在上述行号 ±20 行以内。"
        "补丁的目标是消除该污点路径，例如改用参数化查询、白名单校验或安全的 API 替代。"
        "如果不确定能给出正确的 diff，请只回复：NO_PATCH"
    )
    return [
        ChatMessage(role="system", content=_BASE_SYSTEM),
        ChatMessage(role="user", content=_facts(payload) + instruction),
    ]


# ---------------------------------------------------------------------------
# ③ 攻击链中文叙事
# ---------------------------------------------------------------------------


def build_chain_messages(chain: ChainView) -> list[ChatMessage]:
    """用点 ③：攻击链叙事。

    校验基准是「叙事中提到的漏洞编码 ⊆ 该链的实际节点集合」（PRD §7.6.3），
    所以这里把节点集合原样给出 —— 模型能引用的编号，就是输入里那些。
    """
    nodes = [
        {
            "序号": n.order_index + 1,
            "标签": n.label,
            "节点类型": n.node_type,
            "验证状态（已判定）": n.verification_status,
            "命中的推演规则": n.rule_id,
            "说明": n.detail,
            "关联漏洞编码": n.vuln_code,
        }
        for n in chain.nodes
    ]
    payload = _strip_none(
        {
            "链名称": chain.name,
            "入口点": chain.entry_point,
            "攻陷目标": chain.target_asset,
            "严重度（已判定）": chain.severity,
            "涉及漏洞编码（完整集合）": list(chain.vuln_codes),
            "节点与边（按 order_index 排序，parent 关系即边）": nodes,
        }
    )
    instruction = (
        "请写一段 150–300 字的中文攻击链叙事，按环的顺序说明攻击者依次做了什么、"
        "每一环获得了什么权限或信息、如何构成到下一环的前置条件。"
        "对验证状态为 verified 的环，用「已在沙箱中无害验证」表述；"
        "对 inferred 的环，必须明确说明「由已证实的前置条件推演得出，未实际执行」。"
        "只能引用上面列出的漏洞编码，不得引入新的编码或新的攻击步骤。"
    )
    return [
        ChatMessage(role="system", content=_BASE_SYSTEM),
        ChatMessage(role="user", content=_facts(payload) + instruction),
    ]


# ---------------------------------------------------------------------------
# ④ 整改建议文案
# ---------------------------------------------------------------------------


def build_remediation_messages(finding: FindingView, *, rank: int, total: int) -> list[ChatMessage]:
    """用点 ④：整改建议文案。

    ⚠️ **`rank` 是输入，不是输出。** 整改顺序由 `report/scoring.py` 的确定性公式
    （等级 × 可达性 × 修复成本）产出，这里只是把「这是第几项」告诉模型，
    让文案能说「优先修复」而不是让模型去排出「谁最该先修」——
    顺序一旦由模型决定，同一份数据两次生成就会得到两份不同的报告。
    """
    payload = _strip_none(
        {
            "整改项序号": f"{rank}/{total}",
            "漏洞编号": finding.code,
            "漏洞类型": finding.vuln_type,
            "严重度（已判定）": finding.severity,
            "验证状态（已判定）": finding.status,
            "CVSS": finding.cvss_score,
            "位置": f"{finding.file_path}:{finding.line_start}-{finding.line_end}",
            "已有处置说明": finding.rationale,
        }
    )
    instruction = (
        "请写一段 100–200 字的中文整改建议，包含两小节："
        "①「修复动作」——针对该类型漏洞给出可执行的具体做法；"
        "②「复核要点」——说明改完之后如何确认问题真的消失。"
        "不要重复排序、不要讨论该漏洞是否应该排在这个位置、不要新增文件路径或行号。"
    )
    return [
        ChatMessage(role="system", content=_BASE_SYSTEM),
        ChatMessage(role="user", content=_facts(payload) + instruction),
    ]


__all__ = [
    "build_chain_messages",
    "build_description_messages",
    "build_patch_messages",
    "build_remediation_messages",
]
