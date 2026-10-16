"""CVSS 3.1 基础分计算（设计文档 §2 / §4.5 的 cvss）。

**这是全模块唯一可以「精确验证」的部分**：公式与系数都在 CVSS 3.1 官方规范里，
所以这一段的测试不是「我认为对」，而是「拿官方规范里的已知向量跑出官方分值」。
其余部分（污点传播）只能验证「在给定样例上符合预期」，两者的证据强度不同 ——
报告里不该把这两类测试混为一谈。

**B4 只给静态基线分**。`poc_verify` 通过后的上调（如 7.5 → 9.8）属 B5 职责
（PRD §7.1 ⑧ 末句）。这里的实现是纯函数：同一个向量必然同一个分数。
"""

from __future__ import annotations

import math

from app.analysis.types import VulnType
from app.models.enums import Severity

# ---------------------------------------------------------------------------
# CVSS 3.1 官方系数表（规范 §7.4 Base Metrics）
# ---------------------------------------------------------------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

#: 向量串的版本前缀。表里的 `VECTORS` 只存**指标段**（`AV:N/AC:L/...`），
#: 前缀在 `score_for` 出口处统一加上 —— 让内部计算与本文件里
#: 一眼可比对的表格形式保持一致，只在最终交付给报告的那一份上加前缀。
VECTOR_PREFIX = "CVSS:3.1/"

#: 每条规则的向量模板（设计文档 §4.5 的表）。
#:
#: `%PR%` 是唯一会被替换的占位符：需要认证与否由漏洞类型决定，
#: 其余量值在同一类型里是固定的。
VECTORS: dict[VulnType, str] = {
    # RCE 类：拿到代码执行等于全丢
    VulnType.COMMAND_INJECTION: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    VulnType.DESERIALIZATION: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    # SQL 注入：可读可写，但不直接等于命令执行，完整性影响按 H 记
    VulnType.SQL_INJECTION: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    # 文件上传落到 WebShell 需要先能进后台，故 PR:L
    VulnType.FILE_UPLOAD: "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    # 只读型：能读敏感数据，不能改
    VulnType.PATH_TRAVERSAL: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    VulnType.INFO_DISCLOSURE: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    # 越权访问：需要先有账号（PR:L）
    VulnType.IDOR: "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    # 未授权访问：**连账号都不需要**（PR:N），所以比 IDOR 高。
    # 影响仍按只读记 —— 本类别只覆盖"整表被读走"，写侧不在此列
    # （见 `patterns.detect_unauth_access` 的判据 5）。
    VulnType.UNAUTH_ACCESS: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    # XSS：需要受害者交互（UI:R），且作用域变更为 C（影响受害者浏览器而非服务端）
    VulnType.XSS: "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    # 硬编码密钥：需要先拿到源码（AV:L / PR:L）
    VulnType.HARDCODED_SECRET: "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
}

#: 严重度分档（CVSS 3.1 定性等级，设计文档 §4.5 末段）
_SEVERITY_BANDS: tuple[tuple[float, Severity], ...] = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
)


def roundup(value: float) -> float:
    """CVSS 3.1 的 **Roundup**：向上取到一位小数。

    官方规范为了避开「浮点误差导致 8.8 变成 8.7」特意定义了它，
    并给出整型实现（先放大成整数再判断余数）。直接用 `math.ceil(x * 10) / 10`
    在 `x = 8.6` 这种「十进制看起来正好」的值上会因为二进制表示
    （8.6 实际是 8.5999999999999996）多进一位。所以按官方定义实现。
    """
    scaled = int(round(value * 100_000))
    if scaled % 10_000 == 0:
        return scaled / 100_000
    return (math.floor(scaled / 10_000) + 1) / 10


def parse_vector(vector: str) -> dict[str, str]:
    """`"AV:N/AC:L/..."` → `{"AV": "N", "AC": "L", ...}`。

    解析失败直接抛 `ValueError`：向量串是**我们自己生成的常量**，
    不是外部输入 —— 它一旦解析不了，说明代码里那张表被改错了，
    这种情况必须响亮地失败，而不是默默回一个 0 分。
    """
    metrics: dict[str, str] = {}
    for chunk in vector.split("/"):
        if not chunk:
            continue
        key, _, value = chunk.partition(":")
        if not key or not value:
            raise ValueError(f"CVSS 向量段非法：{chunk!r}（完整向量 {vector!r}）")
        if key.strip().upper() == "CVSS":
            # 版本前缀（`CVSS:3.1/AV:N/...`）不是指标段，直接跳过。
            # 容忍它是为了能**照抄 NVD 页面上的向量**做校验 ——
            # 官方公布的都是带前缀的完整形式，要求调用方先手工裁掉前缀，
            # 等于把「校验公式」这件事变成一次易错的字符串编辑。
            continue
        metrics[key.strip()] = value.strip()
    missing = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"} - metrics.keys()
    if missing:
        raise ValueError(f"CVSS 向量缺少必需指标：{sorted(missing)}（完整向量 {vector!r}）")
    return metrics


def base_score(vector: str) -> float:
    """CVSS 3.1 基础分（规范 §7.1 的完整公式）。纯函数。"""
    m = parse_vector(vector)
    av = _AV[m["AV"]]
    ac = _AC[m["AC"]]
    scope_changed = m["S"] == "C"
    pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]
    ui = _UI[m["UI"]]
    confidentiality = _CIA[m["C"]]
    integrity = _CIA[m["I"]]
    availability = _CIA[m["A"]]

    # Impact Sub-Score：三个 CIA 维度里**至少一个完全无损**才可能为 0
    iss = 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        # 无影响就是 0 分（规范明确：Impact 为 0 时不计算 Exploitability）
        return 0.0
    if scope_changed:
        return roundup(min(1.08 * (impact + exploitability), 10.0))
    return roundup(min(impact + exploitability, 10.0))


def vector_for(
    vuln_type: VulnType,
    *,
    requires_auth: bool = False,
    remote: bool = True,
) -> str:
    """按「漏洞类型 × 是否需要认证 × 是否可远程触发」取向量（设计文档 §4.5）。

    两个修正参数只重写**对应的那个指标**，不去动 CIA ——
    影响面由漏洞类型决定，可达性由部署形态决定，这两件事正交。
    这样 `vector_for(t)` 与 `vector_for(t, requires_auth=True)` 的差异
    永远只体现在 `PR` 一个字母上，排查评分差异时一眼能看出来。
    """
    vector = VECTORS[vuln_type]
    if requires_auth:
        vector = _replace_metric(vector, "PR", "L")
    if not remote:
        vector = _replace_metric(vector, "AV", "L")
    return vector


def _replace_metric(vector: str, key: str, value: str) -> str:
    parts = []
    replaced = False
    for chunk in vector.split("/"):
        if chunk.startswith(f"{key}:"):
            parts.append(f"{key}:{value}")
            replaced = True
        else:
            parts.append(chunk)
    if not replaced:  # pragma: no cover - 表里必然含全部指标
        parts.append(f"{key}:{value}")
    return "/".join(parts)


def severity_of(score: float) -> Severity:
    """基础分 → 严重度。B4 产出的 `severity` 是**漏洞严重度**，
    与 `assessments.security_grade`（项目综合等级）是两套四级术语，不可混用。"""
    for threshold, severity in _SEVERITY_BANDS:
        if score >= threshold:
            return severity
    return Severity.LOW


def score_for(
    vuln_type: VulnType,
    *,
    requires_auth: bool = False,
    remote: bool = True,
) -> tuple[str, float, Severity]:
    """一次算出 `(向量, 基础分, 严重度)`。

    返回的向量带 `CVSS:3.1/` 前缀（NVD 公布的标准形式）—— 报告与前端要把它
    原样展示给人看、给工具解析，缺了版本前缀的裸指标串在外部工具里
    会被判成非法向量。内部的 `base_score` 两种形式都收（见 `parse_vector`）。

    **不缓存**：预算量级是微秒，而缓存会引入「同一输入两次调用结果是否一致」
    之外的第三种状态（缓存命中/未命中），确定性契约不想背上这个包袱。
    """
    vector = vector_for(vuln_type, requires_auth=requires_auth, remote=remote)
    score = base_score(vector)
    return VECTOR_PREFIX + vector, score, severity_of(score)
