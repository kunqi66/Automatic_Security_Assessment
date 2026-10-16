"""L3「输出必校验」：实体白名单。

PRD §7.6.2 的 L2 说「LLM 输出中不得出现输入里没有的文件路径、行号、CVE 编号、
函数名、漏洞编码」。**这句话单独写在 prompt 里是没有约束力的** ——
模型在温度 0.2 下依然会写出「类似的 `app/api/login.py`」这种看起来很合理的路径，
而那种幻觉在安全报告里是最贵的错误：读者无法分辨哪条位置是真的。

所以这里是**硬闸**：从模型输出里把「可被追问的实体」全部抽出来，逐个核对
是否在输入里存在。**任何一条对不上，整段拒收，走确定性模板**（不是删掉那一句 ——
删掉会让文案读起来仍然通顺，从而让幻觉的痕迹消失）。

## 为什么拒收而不是「改写」

拒收的代价已知且可控（措辞变差）；改写的代价是「我们发明了一段既不是模型说的、
也不是模板说的文本」，它无法解释、无法复现。按 L4，降级是允许的，
**发明**是不允许的。

## 已实现与未实现的检查

| 实体 | 状态 | 说明 |
|---|---|---|
| 文件路径（带扩展名） | ✅ | 必须精确命中输入里的 `file_path` 集合 |
| `路径:行号` | ✅ | 路径命中 + 行号落在该漏洞的 ±20 行窗口内 |
| 「第 N 行」/「行 N」 | ✅ | 行号必须落在允许行号集合内 |
| CVE 编号 | ✅ | 必须命中输入的 CVE 集合 |
| 漏洞编码（`VULN-xxxx-xxxx`） | ✅ | 单条漏洞用输入编码；攻击链用链的节点集合 |
| 函数/符号名 | ⚠️ **未实现** | 见下 |

**函数名为什么不查**：判断「`run_query` 是不是输入里存在的符号」需要先把自然语言
里的标识符切出来，而中文技术文本里 `` `order_id` ``、`cursor.execute`、
「订单查询接口」混在一起，规则法切出来的候选一半是噪声。噪声的代价是**误拒** ——
而误拒会把本来合格的模型输出也推回模板，等于把用点①③④一起废掉。
更合适的做法是静态分析层（B4）输出一份候选符号表再比对，那是 B4 的接口变更，
不在本模块的边界内。**这是一个已知的、有意的空缺，不是遗漏。**
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: 常见可分析源码扩展名。刻意限定在「会出现在漏洞位置里」的那批 ——
#: 放宽成 `\w+\.\w+` 会把 `foo.bar` 这种点号表达式也当成路径，噪声大到不可用。
_PATH_RE = re.compile(
    r"[A-Za-z0-9_][A-Za-z0-9_\-./]*\."
    r"(?:py|pyi|js|jsx|mjs|cjs|ts|tsx|vue|java|kt|go|rb|php|c|h|cc|cpp|hpp|cs|rs|swift|"
    r"sql|sh|bash|ps1|yml|yaml|json|toml|ini|cfg|conf|xml|html|j2|env)\b"
)
#: 带行号的引用，如 `app/api/order.py:42`
_PATH_LINE_RE = re.compile(rf"({_PATH_RE.pattern}):(\d{{1,6}})")
#: 中文里最常见的两种裸行号写法
_BARE_LINE_RE = re.compile(r"第\s*(\d{1,6})\s*行|[（(]?\b行\s*(\d{1,6})\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_VULN_CODE_RE = re.compile(r"\bVULN-\d{4}-\d{4,6}\b", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class EntityWhitelist:
    """一次校验的允许集合。**由调用方从输入事实里现算，不从模型输出里猜。**"""

    #: 允许出现的文件路径（精确匹配）
    paths: frozenset[str] = frozenset()
    #: 允许出现的行号
    lines: frozenset[int] = frozenset()
    #: 允许出现的 CVE
    cves: frozenset[str] = frozenset()
    #: 允许出现的漏洞编码（如 VULN-2026-0001）
    codes: frozenset[str] = frozenset()

    @classmethod
    def for_finding(
        cls,
        *,
        file_path: str,
        line_start: int,
        line_end: int,
        taint_lines: frozenset[int] = frozenset(),
        code: str | None = None,
        cwe_id: str | None = None,
        window: int = 20,
    ) -> EntityWhitelist:
        """单条漏洞的允许集合。

        行号窗口取 ±20，**与补丁第 2 道校验同一个窗口**（PRD §7.6.2）——
        两个窗口用同一个数是有意的：模型被允许「顺手提到」的范围，
        恰好就是它被允许「顺手改动」的范围，不存在「能说但不能改」的夹缝。
        """
        lo = max(1, min(line_start, line_end) - window)
        hi = max(line_start, line_end) + window
        lines = set(range(lo, hi + 1)) | set(taint_lines)
        codes = {code} if code else set()
        cves = {cwe_id.upper()} if cwe_id and cwe_id.upper().startswith("CVE-") else set()
        return cls(
            paths=frozenset({file_path}),
            lines=frozenset(lines),
            cves=frozenset(cves),
            codes=frozenset(codes),
        )

    @classmethod
    def for_chain(cls, *, paths: frozenset[str], codes: frozenset[str]) -> EntityWhitelist:
        """攻击链的允许集合：编码集合 = 链的实际节点集合（PRD §7.6.3 用点③）。"""
        return cls(paths=paths, lines=frozenset(), cves=frozenset(), codes=codes)


@dataclass(frozen=True, slots=True)
class GuardVerdict:
    ok: bool
    #: 第一处越界实体，直接进日志与 `TextResult.reason` 的 detail
    offending: str | None = None
    kind: str | None = None


def check_entities(text: str, whitelist: EntityWhitelist) -> GuardVerdict:
    """核对 `text` 里出现的实体是否都在白名单内。

    返回**第一处**越界即停：拒收是整段拒收，后面的还查不查对结果没有影响，
    而逐条收集只会让日志更长。
    """
    # 顺序即优先级：先查「最容易被编造、也最贵」的路径
    for match in _PATH_LINE_RE.finditer(text):
        path, line = match.group(1), int(match.group(2))
        if path not in whitelist.paths:
            return GuardVerdict(False, path, "path")
        if whitelist.lines and line not in whitelist.lines:
            return GuardVerdict(False, f"{path}:{line}", "line")

    for match in _PATH_RE.finditer(text):
        path = match.group(0)
        # `_PATH_LINE_RE` 已覆盖过的部分不重复报，避免同一个错误报两遍
        if path not in whitelist.paths:
            return GuardVerdict(False, path, "path")

    for match in _BARE_LINE_RE.finditer(text):
        raw = match.group(1) or match.group(2)
        if raw is None:
            continue
        if whitelist.lines and int(raw) not in whitelist.lines:
            return GuardVerdict(False, f"第 {raw} 行", "line")

    for match in _CVE_RE.finditer(text):
        if match.group(0).upper() not in whitelist.cves:
            return GuardVerdict(False, match.group(0), "cve")

    codes = {c.upper() for c in whitelist.codes}
    for match in _VULN_CODE_RE.finditer(text):
        if match.group(0).upper() not in codes:
            return GuardVerdict(False, match.group(0), "code")

    return GuardVerdict(True)


__all__ = ["EntityWhitelist", "GuardVerdict", "check_entities"]
