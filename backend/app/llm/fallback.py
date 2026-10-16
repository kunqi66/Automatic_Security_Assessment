"""确定性降级模板 —— 「拿掉 LLM，结论一字不变」这句话的实际载体。

**这不是兜底垃圾代码。** 四个使用点的降级产物是**系统在无 LLM 环境下的正式输出**
（面试现场、离线演示、CI 里都会用到），所以这里要求：

1. **信息量不缩水**：模板必须把输入里的事实（位置、行号、CVSS、污点每一跳、
   验证状态、链的每一环）如实讲出来。模板说不出的只有「结合路径的自然语言润色」，
   那正是 LLM 的那部分价值（PRD §7.6.4 的问答二）。
2. **不出现占位符**：没有 `TODO`、没有 `{未知类型}` 这种糊弄。类型表里没有的
   `vuln_type` 会退化成 `「<原名>」类缺陷` —— 难看，但**不撒谎**。
3. **措辞专业**：这是一份交付给开发团队的安全报告，不是调试输出。
4. **每个函数单独可测**：判据是「拿掉 LLM 后系统的结论一字不变」，
   所以这些函数必须能被直接调用、直接断言，而不必绕道 HTTP 假客户端。

**所有函数的共同前提**：入参里没有一个字段是「待判断」的。`severity`、`status`、
`guard_blocked`、`verification_status` 都是上游确定性代码的结论，模板只做陈述。

## ⚠️ 产出的文本是**纯文本**，不含任何 Markdown 语法

一份文案同时喂给 HTML 与 Markdown 两个模板（`ReportData` 只有一份），
所以它不能带任何**只有一种格式认识**的标记：`**粗体**` 在 HTML 里会原样显示成
星号，反引号同理 —— 而这类残留**不会报错**，只会在页面上多出几个刺眼的标点。

强调靠中文标点解决（「」、《》、破折号），代码片段由模板自己用 `<code>` /
反引号围栏包起来。LLM 的产出同理不受信任地被当成纯文本 ——
把模型返回的 Markdown 解释成 HTML 等于凭空开一个注入面。
"""

from __future__ import annotations

from app.llm.types import ChainView, FindingView

# ---------------------------------------------------------------------------
# 术语映射
# ---------------------------------------------------------------------------

#: 单漏洞严重度 → 中文。⚠️ 与项目综合等级（极高危/高危/中危/安全）**不是一套**，
#: 见 `models/enums.py` 的 `Severity` / `SecurityGrade` 注释与 B6 设计 §4.3。
SEVERITY_LABEL: dict[str, str] = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
}

#: 漏洞四态 → 中文口径。`skipped` 在这里刻意没有对应值：它是**阶段**状态，
#: 一旦被塞进漏洞状态，报告里就会出现「未验证 = 无风险」这种最常见的误读。
STATUS_LABEL: dict[str, str] = {
    "verified": "已通过动态验证",
    "potential": "存在利用线索但未完全坐实",
    "unverified": "未经动态验证（仅静态分析结论）",
    "rejected": "已复核排除",
}

VULN_TYPE_LABEL: dict[str, str] = {
    "sql_injection": "SQL 注入",
    "command_injection": "命令注入",
    "code_injection": "代码注入",
    "path_traversal": "路径穿越",
    "xss": "跨站脚本（XSS）",
    "cross_site_scripting": "跨站脚本（XSS）",
    "ssrf": "服务端请求伪造（SSRF）",
    "xxe": "XML 外部实体注入（XXE）",
    "ldap_injection": "LDAP 注入",
    "template_injection": "模板注入（SSTI）",
    "ssti": "模板注入（SSTI）",
    "open_redirect": "开放重定向",
    "csrf": "跨站请求伪造（CSRF）",
    "idor": "越权访问（IDOR）",
    "unauth_access": "未授权访问",
    "broken_access_control": "访问控制缺陷",
    "hardcoded_secret": "硬编码凭据",
    "weak_crypto": "弱加密算法",
    "insecure_hash": "不安全的哈希算法",
    "insecure_deserialization": "不安全反序列化",
    "deserialization": "不安全反序列化",
    "unsafe_file_upload": "不安全文件上传",
    "log_injection": "日志注入",
    "format_string": "格式化字符串",
    "race_condition": "竞态条件",
    "insecure_random": "不安全的随机数",
}

#: 每类漏洞的修复方向与复核要点。**只讲已被广泛接受的工程做法**，
#: 不发明「本系统特有」的解法 —— 降级文案会被真正拿去排期修代码。
_FIX_GUIDE: dict[str, tuple[str, str]] = {
    "sql_injection": (
        "把拼接 SQL 的写法改为参数化查询（预编译语句），让输入永远只作为数据、"
        "不参与语句结构解析；同时对参数做类型转换与取值白名单校验",
        "构造原本可触发的载荷重放，确认返回不再泄漏数据；再重跑静态污点分析，"
        "确认该条 source→sink 路径不再上报。ORM 的 raw() / extra() 一类逃生口要一并排查",
    ),
    "command_injection": (
        "改用不经过 shell 的执行方式（如参数数组形式的 subprocess，shell=False），"
        "并对命令参数做严格白名单；禁止把用户输入拼接进命令行",
        "重放原载荷确认不再产生命令执行结果；检查同一执行点是否还有其它调用方传入可控参数",
    ),
    "code_injection": (
        "移除对用户输入的 eval / exec / 动态导入；若业务确需表达式求值，"
        "改用受限的解释器或明确的白名单映射",
        "重放原载荷确认不再执行；全局检索同类动态执行调用点",
    ),
    "path_traversal": (
        "把用户输入解析为绝对路径后，用 realpath 校验其仍位于允许的根目录内，"
        "并对符号链接做二次检查；不要只做字符串替换 ../",
        "用 ../、绝对路径、Windows 风格分隔符、符号链接四种载荷分别复测；"
        "确认拒绝时返回的是 4xx 而不是意外泄漏了文件内容",
    ),
    "xss": (
        "输出侧按上下文做转义（HTML 文本、属性、JS、URL 各自不同），"
        "并配置 CSP；输入侧不要试图靠黑名单过滤标签",
        '用 "><script>、onerror=、javascript: 三类载荷复测；'
        "确认 CSP 头生效且没有 unsafe-inline 的例外",
    ),
    "ssrf": (
        "对目标地址做协议与主机白名单校验，解析后再次校验 IP 归属，"
        "禁止访问回环、内网网段与云元数据地址（169.254.169.254）",
        "用十进制/八进制 IP、DNS 重绑定、302 跳转三种绕过手法复测；"
        "确认请求发起前的校验与真正连接使用的是同一份解析结果",
    ),
    "hardcoded_secret": (
        "把凭据移出源码，改由环境变量或密钥管理服务注入，并在部署配置中声明；"
        "无论代码是否已公开，都应当轮换该凭据 —— 已经进入版本历史的密钥无法收回",
        "确认新凭据不再出现在源码、构建产物与日志中；检索版本历史，"
        "确认旧值已被轮换而不是仅从最新提交里删除",
    ),
    "unauth_access": (
        "给该端点补上鉴权（装饰器 / 依赖注入 / 中间件任选其一），"
        "并且**在服务端校验**，不要依赖前端不显示入口；"
        "整表返回的接口还应同时加分页与字段白名单，避免一次请求拖走全量账号数据",
        "用**不带任何凭证**的请求复测该端点，确认返回 401/403；"
        "再确认带**低权限**凭证时不会因为「只在路径上做了限制」而绕过",
    ),
    "insecure_deserialization": (
        "改用不执行任意对象构造的数据格式（如 JSON），或使用带类型白名单的安全反序列化接口",
        "重放原载荷确认不再触发对象构造；确认反序列化入口不接受不可信的原始字节",
    ),
    "insecure_hash": (
        "口令存储改用带盐的自适应算法（bcrypt / scrypt / Argon2）；"
        "完整性校验改用 SHA-256 及以上，不要用 MD5 / SHA-1",
        "确认库中存量口令的迁移方案（下次登录时重算，或强制重置），而不是只改新代码",
    ),
    "weak_crypto": (
        "改用当前推荐的算法与足够长度的密钥（对称建议 AES-GCM，"
        "非对称建议 RSA-2048 以上或 Ed25519），并确保 IV/nonce 唯一",
        "确认没有为兼容而保留旧算法的降级分支 —— 那等于没改",
    ),
    "xxe": (
        "在 XML 解析器中显式关闭外部实体与 DTD 处理，并限制实体展开深度",
        "用外部实体读取本地文件与发起外连两种载荷复测；确认解析器配置在所有"
        "解析入口都生效，而不只是被报的那一处",
    ),
    "unsafe_file_upload": (
        "按内容而非扩展名判定类型，把上传文件重命名后存放在 Web 根之外，并限制可执行权限",
        "上传伪装扩展名的可执行文件复测；确认即使被上传也无法通过 URL 直接访问或执行",
    ),
    "unverified": (
        "按静态分析给出的证据修复该处数据处理逻辑，并在修复后补充动态验证",
        "先补一次动态验证确认问题真实存在，再验证修复有效 —— "
        "未验证的结论不应被当作已确认的事实排期，也不应被直接忽略",
    ),
}

_GENERIC_FIX = (
    "按该类型缺陷的通行做法修复：在数据进入危险操作之前完成校验或编码，"
    "优先采用语言与框架提供的安全 API，而不是自建过滤逻辑",
    "重放原始触发载荷确认不再复现，并重跑静态污点分析确认该条路径消失；"
    "同时排查同一模式在代码库中的其它出现位置",
)


def vuln_type_label(vuln_type: str) -> str:
    """类型中文名。未登记的类型**如实回显原名**，不编一个听起来合理的名字。"""
    key = (vuln_type or "").strip().lower()
    return VULN_TYPE_LABEL.get(key, f"{vuln_type or '未分类'} 类缺陷")


def severity_label(severity: str) -> str:
    return SEVERITY_LABEL.get((severity or "").strip().lower(), "未定级")


def status_label(status: str | None) -> str:
    if not status:
        return "状态未知"
    return STATUS_LABEL.get(status.strip().lower(), f"状态 {status}")


def _loc(file_path: str, line: int | None = None, span: tuple[int, int] | None = None) -> str:
    """统一的位置写法：`路径:行` 或 `路径:起-止`。

    ⚠️ **不加 Markdown 反引号**，见模块文档「纯文本」一节。
    """
    if span is not None:
        return f"{file_path}:{span[0]}-{span[1]}"
    return f"{file_path}:{line}"


def _taint_lines(finding: FindingView) -> list[str]:
    """把污点路径逐跳渲染成带序号的清单 —— 这是模板里信息密度最高的一段。"""
    icon = {"source": "source", "propagate": "propagate", "sanitize": "sanitize", "sink": "sink"}
    rows: list[str] = []
    for step in finding.taint_path:
        mark = icon.get(step.step_kind, step.step_kind)
        symbol = f" {step.symbol}" if step.symbol else ""
        rows.append(f"  {step.step_index + 1}. [{mark}]{symbol} {step.file_path}:{step.line}")
        if step.snippet:
            rows.append(f"     {step.snippet.strip().splitlines()[0][:120]}")
    return rows


# ---------------------------------------------------------------------------
# ① 漏洞描述
# ---------------------------------------------------------------------------


def describe_finding(finding: FindingView) -> str:
    """用点 ① 的降级产物：一段完整、可交付的中文漏洞描述。"""
    head = (
        f"【{vuln_type_label(finding.vuln_type)}】"
        f"漏洞严重度 {severity_label(finding.severity)}"
        f"（CVSS {finding.cvss_score:.1f}）"
    )
    if finding.code:
        head += f"，编号 {finding.code}"
    if finding.cwe_id:
        head += f"，{finding.cwe_id}"
    head += "。"

    loc = f"触发位置：{_loc(finding.file_path, span=(finding.line_start, finding.line_end))}"
    if finding.symbol:
        loc += f"，下沉符号 {finding.symbol}"
    loc += "。"

    blocks = [head, "", loc]

    if finding.taint_path:
        src = finding.taint_path[0]
        propagations = sum(1 for s in finding.taint_path if s.step_kind == "propagate")
        blocks += [
            "",
            f"污点数据自 {_loc(src.file_path, src.line)} 进入"
            f"（来源类别：{finding.source_kind or '外部输入'}），"
            f"经 {propagations} 跳传播后在下沉点汇聚"
            f"（{finding.sink_kind or '危险操作'}）：",
            *_taint_lines(finding),
        ]
    else:
        blocks += [
            "",
            "本条仅由模式匹配命中，未记录到完整的污点路径 —— 报告中不给出未经证实的数据流描述。",
        ]

    blocks += ["", f"危害判定：{_harm(finding)}"]
    blocks += ["", _markers(finding)]
    return "\n".join(blocks).strip()


def _harm(finding: FindingView) -> str:
    """危害说明。**按类型给具体后果，不给「可能导致安全问题」这种废话。**"""
    key = (finding.vuln_type or "").strip().lower()
    harm = {
        "sql_injection": "攻击者可构造参数改变 SQL 语句结构，绕过业务查询条件读写任意数据；"
        "若数据库账号权限过高，还可能借助数据库内置能力读写文件或进一步横向移动。",
        "command_injection": "攻击者可在目标主机上以服务进程的身份执行任意系统命令，"
        "进而读取源码与配置中的凭据、写入持久化后门。",
        "path_traversal": "攻击者可读取（或在可写场景下覆盖）授权目录之外的任意文件，"
        "典型目标是配置文件、密钥文件与源码。",
        "xss": "攻击者的脚本将在受害者浏览器中、以当前站点身份执行，"
        "可窃取会话凭证或代替用户发起操作。",
        "ssrf": "攻击者可使服务器以其内网身份发起请求，用于探测内网拓扑、读取云环境元数据凭据。",
        "hardcoded_secret": "源码中的凭据一旦随仓库、构建产物或镜像外泄即等同于凭据泄露；"
        "由于历史提交无法收回，影响范围通常超出当前版本。",
        "unauth_access": "任何能访问到该端点的人都可取得本应受保护的账号数据，"
        "无需注册、无需登录，也不留下与真实用户关联的操作痕迹。",
        "insecure_deserialization": "不可信数据在反序列化过程中可能触发任意对象构造，"
        "通常直接导致远程代码执行。",
        "unverified": "该处数据处理未经过有效性校验，具体可利用性尚未通过动态验证确认。",
    }.get(key)
    if harm:
        return harm
    return (
        f"{vuln_type_label(finding.vuln_type)}位于业务处理链路的关键位置，"
        "其未受校验的输入可被用于绕过预期的安全约束。"
    )


def _markers(finding: FindingView) -> str:
    """把**不利结论**如实标出来。

    这一行的存在是有意的：模板若只报「这里有个漏洞」，读者就无从判断它的可信度。
    `guard_blocked` 说的是「路径上有生效的净化，风险已降低」，`status` 说的是
    「这条结论被验证到什么程度」—— 两者的方向相反，都不能省。
    """
    parts: list[str] = []
    if finding.guard_blocked:
        parts.append(
            "路径上存在生效的净化函数：该处输入在到达危险操作前已做处理，"
            "本条按「存在风险但利用条件受限」呈现。"
        )
    else:
        parts.append("路径上未发现有效的净化处理。")
    parts.append(f"验证状态：{status_label(finding.status)}。")
    if finding.confidence:
        parts.append(f"分析置信度 {finding.confidence:.2f}（由确定性规则给出，非概率估计）。")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# ② 补丁降级：无补丁 + 通用修复建议
# ---------------------------------------------------------------------------


def patch_advice(finding: FindingView) -> str:
    """用点 ② 的降级产物。

    契约 3 规定降级是「无补丁（`patch=null`）」，但只回一个 null 什么都没交付，
    所以同时给出**通用修复方向**（PRD §7.6.3 写的就是「通用修复建议」）。

    ⚠️ 这里**不生成 diff**。模板凭一张 `file_path` + 行号拼出来的 diff，
    在语法上可能成立、在语义上几乎一定是错的 —— 而一个「看起来能 apply」的
    错误补丁比没有补丁更危险：它会消耗掉复核者的信任。
    """
    key = (finding.vuln_type or "").strip().lower()
    fix, check = _FIX_GUIDE.get(key, _GENERIC_FIX)
    if not finding.status or finding.status == "unverified":
        fix, check = _FIX_GUIDE["unverified"]

    return "\n".join(
        [
            f"修复方向（{vuln_type_label(finding.vuln_type)} · "
            f"漏洞严重度 {severity_label(finding.severity)}）：",
            f"  位置：{_loc(finding.file_path, span=(finding.line_start, finding.line_end))}",
            f"  做法：{fix}。",
            f"  复核要点：{check}。",
            "",
            "说明：本次未生成可直接应用的补丁（补丁必须由模型产出并经四道校验，"
            "不接受模板拼接的 diff）。以上为人工修复的参考方向，"
            "补丁的有效性最终以「打上之后污点引擎不再上报同一条路径」为准。",
        ]
    )


# ---------------------------------------------------------------------------
# ③ 攻击链叙事
# ---------------------------------------------------------------------------


def narrate_chain(chain: ChainView) -> str:
    """用点 ③ 的降级产物：一串按环展开的中文叙事。"""
    if not chain.nodes:
        return (
            f"攻击链「{chain.name}」未记录到可用节点，无法给出叙事。"
            "该链的结构本身即为空，报告中不对其做任何推断。"
        )

    entry = chain.entry_point or chain.nodes[0].label
    target = chain.target_asset or chain.nodes[-1].label

    lines = [
        f"本攻击链自入口「{entry}」开始，依次经 {len(chain.nodes)} 环，目标是「{target}」。",
        "",
    ]
    for node in chain.nodes:
        mark = "[已验证]" if node.verification_status == "verified" else "[已推演]"
        lines.append(f"第 {node.order_index + 1} 环 {mark} {node.label}（{node.node_type}）")
        if node.detail:
            lines.append(f"    {node.detail}")
        if node.vuln_code:
            lines.append(f"    关联漏洞：{node.vuln_code}")
        if node.rule_id:
            lines.append(f"    推演规则：{node.rule_id}")
        lines.append("")

    verified = chain.verified_count
    inferred = chain.inferred_count
    if inferred:
        lines.append(
            f"说明：前 {verified} 环已在沙箱中无害验证，后 {inferred} 环由已证实的前置条件"
            "推演得出，未实际执行 —— 本系统可以推断「这里能打穿」，但不代为打穿。"
        )
    else:
        lines.append("说明：本链各环均已在沙箱中无害验证。")
    return "\n".join(lines).strip()


# ---------------------------------------------------------------------------
# ④ 整改建议文案
# ---------------------------------------------------------------------------


def suggest_remediation(finding: FindingView, *, rank: int = 1, total: int = 1) -> str:
    """用点 ④ 的降级产物。

    **排序序号 `rank` 是输入**（由 `report/scoring.py` 的确定性公式产出），
    模板只把它读出来写进文案，不参与任何比较与排序（PRD §7.6.3 用点④）。
    """
    key = (finding.vuln_type or "").strip().lower()
    fix, check = _FIX_GUIDE.get(key, _GENERIC_FIX)

    urgency = (
        "该结论已通过动态验证，可被实际利用，建议优先安排修复。"
        if finding.status == "verified"
        else "该结论尚未通过动态验证，建议先补一次验证再排期，以免把静态误报计入工时。"
    )
    if finding.status == "rejected":
        urgency = "该条已人工复核排除，列入清单仅为留痕，无需修复。"

    head = (
        f"整改项 {rank}/{total}：{vuln_type_label(finding.vuln_type)}"
        f"（漏洞严重度 {severity_label(finding.severity)}，CVSS {finding.cvss_score:.1f}）"
    )
    if finding.code:
        head += f"，{finding.code}"
    head += f"，位置 {_loc(finding.file_path, span=(finding.line_start, finding.line_end))}。"

    return "\n".join(
        [
            head,
            f"【修复动作】{fix}。",
            f"【复核要点】{check}。",
            f"【处置优先级说明】{urgency}",
        ]
    )


__all__ = [
    "SEVERITY_LABEL",
    "STATUS_LABEL",
    "VULN_TYPE_LABEL",
    "describe_finding",
    "narrate_chain",
    "patch_advice",
    "severity_label",
    "status_label",
    "suggest_remediation",
    "vuln_type_label",
]
