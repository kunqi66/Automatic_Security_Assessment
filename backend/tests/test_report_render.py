"""报告渲染测试：**注入防护**与**如实标注**（B6 设计 §4.2 / §4.5）。

## 为什么这两件事要各写一组断言

它们都不是「功能」，所以不会有人主动来测：

* **注入**：报告里渲染的是被评估项目的**源码片段、漏洞标题、项目名**，
  以及 LLM 的输出 —— 全是不可信数据。不转义时的表现是「报告看起来完全正常」，
  只是打开时执行了脚本。
* **如实标注**：`skipped` 的验证写成「无风险」，`inferred` 的攻击链环写成
  「已验证」—— 报告照样能生成、照样好看，只是它在撒谎。

两条都属于「不测就永远不知道坏了」的类型，而且坏了以后**没有任何报错**。
"""

from __future__ import annotations

import re
from datetime import datetime

import pytest

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
from app.report.charts import score_ring, severity_bar_chart, type_donut, type_legend
from app.report.render import md_cell, md_code, md_text, render_html, render_markdown
from app.report.types import (
    STATUS_LABEL,
    ChainEntry,
    ChainNodeEntry,
    PatchEntry,
    PocEvidence,
    Recommendation,
    ReportData,
    ReportMeta,
    SecurityScore,
    StageSummary,
    TaintStepEntry,
    TypeSlice,
    VulnEntry,
    build_verification_footnote,
)

#: 故意带脚本的项目名与标题 —— 它们都会进 HTML 正文与 Markdown 表格。
XSS = "<script>alert(1)</script>"


def _table_blocks(md: str) -> list[list[str]]:
    """把 Markdown 里连续的 `| ... |` 行切成一块一块，用于检查列数是否对齐。"""
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in md.splitlines():
        if line.startswith("|"):
            current.append(line)
        elif current:
            blocks.append(current)
            current = []
    if current:
        blocks.append(current)
    return blocks


def _cells(line: str) -> int:
    """数**未被转义**的管道符 —— `\\|` 是内容，不是分隔符。

    这个区分正是 `md_cell` 存在的理由：把 `\\|` 也算成列，等于假装
    「转义了」和「没转义」没区别。
    """
    return len(re.findall(r"(?<!\\)\|", line))


def make_vuln(**overrides: object) -> VulnEntry:
    base = dict(
        id=1,
        code="VULN-2026-0001",
        title=f"订单查询接口存在 SQL 注入 {XSS}",
        vuln_type="sql_injection",
        type_label="SQL 注入",
        severity=Severity.CRITICAL,
        severity_cn="严重",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        status=VulnStatus.VERIFIED,
        status_cn=STATUS_LABEL["verified"],
        file_path="app/api/order.py",
        line_start=40,
        line_end=48,
        sink_symbol="cursor.execute",
        code_snippet="cursor.execute(sql)",
        description=f"外部输入被直接拼接进 SQL 语句。{XSS}",
        remediation_note="",
        confidence=0.9,
        detection_method=DetectionMethod.TAINT_INTER,
        guard_blocked=False,
        taint_path=[
            TaintStepEntry(
                step_index=0,
                step_type="source",
                file_path="app/api/order.py",
                line=12,
                symbol="request.args",
                code_snippet="order_id = request.args.get('order_id')",
            ),
            TaintStepEntry(
                step_index=1,
                step_type="sink",
                file_path="app/api/order.py",
                line=44,
                symbol="cursor.execute",
                code_snippet="cursor.execute(sql)",
            ),
        ],
        poc=PocEvidence(
            technique="boolean_blind",
            payload="1' AND 1=1-- ",
            matched=True,
            http_status=200,
            elapsed_ms=120,
            expected_pattern="nonce-a1b2c3",
        ),
        patch=PatchEntry(
            target_file="app/api/order.py",
            diff="--- a/app/api/order.py\n+++ b/app/api/order.py\n@@ -40,3 +40,3 @@\n-old\n+new\n",
            status=PatchStatus.SUGGESTED,
            source=PatchSource.LLM,
            llm_model="deepseek-chat",
            valid_diff=True,
            window_ok=True,
            apply_check_ok=True,
            taint_cleared=True,
        ),
    )
    base.update(overrides)
    return VulnEntry(**base)  # type: ignore[arg-type]


def make_chain(**overrides: object) -> ChainEntry:
    base = dict(
        id=1,
        name=f"SQL 注入 → 管理员凭证 → 上传 WebShell {XSS}",
        description="自订单查询接口注入开始，逐级取得更高权限。",
        severity=Severity.CRITICAL,
        entry_point="订单查询接口",
        target_asset="ECS 宿主机",
        confidence=0.85,
        nodes=[
            ChainNodeEntry(
                order_index=0,
                node_type=ChainNodeType.VULN,
                label="SQL 注入获取数据库读写",
                detail="布尔盲注确认可读取任意表",
                rule_id="R1",
                vuln_code="VULN-2026-0001",
                verification_status=VerificationStatus.VERIFIED,
            ),
            ChainNodeEntry(
                order_index=1,
                node_type=ChainNodeType.CREDENTIAL,
                label="读出管理员口令哈希",
                verification_status=VerificationStatus.VERIFIED,
            ),
            ChainNodeEntry(
                order_index=2,
                node_type=ChainNodeType.CREDENTIAL,
                label="弱哈希离线破解得到明文口令",
                verification_status=VerificationStatus.INFERRED,
            ),
            ChainNodeEntry(
                order_index=3,
                node_type=ChainNodeType.SHELL,
                label="登录后台并上传 WebShell",
                verification_status=VerificationStatus.INFERRED,
            ),
        ],
        narrative="攻击者首先利用订单查询接口的注入点取得数据库读写能力。",
        narrative_model="deepseek-chat",
    )
    base.update(overrides)
    chain = ChainEntry(**base)  # type: ignore[arg-type]
    chain.verification_footnote = build_verification_footnote(chain.nodes)
    return chain


def make_recommendation(**overrides: object) -> Recommendation:
    base = dict(
        rank=1,
        code="VULN-2026-0001",
        title=f"订单查询接口存在 SQL 注入 {XSS}",
        type_label="SQL 注入",
        severity=Severity.CRITICAL,
        severity_cn="严重",
        status=VulnStatus.VERIFIED,
        status_cn=STATUS_LABEL["verified"],
        cvss_score=9.8,
        file_path="app/api/order.py",
        line_start=40,
        line_end=48,
        priority=4.0,
        priority_factors={"等级权重": 4.0, "可达性": 1.0, "修复成本": 1.0, "优先级": 4.0},
        note="把拼接 SQL 的写法改为参数化查询。",
        note_model="deepseek-chat",
    )
    base.update(overrides)
    return Recommendation(**base)  # type: ignore[arg-type]


def make_data(**overrides: object) -> ReportData:
    vulns = overrides.pop("vulnerabilities", [make_vuln()])
    chains = overrides.pop("chains", [make_chain()])
    recommendations = overrides.pop("recommendations", [make_recommendation()])
    stages = overrides.pop(
        "stages",
        [
            StageSummary(stage=StageName.RECON, status=StageStatus.COMPLETED, duration_seconds=1.2),
            StageSummary(
                stage=StageName.POC_VERIFY,
                status=StageStatus.SKIPPED,
                note="沙箱不可达，已跳过动态验证",
            ),
            StageSummary(
                stage=StageName.EXPLOIT_CHAIN, status=StageStatus.COMPLETED, duration_seconds=0.4
            ),
        ],
    )
    meta = ReportMeta(
        assessment_id=1,
        project_id=1,
        project_name=f"靶场订单系统 {XSS}",
        project_description="用于演示注入类漏洞的靶场。",
        source_type="git",
        source_url="https://example.invalid/target.git",
        source_branch="main",
        tech_stack={"python": "3.12", "flask": "3.0"},
        total_loc=1200,
        started_at=datetime(2026, 10, 16, 10, 0, 0),
        finished_at=datetime(2026, 10, 16, 10, 3, 30),
        duration_seconds=210.0,
        stages=stages,
        generated_at=datetime(2026, 10, 16, 10, 4, 0),
    )
    base = dict(
        meta=meta,
        score=SecurityScore(
            score=89.7,
            grade=SecurityGrade.CRITICAL,
            veto=True,
            breakdown={"critical": 9.8, "total_penalty": 10.3},
        ),
        severity_matrix={("critical", "verified"): 1},
        severity_counts={"critical": 1, "high": 0, "medium": 0, "low": 0},
        severity_row_totals={"critical": 1, "high": 0, "medium": 0, "low": 0},
        type_distribution=[
            TypeSlice(category="sql_injection", label="SQL 注入", count=1, ratio=1.0)
        ],
        vulnerabilities=vulns,
        chains=chains,
        recommendations=recommendations,
        degraded=[],
        has_verified=True,
        chapter3_title="已验证漏洞清单",
        chapter3_note="本次共 1 条漏洞，其中 1 条已通过沙箱无害化验证。",
    )
    base.update(overrides)
    return ReportData(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 一、注入防护
# ---------------------------------------------------------------------------


def test_HTML_不出现可执行脚本标签() -> None:
    """被评估项目的源码片段、标题、项目名都是**不可信数据**。

    `select_autoescape` 按文件名后缀判断，而我们的模板叫 `report.html.j2` ——
    后缀是 `.j2`，**不会**被自动转义。所以 `render.py` 里显式写的是
    `autoescape=True`。这条断言就是那个选择的存在理由：
    少写这一次，报告就成了存储型 XSS 的投递平台。
    """
    html = render_html(make_data())

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    # 报告自带 CSP，双重保险（页面被塞进 iframe 时外链脚本也进不来）
    assert "default-src 'none'" in html


def test_HTML_里属性与文本都被转义() -> None:
    """转义要盖住**所有**插值点。

    只测标题那一处不够 —— 污点路径的代码片段、LLM 写的描述、
    攻击链的叙事都是独立的插值点，任一漏掉都成立。
    """
    html = render_html(make_data())

    # 描述（LLM 产出）里的脚本
    assert html.count("&lt;script&gt;") >= 4, "标题 / 描述 / 链名 / 项目名都该被转义"
    assert "alert(1)</script>" not in html


def test_Markdown_中和裸_HTML_并保护表格列() -> None:
    """Markdown 的注入面小，但不是没有。

    表格里一个未转义的 `|` 就会把整行拆成两行、后面所有行**列错位** ——
    而列错位不会报错，只会给出错误的数字对应关系。
    """
    md = render_markdown(make_data())

    assert "<script>" not in md
    # `md_text` 只中和左尖括号（右括号不是标签的起点），
    # 渲染 Markdown 的库看到的是实体 `&lt;script>`，它只会当成文字
    assert "&lt;script>" in md
    # 表格结构没被标题里的管道符/换行撑坏：每张表内每一行的列数必须一致
    for block in _table_blocks(md):
        widths = {_cells(line) for line in block}
        assert len(widths) == 1, f"表格列数不一致：{widths}\n" + "\n".join(block)


def test_md_cell_处理管道符换行与标签() -> None:
    assert md_cell("a|b") == r"a\|b"
    assert md_cell("a\nb\r\nc") == "a b c"
    assert md_cell("<img src=x>") == "&lt;img src=x>"
    # `a < b` 这种比较不该被误伤
    assert md_cell("a < b") == "a < b"
    assert md_cell(None) == ""


def test_md_code_围栏长度随内容自适应() -> None:
    """内容里出现三个反引号时，围栏必须比它长，否则会被提前闭合。"""
    fenced = md_code("```python\nboom\n```", "text")
    assert fenced.startswith("````")
    assert fenced.rstrip().endswith("````")


def test_md_text_保留换行() -> None:
    assert md_text("第一行\n第二行") == "第一行\n第二行"
    assert md_text("<b>x</b>") == "&lt;b>x&lt;/b>"


def test_图表内联_且自带转义() -> None:
    """图表返回 `Markup`（绕过 Jinja 转义），因此必须自己 `escape()`。

    用带脚本的标签输入直接打这三个函数 —— 它们是最容易被漏掉的一处，
    因为「图表数据来自规则库」听起来比「项目名来自用户」可信，但两者都不是常量。
    """
    bar = severity_bar_chart({"critical": 1}, labels={"critical": XSS})
    donut = type_donut([TypeSlice(category="x", label=XSS, count=1, ratio=1.0)])
    legend = type_legend([TypeSlice(category="x", label=XSS, count=1, ratio=1.0)])
    ring = score_ring(88.0, label=XSS)

    for svg in (bar, donut, legend, ring):
        assert "<script>" not in svg
        assert "alert(1)" not in svg.replace("&lt;script&gt;alert(1)&lt;/script&gt;", "")
    # 空数据返回空串而不是空图 —— 空坐标轴看起来像「图挂了」
    assert severity_bar_chart({}) == ""
    assert type_donut([]) == ""


# ---------------------------------------------------------------------------
# 二、如实标注：验证状态与攻击链环
# ---------------------------------------------------------------------------


def test_跳过的阶段写成已跳过而不是已完成() -> None:
    """`skipped` 是**降级态不是失败**，但更不是「跑了没问题」。

    报告不能把「没跑」与「跑了没问题」混成同一个灰点 ——
    这正是「一份诚实标注局限的报告比一份看起来很全的报告有价值」。
    """
    html = render_html(make_data())

    assert "已跳过" in html
    assert "沙箱不可达，已跳过动态验证" in html


def test_未验证的漏洞写成未经验证而不是无风险() -> None:
    data = make_data(
        vulnerabilities=[
            make_vuln(
                id=2,
                code="VULN-2026-0002",
                severity=Severity.HIGH,
                severity_cn="高危",
                status=VulnStatus.UNVERIFIED,
                status_cn=STATUS_LABEL["unverified"],
                cvss_score=8.0,
                poc=None,
            )
        ],
        chains=[],
        chapter3_title="漏洞清单（含未经验证条目）",
        has_verified=False,
        chapter3_note="本次共 1 条漏洞，没有任何一条通过动态验证。",
        chapter4_placeholder="本次评估未产出攻击链。",
        score=SecurityScore(score=99.2, grade=SecurityGrade.SAFE, veto=False, breakdown={}),
    )
    html = render_html(data)
    md = render_markdown(data)

    for text in (html, md):
        assert "未经验证（仅静态分析结论）" in text
        assert "未发现漏洞" not in text, "有漏洞时不能出现空态文案"

    # 「未经验证」与「无风险」是两件事，报告必须把这一句写出来
    assert "没有任何一条通过动态验证" in html
    assert "未经验证（仅静态分析结论）" in md


def test_攻击链脚注按实际环数动态生成() -> None:
    """B6 设计 §4.5 第 3 条：脚注**不得写死**。

    写死的后果是「链变成 5 环，脚注还在说第 3 环」——
    而它读起来完全通顺，没人会去核对。
    """
    chain = make_chain()
    assert chain.verified_count == 2
    assert chain.inferred_count == 2
    assert "第 1–2 环已在沙箱中无害验证" in chain.verification_footnote
    assert "第 3–4 环由已证实的前置条件推演得出，未实际执行" in chain.verification_footnote

    html = render_html(make_data(chains=[chain]))
    md = render_markdown(make_data(chains=[chain]))
    assert "第 3–4 环由已证实的前置条件推演得出" in html
    # Markdown 用文字前缀替代配色，口径必须与 HTML 一致
    assert md.count("[已验证]") == 2
    assert md.count("[已推演]") == 2


def test_全推演的链脚注如实声明() -> None:
    nodes = [
        ChainNodeEntry(
            order_index=i,
            node_type=ChainNodeType.ENTRY,
            label=f"第 {i + 1} 环",
            verification_status=VerificationStatus.INFERRED,
        )
        for i in range(3)
    ]
    footnote = build_verification_footnote(nodes)
    assert "3 环均由已证实的前置条件推演得出，未实际执行" in footnote


def test_全验证的链脚注不出现未执行字样() -> None:
    nodes = [
        ChainNodeEntry(
            order_index=i,
            node_type=ChainNodeType.VULN,
            label=f"第 {i + 1} 环",
            verification_status=VerificationStatus.VERIFIED,
        )
        for i in range(2)
    ]
    assert build_verification_footnote(nodes) == "第 1–2 环已在沙箱中无害验证。"


def test_未过四道校验的补丁显式标注仅作人工参考() -> None:
    data = make_data(
        vulnerabilities=[
            make_vuln(
                patch=PatchEntry(
                    target_file="app/api/order.py",
                    diff="--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n",
                    status=PatchStatus.SUGGESTED,
                    source=PatchSource.VALIDATE_FAILED,
                    valid_diff=True,
                    window_ok=True,
                    apply_check_ok=False,
                    taint_cleared=False,
                    failure_reason="打上后污点路径仍然存在",
                )
            )
        ]
    )
    html = render_html(data)
    md = render_markdown(data)

    assert "四道校验未通过，已降级为人工参考" in html
    assert "打上后污点路径仍然存在" in html
    # 四道校验逐条列出，而不是合成一个「校验失败」——
    # 「哪一道没过」决定了这补丁还差多少才可用
    assert "③ git apply 干跑：未通过" in html
    assert "④ 污点路径消失：未通过" in html
    # Markdown 没有徽章配色，用文字把同一件事说清楚
    assert "四道校验未通过，已降级为人工参考" in md
    assert "③ `git apply` 干跑 未通过" in md
    assert "④ 污点路径消失 未通过" in md


# ---------------------------------------------------------------------------
# 三、完整性与降级标注
# ---------------------------------------------------------------------------


def test_无_LLM_时五章齐全且标注模板生成() -> None:
    """**「拿掉 LLM，结论一字不变」在渲染层的体现。**

    报告必须仍然有：漏洞清单、CVSS、污点路径、攻击链、整改建议 —— 一个都不少，
    只是第 5 章的文案标注为「模板生成」。
    """
    data = make_data(
        degraded=["llm"],
        notes_template_count=1,
        recommendations=[
            make_recommendation(
                note="把拼接 SQL 的写法改为参数化查询。",
                note_model="template",
                note_degraded=True,
            )
        ],
        chains=[
            make_chain(
                narrative="攻击链叙事（模板生成）",
                narrative_model="template",
                narrative_degraded=True,
            )
        ],
    )
    html = render_html(data)
    md = render_markdown(data)

    for text in (html, md):
        assert "1. 项目概况与执行信息" in text
        assert "2. 安全评分与风险大盘" in text
        assert "3. " in text and "漏洞清单" in text
        assert "4. 多步攻击路径推演" in text
        assert "5. 安全整改建议" in text
        # 漏洞级的关键事实
        assert "9.8" in text, "CVSS 缺失"
        assert "app/api/order.py:12" in text, "污点路径缺失"
        assert "VULN-2026-0001" in text

    assert "模板生成" in html
    assert "模板生成" in md
    assert "本次报告的降级说明" in md


def test_降级清单为空时不出现降级横幅() -> None:
    """只登记**真的发生了**的降级。

    一个固定的「本报告可能降级」免责声明没有信息量，
    反而会让人忽略掉真正的降级项。
    """
    html = render_html(make_data(degraded=[]))
    md = render_markdown(make_data(degraded=[]))

    assert "本次报告的降级说明" not in html
    assert "本次报告的降级说明" not in md
    # 脚注里那句「未通过即降级为模板文案」是**机制说明**，不是降级声明 —— 它恒在
    assert "本次报告无降级项" not in html


def test_无漏洞时走空态() -> None:
    data = make_data(
        vulnerabilities=[],
        chains=[],
        recommendations=[],
        empty_state=True,
        has_verified=False,
        chapter3_note="",
        chapter4_placeholder="本次评估未产出攻击链。",
        severity_matrix={},
        type_distribution=[],
        score=SecurityScore(score=100.0, grade=SecurityGrade.SAFE, veto=False, breakdown={}),
    )
    html = render_html(data)

    assert "未发现漏洞" in html
    assert "本次评估未产出攻击链" in html
    assert "本次评估未产出漏洞条目" in html


def test_逐点证据标注为逐点确认() -> None:
    """探针打在本条**自己的端点**上时，报告要明确说这是逐点确认。

    ⚠️ 这条与下面的 `test_类别级证据明确标注不是逐点` 是**一对**。
    早先只有一句笼统的「证据适用范围」免责声明，两种强度完全不同的证据
    读起来一模一样 —— 而靶场实测 15 条里 10 条是弱的那种。
    免责声明不算交代清楚，**分开说**才算。
    """
    data = make_data(
        vulnerabilities=[
            make_vuln(
                poc=PocEvidence(
                    technique="union_extract",
                    payload="1 UNION SELECT 'nonce-a1b2c3','asa' -- ",
                    matched=True,
                    http_status=200,
                    elapsed_ms=24,
                    expected_pattern="nonce-a1b2c3",
                    request_raw="GET /search?q=1%20UNION%20SELECT%20'nonce'%20--%20",
                    bound_to_finding=True,
                )
            )
        ]
    )
    html = render_html(data)
    md = render_markdown(data)

    for rendered, fmt in ((html, "HTML"), (md, "Markdown")):
        assert "逐点确认" in rendered, f"{fmt} 里没说明这是逐点确认"
        assert "仅类别级" not in rendered, f"{fmt} 把逐点证据说成了类别级"
        # 触发位置与请求路径同时在场，读者才比对得起来
        assert "app/api/order.py" in rendered, f"{fmt} 里没有触发位置"
        assert "/search?q=" in rendered, f"{fmt} 里没有请求报文路径"


def test_类别级证据明确标注不是逐点() -> None:
    """探针只能打在模板的固定路由上时，报告必须**把话收住**。

    回归测试，对应一个实测出来的解读陷阱：探针的路由来自模板、不来自 finding，
    所以靶场上出现过「`admin_login.py:43` 的 SQL 注入，证据是 `GET /search?q=`」。
    报告里两句话都在（触发位置 + 请求报文），但**没有任何一句说明二者可以不是
    同一个端点** —— 读者会把「该类漏洞的标准形态已确认」读成「这一行已被打通」。
    """
    data = make_data(
        vulnerabilities=[
            make_vuln(
                poc=PocEvidence(
                    technique="union_extract",
                    payload="1 UNION SELECT 'nonce-a1b2c3','asa' -- ",
                    matched=True,
                    http_status=200,
                    elapsed_ms=24,
                    expected_pattern="nonce-a1b2c3",
                    request_raw="GET /search?q=1%20UNION%20SELECT%20'nonce'%20--%20",
                    bound_to_finding=False,
                )
            )
        ]
    )
    html = render_html(data)
    md = render_markdown(data)

    for rendered, fmt in ((html, "HTML"), (md, "Markdown")):
        assert "仅类别级" in rendered, f"{fmt} 里没有说明这只是类别级证据"
        assert "不等于" in rendered, f"{fmt} 里没有把话收住"
        assert "逐点确认" not in rendered, f"{fmt} 把类别级证据说成了逐点确认"
        # 触发位置与请求路径同时在场，读者才比对得起来
        assert "app/api/order.py" in rendered, f"{fmt} 里没有触发位置"
        assert "/search?q=" in rendered, f"{fmt} 里没有请求报文路径"


def test_动态未复现的条数如实标注() -> None:
    """未复现的条目在正文留痕、在整改清单里说明 —— **不悄悄丢掉**。

    ⚠️ 断言的是「机器判定 + 待人工确认」这层意思，**不是**「已复核排除」。
    原措辞把全自动的结论说成人工复核过的，实测中它掩盖过两条真 SQL 注入
    （机器判 `rejected`，报告却说人工已排除）。所以这里锁死两件事：
    ①条数如实出现；②措辞必须点明未经人工确认。
    """
    data = make_data(excluded_rejected=2)
    html = render_html(data)
    md = render_markdown(data)

    for rendered, fmt in ((html, "HTML"), (md, "Markdown")):
        assert "2 条漏洞经机器动态验证未复现" in rendered, f"{fmt} 里没有如实报出条数"
        assert "未经人工确认" in rendered, f"{fmt} 里没点明这是机器结论"
        # 回归：不得再把机器结论说成人工复核过的
        assert "已人工复核排除" not in rendered, f"{fmt} 里出现了「已人工复核排除」"


def test_导出的两种格式章节顺序一致() -> None:
    """HTML 与 Markdown 的章节顺序**必须一致**（设计 §7.2「一套数据三格式」）。

    顺序漂移的表现是「PDF 里第 3 章在第 4 章后面」，而三份文件各自读起来都通顺。
    """
    data = make_data()
    html = render_html(data)
    md = render_markdown(data)
    titles = [
        "1. 项目概况与执行信息",
        "2. 安全评分与风险大盘",
        "4. 多步攻击路径推演",
        "5. 安全整改建议",
    ]

    for title in titles:
        assert title in html
        assert title in md
    assert (
        html.index(titles[0])
        < html.index(titles[1])
        < html.index(titles[2])
        < html.index(titles[3])
    )
    assert md.index(titles[0]) < md.index(titles[1]) < md.index(titles[2]) < md.index(titles[3])


def test_报告末尾声明结论不来自模型() -> None:
    """报告要能自证「哪部分不是模型写的」—— 这是它可被追问的前提。"""
    for text in (render_html(make_data()), render_markdown(make_data())):
        assert "不来自大语言模型" in text


def _html_bodies() -> list[tuple[str, str]]:
    """几条**会走到不同分支**的 HTML 正文。

    单测「一份普通报告」是不够的：`**` 曾藏在「未发现漏洞」空态提示与
    「一票否决」告警里，而这两段只有在对应分支被点亮时才渲染出来 ——
    默认夹具里一条都看不到，测试全绿，页面上却挂着星号。
    """
    empty = make_data(
        vulnerabilities=[],
        chains=[],
        recommendations=[],
        empty_state=True,
        has_verified=False,
        severity_matrix={},
        severity_counts={},
        severity_row_totals={},
        type_distribution=[],
        chapter3_note="",
    )
    return [
        ("有漏洞", render_html(make_data())),
        ("空态", render_html(empty)),
    ]


def test_HTML_正文不含_Markdown_残留标记() -> None:
    """同一份文案同时喂 HTML 与 Markdown，因此它必须是纯文本。

    这条守的是一类不会报错的瑕疵：`_chapter3_note` 里写 `**不等于**` 或
    `fallback._loc` 里包一对反引号，两种格式都照常生成、测试全绿，
    只有打开 HTML 页面才会看到一串多余的星号和反引号。

    只查正文，不查 `<style>`：内联 CSS 里的注释不参与渲染。
    """
    for name, html in _html_bodies():
        body = html.split("</style>", 1)[-1]
        assert "**" not in body, f"{name} 正文里有 Markdown 强调标记"
        assert "`" not in body, f"{name} 正文里有 Markdown 代码标记"


def test_Markdown_里保留_fenced_code_与强调() -> None:
    """反过来：Markdown 侧该有的语法不能被「纯文本化」误伤。"""
    md = render_markdown(make_data())

    assert "```" in md, "补丁/载荷的围栏代码块丢了"
    assert "**" in md, "Markdown 的强调语法丢了"


@pytest.mark.parametrize("fmt", list(ReportFormat))
def test_格式枚举与导出路径映射齐全(fmt: ReportFormat) -> None:
    from app.report import paths

    assert paths.relative_path(7, fmt) == f"7/report.{fmt.value}"
