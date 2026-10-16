"""L4 降级路径测试：**拿掉 LLM，四个使用点必须照样产出可交付的中文文案。**

## 这一组测试在验什么

它验的不是「有没有 try/except」，而是 PRD §7.6.4 问答二那句判据：

> 拿掉 LLM，系统的结论必须一字不变，只有措辞会变。

所以每条降级断言都分三层：

1. **有产出**：返回对象存在、`TextResult.text` 非空 —— 防的是 `return ""`；
2. **有信息**：位置、行号、CVSS、验证状态这些**已被判定的值**原样出现在文案里
   —— 防的是「降级文案退化成一句『存在漏洞，请修复』」；
3. **有标注**：`llm_model == "template"`、`degraded is True`
   —— 防的是「用模板产出但对外声称是模型写的」，那是报告诚信问题。

三层缺一层，这套降级就是装饰性的。第 2 层尤其容易被写成走过场，
所以下面用的是「具体字符串在不在」而不是「长度够不够」。
"""

from __future__ import annotations

import pytest

from app.llm import fallback
from app.llm.expressions import (
    describe_finding,
    narrate_chain,
    suggest_patch,
    suggest_remediation,
    suggest_remediations,
)
from app.llm.types import (
    TEMPLATE_MODEL,
    ChainNodeView,
    ChainView,
    FindingView,
    TaintStepView,
)
from tests.llm_fakes import FailingCompleter, FakeCompleter, MalformedCompleter, NoKeyCompleter

# ---------------------------------------------------------------------------
# 输入构造
# ---------------------------------------------------------------------------

#: 一个「信息齐全」的漏洞：有编号、有 CWE、有污点路径、有验证状态。
#: 齐全的输入才能验出模板有没有把信息搬进文案 —— 缺字段的输入会掩盖这个问题。
FINDING = FindingView(
    vuln_type="sql_injection",
    severity="critical",
    file_path="app/api/order.py",
    line_start=40,
    line_end=48,
    code="VULN-2026-0001",
    title="订单查询接口存在 SQL 注入",
    symbol="cursor.execute",
    cwe_id="CWE-89",
    cvss_score=9.8,
    confidence=0.9,
    source_kind="request.args['order_id']",
    sink_kind="cursor.execute",
    status="verified",
    taint_path=(
        TaintStepView(
            step_index=0,
            step_kind="source",
            file_path="app/api/order.py",
            line=12,
            symbol="request.args",
            snippet="order_id = request.args.get('order_id')",
        ),
        TaintStepView(
            step_index=1,
            step_kind="propagate",
            file_path="app/service/order.py",
            line=30,
            symbol="build_sql",
            snippet="sql = 'SELECT * FROM orders WHERE id = %s' % order_id",
        ),
        TaintStepView(
            step_index=2,
            step_kind="sink",
            file_path="app/api/order.py",
            line=44,
            symbol="cursor.execute",
            snippet="cursor.execute(sql)",
        ),
    ),
)

#: 未经验证、缺 CVSS 的一条 —— 验「不利结论也要如实写出来」。
UNVERIFIED_FINDING = FindingView(
    vuln_type="path_traversal",
    severity="high",
    file_path="app/api/file.py",
    line_start=21,
    line_end=24,
    code="VULN-2026-0002",
    title="文件下载接口存在路径穿越",
    symbol="open",
    status="unverified",
    taint_path=(),
)

#: 一条 4 环的链，前 2 环已验证、后 2 环推演 —— 与 PRD §10.1 演示链同形。
CHAIN = ChainView(
    name="SQL 注入 → 管理员凭证 → 上传 WebShell → 宿主机 RCE",
    description="自订单查询接口注入开始，逐级取得更高权限。",
    entry_point="订单查询接口",
    target_asset="ECS 宿主机",
    severity="critical",
    nodes=(
        ChainNodeView(
            label="SQL 注入获取数据库读写",
            node_type="vuln",
            order_index=0,
            verification_status="verified",
            detail="布尔盲注确认可读取任意表",
            vuln_code="VULN-2026-0001",
            rule_id="R1",
        ),
        ChainNodeView(
            label="读出管理员口令哈希",
            node_type="credential",
            order_index=1,
            verification_status="verified",
            detail="users 表中取得管理员记录",
            vuln_code="VULN-2026-0001",
            rule_id="R2",
        ),
        ChainNodeView(
            label="弱哈希离线破解得到明文口令",
            node_type="credential",
            order_index=2,
            verification_status="inferred",
            detail="MD5 口令可离线爆破",
            rule_id="R3",
        ),
        ChainNodeView(
            label="登录后台并上传 WebShell",
            node_type="shell",
            order_index=3,
            verification_status="inferred",
            detail="后台存在不受限的文件上传",
            rule_id="R4",
        ),
    ),
)

#: 四个使用点在「LLM 完全不可用」时各自的输入。
ALL_POINTS = {
    "①漏洞描述": lambda client: describe_finding(FINDING, client=client),
    "②Diff 补丁": lambda client: suggest_patch(FINDING, client=client),
    "③攻击链叙事": lambda client: narrate_chain(CHAIN, client=client),
    "④整改建议": lambda client: suggest_remediation(FINDING, rank=1, total=7, client=client),
}

#: 会出现在降级文案里的占位符痕迹。出现任何一个都说明模板没写完。
_FORBIDDEN = ("TODO", "FIXME", "XXX", "{", "}", "None", "undefined", "placeholder")


def causes() -> list[tuple[str, object]]:
    """三种「LLM 用不了」的成因。**三种都要单独跑**：

    * 没配 key —— 合法的开发态配置，必须安静降级；
    * 配了 key 但超时/500 —— 真实环境里最常见的一种；
    * 响应到了但不是 chat 补全结构 —— 网关把错误页当 200 返回。

    合成一个用例的后果是：只测了「没 key」这一条，另外两条（恰恰是生产里
    真会发生的）在代码改动后就悄悄断了。
    """
    return [
        ("未配置 API Key", NoKeyCompleter()),
        ("调用失败（超时/500）", FailingCompleter()),
        ("响应畸形", MalformedCompleter()),
    ]


# ---------------------------------------------------------------------------
# 一、四个使用点 × 三种不可用成因 —— 全部必须降级产出
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("cause", "client"), causes(), ids=lambda v: str(v)[:24])
@pytest.mark.parametrize("point", sorted(ALL_POINTS))
async def test_四个用点在任何异常下都降级产出(cause: str, client: object, point: str) -> None:
    result = await ALL_POINTS[point](client)

    assert result.llm_model == TEMPLATE_MODEL, f"{point} 在「{cause}」时没有标注为模板"
    assert result.degraded is True, f"{point} 在「{cause}」时没有标记降级"
    assert result.reason, "降级必须给出原因码，否则「为什么是模板」无从查起"

    text = result.diff if hasattr(result, "diff") else result.text
    if point == "②Diff 补丁":
        # 契约 3：用点②的降级产物是「无补丁」，但**必须同时给出通用修复建议**
        assert result.diff is None
        assert result.advice.strip()
        text = result.advice

    assert text and text.strip(), f"{point} 在「{cause}」时产出了空文本"
    assert len(text) >= 60, f"{point} 的降级文案过短，信息量不足：{text!r}"
    for token in _FORBIDDEN:
        assert token not in text, f"{point} 的降级文案里出现占位符 {token!r}"
    # 纯文本契约（见 `fallback.py` 模块文档）：同一份文案也进 HTML 模板，
    # 带 Markdown 标记就会在页面上留下星号和反引号 —— 而且不会报错
    assert "**" not in text, f"{point} 的降级文案里混进了 Markdown 强调标记"
    assert "`" not in text, f"{point} 的降级文案里混进了 Markdown 代码标记"


async def test_无_key_时不发网络请求也不重试() -> None:
    """未配 key 是**合法开发态配置**，不是错误。

    断言的是「一次调用就降级」：如果实现里写成「失败后重试」，`calls` 会大于 1，
    日志里也会刷出一串「密钥缺失」的 warning —— 那是把正常状态当故障处理。
    """
    client = NoKeyCompleter()
    result = await describe_finding(FINDING, client=client)

    assert result.degraded and result.llm_model == TEMPLATE_MODEL
    assert result.reason == "no_api_key"
    assert client.calls == 1


# ---------------------------------------------------------------------------
# 二、降级文案的信息量：已判定的值必须**原样出现**
# ---------------------------------------------------------------------------


async def test_漏洞描述降级文案保留全部已判定事实() -> None:
    text = (await describe_finding(FINDING, client=NoKeyCompleter())).text

    assert "SQL 注入" in text, "漏洞类型没进文案"
    assert "严重" in text, "漏洞严重度没进文案"
    assert "9.8" in text, "CVSS 没进文案"
    assert "VULN-2026-0001" in text, "漏洞编号没进文案"
    assert "app/api/order.py:40-48" in text, "触发位置没进文案"
    assert "已通过动态验证" in text, "验证状态没进文案 —— 读者无法判断结论强度"
    # 污点路径的每一跳都必须在，这是模板里信息密度最高的一段
    assert "app/service/order.py:30" in text
    assert "cursor.execute" in text


async def test_未验证漏洞的降级文案不谎称已确认() -> None:
    text = (await describe_finding(UNVERIFIED_FINDING, client=NoKeyCompleter())).text

    assert "未经动态验证" in text
    assert "未记录到完整的污点路径" in text, "没有污点路径时必须明说，而不是编一条"
    assert "路径穿越" in text


async def test_整改建议降级文案里出现排序序号() -> None:
    """`rank` / `total` 是**输入**（由 `scoring.py` 的确定性公式产出）。

    模板必须把它读出来写进文案 —— 若模型参与排序，同一份数据两次生成
    会得到两份不同的行动建议，可复现性当场失效。
    """
    text = (await suggest_remediation(FINDING, rank=3, total=7, client=NoKeyCompleter())).text
    assert "3/7" in text


async def test_攻击链叙事降级文案标注每一环的验证程度() -> None:
    text = (await narrate_chain(CHAIN, client=NoKeyCompleter())).text

    assert text.count("[已验证]") == 2
    assert text.count("[已推演]") == 2
    assert "未实际执行" in text, "「已推演」必须显式声明未实际执行 —— 否则等于宣称做了没做的事"
    assert "VULN-2026-0001" in text


async def test_补丁降级不生成_diff() -> None:
    """模板**绝不拼 diff**。

    凭 `file_path` + 行号拼出来的 diff 在语法上可能成立、语义上几乎一定是错的，
    而一个「看起来能 apply」的错误补丁比没有补丁更危险 —— 它会消耗掉复核者的信任。
    """
    draft = await suggest_patch(FINDING, client=NoKeyCompleter())

    assert draft.diff is None
    assert "参数化查询" in draft.advice, "通用修复建议必须是可执行的具体做法"
    assert "复核要点" in draft.advice


# ---------------------------------------------------------------------------
# 三、模板函数**逐个可直接调用**（不需要经过 HTTP 假客户端）
# ---------------------------------------------------------------------------


def test_模板函数可独立调用() -> None:
    """判据是「拿掉 LLM 结论不变」，因此这些函数必须能被直接断言。

    若它们只能经由 `expressions.py` 触发，这条判据就没法在回归里被守住 ——
    而要绕道假客户端才能测的降级，改起来也更容易被绕过。
    """
    assert fallback.describe_finding(FINDING).strip()
    assert fallback.patch_advice(FINDING).strip()
    assert fallback.narrate_chain(CHAIN).strip()
    assert fallback.suggest_remediation(FINDING, rank=1, total=3).strip()


def test_未登记的类型如实回显原名() -> None:
    """类型表里没有它就回显原名 —— 难看，但不撒谎。"""
    assert "business_logic_abuse" in fallback.vuln_type_label("business_logic_abuse")
    assert fallback.vuln_type_label("sql_injection") == "SQL 注入"


def test_空链不编造叙事() -> None:
    empty = ChainView(name="空链", nodes=())
    text = fallback.narrate_chain(empty)
    assert "未记录到可用节点" in text
    assert "不对其做任何推断" in text


# ---------------------------------------------------------------------------
# 四、LLM 可用时**不降级**（降级不能变成默认行为）
# ---------------------------------------------------------------------------


async def test_模型可用时用模型文案且不标降级() -> None:
    """反向用例。

    只有降级测试的话，「永远走模板」也能让上面全绿 —— 那样 LLM 层就成了
    摆设，而 PRD §7.6 的整个设计意图（措辞交给模型）就落空了。
    """
    client = FakeCompleter("该接口将外部输入直接拼接进 SQL 语句，攻击者可借此改变查询结构。")
    result = await describe_finding(FINDING, client=client)

    assert result.degraded is False
    assert result.llm_model == "deepseek-chat"
    assert result.reason is None
    assert result.text.startswith("该接口")
    assert len(client.calls) == 1


async def test_模型输出含编造实体时整段拒收换模板() -> None:
    """实体白名单是**硬闸**（L3）。

    拒收而不是「删掉那一句」：删掉之后文案依然通顺，幻觉的痕迹就此消失，
    而读者会以为剩下的部分都是核实过的。降级是允许的，发明不是。
    """
    from app.llm.errors import LlmResponseError  # noqa: F401  （保持 import 语义清晰）
    from tests.llm_fakes import HallucinatingCompleter

    result = await describe_finding(FINDING, client=HallucinatingCompleter())

    assert result.degraded is True
    assert result.reason == "guard_rejected"
    assert result.llm_model == TEMPLATE_MODEL
    assert "app/evil.py" not in result.text
    assert "CVE-2021-44228" not in result.text


async def test_批量整改文案在无_key_时整批走模板() -> None:
    """批量版本在**批量层**就短路，省掉 N 次必然失败的调用与 N 行日志。"""
    findings = [FINDING, UNVERIFIED_FINDING]
    results = await suggest_remediations(findings, client=NoKeyCompleter())

    assert len(results) == 2
    assert all(r.degraded and r.llm_model == TEMPLATE_MODEL for r in results)
    # 顺序即语义：调用方按位置取值，不能用 code 做键（code 可能为空）
    assert "1/2" in results[0].text
    assert "2/2" in results[1].text


def test_降级结构拒绝空文本() -> None:
    """把不变量钉在类型里：`return ""` 会在构造时就炸。"""
    from app.llm.types import TextResult

    with pytest.raises(ValueError):
        TextResult(text="   ", llm_model=TEMPLATE_MODEL, degraded=True)
