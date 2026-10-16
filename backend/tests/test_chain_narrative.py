"""攻击链叙事的测试（L2/L3/L4 在 B5 这一侧的落点）。

叙事是 B5 里**唯一**不由代码直接产出的文本，所以这一组测试要钉死三件事：

* **L3 真的在跑**：模型若提到本链之外的漏洞编码，整段拒收、回落模板 ——
  而且是**拒收**不是"把那句删掉"（删掉之后文案仍然通顺，幻觉的痕迹就没了）。
* **L2 真的成立**：叙事换来换去，节点、边、环级验证状态一个字节都不变。
  拿掉 LLM 结论不变，这是可控多智能体设计原则的最低要求。
* **L4 真的降级**：无 key、超时、校验不过、模块缺席 —— 一律回落模板，
  且模板文本**逐字**就是原来的那份，不是"改了一点的版本"。

测试用 `sys.modules` 注入一个假的 `app.llm.expressions`，**不碰真实模型、
也不依赖 B6 当时的实现状态** —— 这一组测的是 B5 的边界行为，
B6 内部的取舍由 B6 自己的测试负责。
"""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest

from app.chain.builder import build_chain
from app.chain.narrative import _offending_codes, build_chain_narrated, narrate_chain, narrate_draft
from app.chain.types import AttackChain
from app.models.enums import VerificationStatus


class _Finding:
    def __init__(
        self,
        vuln_id: int,
        vuln_type: str,
        *,
        file_path: str = "app/api/order.py",
        symbol: str = "cursor.execute",
        cvss: float = 8.0,
        code: str | None = None,
    ) -> None:
        self.vuln_id = vuln_id
        self.vuln_type = vuln_type
        self.file_path = file_path
        self.symbol = symbol
        self.cvss_score = cvss
        self.code = code or f"VULN-2026-{vuln_id:04d}"


def _findings() -> list[_Finding]:
    return [
        _Finding(1, "sql_injection", cvss=9.1, code="VULN-2026-0001"),
        _Finding(
            2,
            "file_upload",
            file_path="app/api/admin/upload.py",
            symbol="save_upload",
            cvss=8.1,
            code="VULN-2026-0004",
        ),
    ]


class _Result:
    """B6 `TextResult` 的最小视图（只用到 `.text` / `.degraded`）。"""

    def __init__(self, text: str = "", *, degraded: bool = False) -> None:
        self.text = text
        self.degraded = degraded


def _install_fake_llm(monkeypatch: pytest.MonkeyPatch, behaviour: Any) -> dict[str, Any]:
    """往 `sys.modules` 塞一个假的 `app.llm.expressions`。

    返回一个可观察的 state 字典（调用次数、最后一次拿到的链），
    **不 import 真实的 `app.llm`**：这一组测的是 B5 的降级与校验，
    真实模块有没有写完不该影响它的结论。
    """
    state: dict[str, Any] = {"calls": 0, "chain": None}
    module = types.ModuleType("app.llm.expressions")

    async def narrate_chain(chain: Any, *, client: Any = None) -> Any:
        state["calls"] += 1
        state["chain"] = chain
        return behaviour(chain)

    module.narrate_chain = narrate_chain  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "app.llm.expressions", module)
    return state


def _demo_chain() -> AttackChain:
    return build_chain(_findings()).chains[0]


# ---------------------------------------------------------------------------
# 正常路径
# ---------------------------------------------------------------------------


async def test_llm_narrative_is_used_and_marked(monkeypatch: pytest.MonkeyPatch) -> None:
    chain = _demo_chain()
    state = _install_fake_llm(monkeypatch, lambda _c: _Result("注入点位于下单接口，可读取用户表。"))

    result = await narrate_chain(chain)

    assert state["calls"] == 1
    assert result.narrative_source == "llm"
    assert result.narrative.startswith("注入点位于下单接口")
    assert result.nodes == chain.nodes  # 结论未被改写


async def test_narration_is_handed_the_already_built_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    """喂给模型的**只有已定稿的事实**（节点/规则编号），不是源码（L2 输入侧）。"""
    chain = _demo_chain()
    state = _install_fake_llm(monkeypatch, lambda _c: _Result("结论文案"))

    await narrate_chain(chain)

    seen = state["chain"]
    assert seen.rule_ids == chain.rule_ids
    assert [n.rule_id for n in seen.nodes] == [n.rule_id for n in chain.nodes]


async def test_llm_cannot_change_any_conclusion(monkeypatch: pytest.MonkeyPatch) -> None:
    """**L1/L2**：叙事换了，节点、边、环级验证状态、置信度一个都不变。

    拿掉 LLM 结论不变 —— 这条如果破了，模型就参与判定了，只是它改的是
    "结构性字段"而不是文字，更难被发现。
    """
    chain = _demo_chain()
    before = chain.model_dump()
    _install_fake_llm(
        monkeypatch, lambda _c: _Result("完全换一套措辞，甚至说这里还有 VULN-2026-0001。")
    )

    result = await narrate_chain(chain)

    after = result.model_dump()
    for field in ("nodes", "rule_ids", "confidence", "severity", "entry_point", "chain_id"):
        assert after[field] == before[field], field
    assert result.verified_ring_count == chain.verified_ring_count
    assert result.narrative != before["narrative"]


async def test_narrative_keeps_the_per_ring_verification_marks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """模型写的新文案不能把"哪几环是推演"这件事盖掉 —— 标记在字段上，不在文字里。"""
    chain = _demo_chain()
    _install_fake_llm(monkeypatch, lambda _c: _Result("一条听起来全都很确定的叙事。"))

    result = await narrate_chain(chain)

    assert result.inferred_ring_count == chain.inferred_ring_count
    assert {n.rule_id: n.verification_status for n in result.nodes} == {
        n.rule_id: n.verification_status for n in chain.nodes
    }
    assert any(n.verification_status is VerificationStatus.INFERRED for n in result.nodes)


# ---------------------------------------------------------------------------
# L3：输出必校验
# ---------------------------------------------------------------------------


async def test_narrative_mentioning_a_foreign_code_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """叙事里出现本链**之外**的漏洞编码 → 整段拒收，回落模板。

    这是最值得写的一条：模型不需要"胡说八道"就能违规 ——
    它只要把工程里另一处的编号顺手写进来，读者就会以为那个漏洞也在这条链上。
    """
    chain = _demo_chain()
    template = chain.narrative
    _install_fake_llm(
        monkeypatch,
        lambda _c: _Result(f"{template} 另外 VULN-2026-0099 也参与了这次利用。"),
    )

    result = await narrate_chain(chain)

    assert result.narrative_source == "template"
    assert result.narrative == template
    assert "VULN-2026-0099" not in result.narrative


async def test_rejected_narrative_is_replaced_not_edited(monkeypatch: pytest.MonkeyPatch) -> None:
    """拒收的产出是**模板原文**，不是"删掉那句之后的模型文案"。

    如果做的是"把那句删掉"，文案会读起来仍然通顺 —— 幻觉的痕迹消失，
    读者不知道少了什么。拒收的代价是已知的（措辞变差），发明不是。
    """
    chain = _demo_chain()
    template = chain.narrative
    hallucinated = "根据分析，攻击者可从 VULN-2026-0099 一路推进到宿主机。"
    _install_fake_llm(monkeypatch, lambda _c: _Result(hallucinated))

    result = await narrate_chain(chain)

    assert result.narrative == template
    assert "根据分析" not in result.narrative
    assert "VULN-2026-0099" not in result.narrative


async def test_a_code_from_the_chain_itself_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    """引用本链自己的编码是合法的（那正是要讲的事实）。"""
    chain = _demo_chain()
    own = sorted(chain.vuln_codes)[0]
    _install_fake_llm(monkeypatch, lambda _c: _Result(f"起点是 {own}，随后取得后台会话。"))

    result = await narrate_chain(chain)

    assert result.narrative_source == "llm"
    assert own in result.narrative


async def test_lowercase_code_counts_as_a_violation(monkeypatch: pytest.MonkeyPatch) -> None:
    """大小写变体不能绕开校验 —— 否则"vuln-2026-0099"就能混进去。"""
    chain = _demo_chain()
    _install_fake_llm(monkeypatch, lambda _c: _Result("参考 vuln-2026-0099 的攻击路径。"))

    result = await narrate_chain(chain)

    assert result.narrative_source == "template"


def test_offending_codes_is_case_insensitive_and_whitelist_driven() -> None:
    allowed = frozenset({"VULN-2026-0001"})
    assert _offending_codes("见 VULN-2026-0001", allowed) == []
    assert _offending_codes("见 vuln-2026-0001", allowed) == []
    assert _offending_codes("见 VULN-2026-0002", allowed) == ["VULN-2026-0002"]
    assert _offending_codes("见 VULN-2026-0002 与 VULN-2026-0003", allowed) == [
        "VULN-2026-0002",
        "VULN-2026-0003",
    ]
    assert _offending_codes("没有编号的一句话", allowed) == []


# ---------------------------------------------------------------------------
# L4：降级不中断
# ---------------------------------------------------------------------------


async def test_degraded_result_falls_back_to_template(monkeypatch: pytest.MonkeyPatch) -> None:
    chain = _demo_chain()
    _install_fake_llm(monkeypatch, lambda _c: _Result("模型说它写好了", degraded=True))

    result = await narrate_chain(chain)

    assert result.narrative_source == "template"
    assert result.narrative == chain.narrative


async def test_empty_text_falls_back_to_template(monkeypatch: pytest.MonkeyPatch) -> None:
    chain = _demo_chain()
    _install_fake_llm(monkeypatch, lambda _c: _Result("   "))

    result = await narrate_chain(chain)

    assert result.narrative_source == "template"
    assert result.narrative == chain.narrative


async def test_llm_exception_falls_back_to_template(monkeypatch: pytest.MonkeyPatch) -> None:
    """超时、限流、解码失败都从这里走 —— **不能把一次评估弄挂**。"""

    def boom(_chain: Any) -> Any:
        raise TimeoutError("模型超时")

    chain = _demo_chain()
    _install_fake_llm(monkeypatch, boom)

    result = await narrate_chain(chain)

    assert result.narrative_source == "template"
    assert result.narrative == chain.narrative
    assert result.nodes == chain.nodes


async def test_missing_llm_module_falls_back_to_template(monkeypatch: pytest.MonkeyPatch) -> None:
    """B6 没落地 / 模块被改名 → `ImportError` → 模板。用 `sys.modules[...] = None`
    制造"这个模块不存在"，比真的去删文件干净。"""
    chain = _demo_chain()
    monkeypatch.setitem(sys.modules, "app.llm.expressions", None)

    result = await narrate_chain(chain)

    assert result.narrative_source == "template"
    assert result.narrative == chain.narrative


async def test_a_chain_without_template_text_still_degrades_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """模型给不出东西、模板又是空的 → 空字符串，不抛异常。"""
    chain = _demo_chain().model_copy(update={"narrative": ""})
    monkeypatch.setitem(sys.modules, "app.llm.expressions", None)

    result = await narrate_chain(chain)

    assert result.narrative == ""
    assert result.narrative_source == "template"


# ---------------------------------------------------------------------------
# 整批
# ---------------------------------------------------------------------------


async def test_narrate_draft_narrates_every_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    draft = build_chain(_findings())
    assert len(draft.chains) >= 1
    _install_fake_llm(monkeypatch, lambda c: _Result(f"{c.chain_id} 的叙事"))

    result = await narrate_draft(draft)

    assert state_calls(result, draft)  # 逐链都调过一次
    for chain in result.chains:
        assert chain.narrative_source == "llm"
    assert [c.chain_id for c in result.chains] == [c.chain_id for c in draft.chains]


def state_calls(narrated: Any, original: Any) -> bool:
    """每条链都拿到了自己的那一份叙事（而不是共用最后一条）。"""
    return all(chain.narrative.endswith("的叙事") for chain in narrated.chains) and len(
        narrated.chains
    ) == len(original.chains)


async def test_one_bad_chain_does_not_affect_the_others(monkeypatch: pytest.MonkeyPatch) -> None:
    """逐链处理：第 2 条被拒收，不该把第 1 条也拖回模板。"""
    # 反序列化没有对应的规则（见 test_chain_rules 里的分歧记录），
    # 于是它落成一条独立的单节点链 —— 正好用来验证"一条坏不影响另一条"。
    findings = [*_findings(), _Finding(9, "deserialization", file_path="app/api/data.py")]
    draft = build_chain(findings)
    assert len(draft.chains) >= 2, "这个场景要能推出多条链"

    bad_id = draft.chains[1].chain_id

    def behaviour(chain: AttackChain) -> _Result:
        if chain.chain_id == bad_id:
            return _Result("顺手提到 VULN-2026-0099")
        return _Result(f"{chain.chain_id} 的叙事")

    _install_fake_llm(monkeypatch, behaviour)

    result = await narrate_draft(draft)

    assert result.chains[0].narrative_source == "llm"
    assert result.chains[1].narrative_source == "template"
    assert result.chains[1].narrative == draft.chains[1].narrative


async def test_narrate_draft_without_chains_is_a_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    draft = build_chain([])
    state = _install_fake_llm(monkeypatch, lambda _c: _Result("不该被调用"))

    result = await narrate_draft(draft)

    assert result.chains == []
    assert state["calls"] == 0


async def test_build_chain_narrated_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    """契约 4 的入口 + 叙事：推演仍是确定性的那份，只有文案来自模型。"""
    _install_fake_llm(monkeypatch, lambda c: _Result(f"叙事：{c.entry_point}"))

    narrated = await build_chain_narrated(_findings())
    plain = build_chain(_findings())

    assert [c.chain_id for c in narrated.chains] == [c.chain_id for c in plain.chains]
    assert [c.rule_ids for c in narrated.chains] == [c.rule_ids for c in plain.chains]
    assert narrated.chains[0].narrative_source == "llm"


async def test_build_chain_narrated_accepts_builder_kwargs(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_llm(monkeypatch, lambda c: _Result(f"叙事：{c.chain_id}"))

    narrated = await build_chain_narrated(_findings(), max_chains=1)

    assert len(narrated.chains) == 1
