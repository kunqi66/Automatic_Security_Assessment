"""CVSS 3.1 基础分：**拿官方已知向量验公式**（设计文档 §8 的验收项）。

这一份测试的证据强度和本目录其它测试**不一样**，值得说清楚：

- 污点传播的测试只能证明「在我挑的样例上结论符合预期」——换一份代码就未必；
- 这里每一条断言都来自 **CVSS 3.1 官方规范 / NVD 公布的向量与分值**，
  是「同一个输入在全世界任何实现里都必须等于同一个数」的硬约束。

所以这一节一旦挂了，就不该去调断言，而应当去查公式。这也正是 L1
在 B4 里最结实的一块：分数不是「算得挺像」，是可复算、可被第三方复现的。
"""

from __future__ import annotations

import pytest

from app.analysis.cvss import (
    VECTOR_PREFIX,
    base_score,
    parse_vector,
    roundup,
    score_for,
    severity_of,
    vector_for,
)
from app.analysis.types import VulnType
from app.models.enums import Severity

#: `(向量, 官方基础分)` —— 全部取自 CVSS 3.1 规范示例与 NVD 上的实际条目。
#:
#: 向量覆盖面刻意拉开：作用域变更（S:C）、需要交互（UI:R）、需要认证（PR:L/H）、
#: 本地可达（AV:L）、物理可达（AV:P）、以及零影响（I/A/C 全 N）。
#: 只验几个高危远程向量的话，公式里好几个系数根本没被走到。
OFFICIAL_VECTORS: tuple[tuple[str, float], ...] = (
    # 远程 + 无需认证 + 全影响：9.8，最常见的「未认证 RCE」
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    # 作用域变更 + 需要交互：6.1（反射型 XSS 的经典向量）
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    # 只读型信息泄露：7.5
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    # 零影响：规范明确 0.0
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    # 作用域变更 + 全影响：10.0（Log4Shell 型）
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    # 本地 + 低权限：7.8（提权型）
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    # 高复杂度：5.9（AC:H 系数）
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    # 物理可达：6.8（AV:P 系数）
    ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 6.8),
    # 需要认证的全影响：8.8（后台 RCE）
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    # 高复杂度 + 全影响：8.1
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
    # 高权限：7.2（PR:H 系数）
    ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),
    # 低影响三连：5.3
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
)


@pytest.mark.parametrize(("vector", "expected"), OFFICIAL_VECTORS)
def test_official_vectors_match_official_scores(vector: str, expected: float) -> None:
    assert base_score(vector) == pytest.approx(expected)


def test_vector_with_or_without_version_prefix_is_equivalent() -> None:
    """带不带 `CVSS:3.1/` 前缀必须算同一个分。

    官方公布的向量一律带前缀，而内部表里只存指标段；两种形态都要能直接算，
    否则「照抄 NVD 页面上的向量来核对」就成了要先手工裁剪字符串的活。
    """
    vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert base_score(vector) == base_score(VECTOR_PREFIX + vector) == 9.8


def test_missing_metric_fails_loudly() -> None:
    """向量不完整必须抛错，不能默认补一个值。

    默认补值会让一个被改坏的规则表继续产出「看起来正常」的分数 ——
    分数错了还能被人工复核发现，静默错着就没人会发现。
    """
    with pytest.raises(ValueError, match="缺少必需指标"):
        base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")
    with pytest.raises(ValueError):
        parse_vector("AVN/AC:L")


def test_roundup_keeps_exact_decimals() -> None:
    """Roundup 只对「多出的余数」进位。

    `8.6` 在二进制浮点里是 `8.5999999999999996`，用
    `math.ceil(x * 10) / 10` 会把它顶成 `8.7` —— 官方规范为此专门定义了
    整数版 Roundup，这里验的就是那个实现。
    """
    assert roundup(8.6) == pytest.approx(8.6)
    assert roundup(4.0) == pytest.approx(4.0)
    assert roundup(6.401) == pytest.approx(6.5)
    assert roundup(0.0) == pytest.approx(0.0)


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (10.0, Severity.CRITICAL),
        (9.0, Severity.CRITICAL),
        (8.9, Severity.HIGH),
        (7.0, Severity.HIGH),
        (6.9, Severity.MEDIUM),
        (4.0, Severity.MEDIUM),
        (3.9, Severity.LOW),
        (0.1, Severity.LOW),
    ],
)
def test_severity_bands(score: float, expected: Severity) -> None:
    assert severity_of(score) is expected


def test_every_vuln_type_has_a_vector_and_a_score() -> None:
    """每个漏洞类型都要有向量 —— 新增规则时最容易漏的一步。

    漏了模板会在 `score_for` 里 `KeyError`，所以这里同时验「表是完整的」
    与「分数落在合法区间内」。
    """
    for vuln_type in VulnType:
        vector = vector_for(vuln_type)
        score = base_score(vector)
        assert 0.0 <= score <= 10.0, (vuln_type, vector, score)
        assert set(parse_vector(vector)) == {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}


def test_score_for_returns_standard_prefixed_vector() -> None:
    """`score_for` 出口的向量必须是 `CVSS:3.1/...`（NVD 标准形式）。"""
    vector, score, severity = score_for(VulnType.SQL_INJECTION)
    assert vector == VECTOR_PREFIX + vector_for(VulnType.SQL_INJECTION)
    assert score == pytest.approx(9.1)
    assert severity is Severity.CRITICAL


def test_requires_auth_only_touches_pr() -> None:
    """「需要认证」只改 PR 一个分量。

    只改一个字母是刻意的：报告里两条 Finding 的分数差异要能一眼归因到
    「这条需要先登录」，而不是一整套指标都变了、只能整体重算。
    """
    anonymous = vector_for(VulnType.SQL_INJECTION)
    authenticated = vector_for(VulnType.SQL_INJECTION, requires_auth=True)
    assert authenticated.replace("PR:L", "PR:N") == anonymous
    assert base_score(authenticated) < base_score(anonymous)


def test_not_remote_only_touches_av() -> None:
    remote = vector_for(VulnType.COMMAND_INJECTION)
    local = vector_for(VulnType.COMMAND_INJECTION, remote=False)
    assert local.replace("AV:L", "AV:N") == remote
    assert base_score(local) < base_score(remote)


def test_requiring_auth_never_raises_the_score() -> None:
    """单调性：可达性变差，分数不可能升高（对所有漏洞类型成立）。"""
    for vuln_type in VulnType:
        anonymous = base_score(vector_for(vuln_type))
        authenticated = base_score(vector_for(vuln_type, requires_auth=True))
        non_remote = base_score(vector_for(vuln_type, remote=False))
        assert authenticated <= anonymous, vuln_type
        assert non_remote <= anonymous, vuln_type


def test_scoring_is_pure() -> None:
    """同样的入参，调用多少次都是同一个结果（无缓存、无隐藏状态）。"""
    first = score_for(VulnType.XSS)
    second = score_for(VulnType.XSS)
    assert first == second
