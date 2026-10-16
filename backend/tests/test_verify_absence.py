"""证伪判据的测试：**什么时候系统才有资格说"这个漏洞不存在"**。

`can_conclude_absence` 是 `rejected` 在整个系统里的**唯一入口**（`runner.py`
只有它这一个调用点）。它此前**一条测试都没有** —— 而它恰恰是本系统能下的
最重结论：`rejected` 说的是"静态分析误报了"，不是"这次没验出来"。

## 为什么单独一个文件

因为这里要钉住的是一条**实测出来的假阴性**，不是构造出来的边界条件：

    vuln 18  sql_injection  app.py:114      → 探针用 ?q=        → verified
    vuln 16  sql_injection  admin_login.py  → 探针用 ?username=  → rejected

两条都是真注入。区别只在参数名是从污点路径推导的、还是模板声明的。
`/search` 只读 `q`，`?username=` 被 Flask 直接忽略，响应体与基线逐字节相同；
SQL 注入的布尔差分判据忠实报告"无差异"；runner 忠实写下 `rejected`。
**三个环节每步都对，结论是错的** —— 这正是这类缺陷难被发现的原因：
它不报错，不崩溃，只是安静地把「没测到」写成「不存在」。

所以本文件的存在理由与 `test_verify_guard.py` 同级：
**系统说"不存在"的资格，必须有测试守着。**
"""

from __future__ import annotations

import pytest

from app.verify.fingerprints import can_conclude_absence
from app.verify.types import (
    ExpectedKind,
    MatchResult,
    Probe,
    ProbeResponse,
    Technique,
)


def _probe(**overrides: object) -> Probe:
    base: dict[str, object] = {
        "probe_id": "P0001-00-boolean_blind",
        "vuln_id": 1,
        "technique": Technique.BOOLEAN_BLIND,
        "payload": "1 AND 1=1",
        "method": "GET",
        "url_path": "/search",
        "param_name": "q",
        "param_is_canonical": True,
        # 布尔差分带对照组 —— 单看判据，它的"未命中"是有否证力的
        "expected_kind": ExpectedKind.BOOLEAN_DIFFERENTIAL,
    }
    base.update(overrides)
    return Probe(**base)  # type: ignore[arg-type]


def _response(**overrides: object) -> ProbeResponse:
    base: dict[str, object] = {
        "probe_id": "P0001-00-boolean_blind",
        "executed": True,
        "http_status": 200,
        "response_raw": "HTTP/1.1 200 OK\n\n<html>商品页</html>",
    }
    base.update(overrides)
    return ProbeResponse(**base)  # type: ignore[arg-type]


_MISS = MatchResult(matched=False, observed="", reason="长度相同")


# ---------------------------------------------------------------------------
# 正例：规范形态打穿了，才有资格说"不存在"
# ---------------------------------------------------------------------------


def test_canonical_conclusive_probe_can_refute() -> None:
    """规范参数 + 对照组判据 + 请求被正常处理 → 具备否证力。"""
    evidence = can_conclude_absence(_probe(), _response(), _MISS)
    assert evidence.conclusive is True
    assert evidence.reason


# ---------------------------------------------------------------------------
# 🔴 回归：推导来的参数名**不得**证伪
# ---------------------------------------------------------------------------


def test_derived_param_probe_cannot_refute() -> None:
    """参数名是推导出来的 → 未命中不构成证伪。

    这就是上面那两条 vuln 的成因：`?username=` 打给只读 `q` 的 `/search`，
    服务端没读过这个载荷，响应当然与基线一样。**"没被读过"不是"不可注入"。**
    """
    derived = _probe(param_name="username", param_is_canonical=False)
    evidence = can_conclude_absence(derived, _response(), _MISS)
    assert evidence.conclusive is False
    assert "证伪" in evidence.reason or "否证" in evidence.reason


def test_derived_param_is_the_only_difference() -> None:
    """对照组：除参数名外逐字段相同，结论必须相反。

    这条是上面两条测试的**互证** —— 若两条都通过而结论相同，说明判据根本没看
    `param_is_canonical`，那前一条测试就是"因为错误的原因而通过"。
    """
    canonical = _probe(param_name="q", param_is_canonical=True)
    derived = _probe(param_name="q", param_is_canonical=False)
    assert canonical.model_dump(exclude={"param_is_canonical"}) == derived.model_dump(
        exclude={"param_is_canonical"}
    ), "两条探针必须只差 param_is_canonical 这一个字段"
    assert can_conclude_absence(canonical, _response(), _MISS).conclusive is True
    assert can_conclude_absence(derived, _response(), _MISS).conclusive is False


# ---------------------------------------------------------------------------
# 反例：连规范形态也谈不上证伪的几种情况
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "response", "why"),
    [
        (
            "未取得响应",
            _response(http_status=None, error="connection refused"),
            "连接被拒只说明这里没有那个端点，不说明不可注入",
        ),
        (
            "4xx",
            _response(http_status=404),
            "404 说明请求没被正常处理，不是'打穿了没反应'",
        ),
        (
            "5xx",
            _response(http_status=500),
            "5xx 说明请求没被正常处理",
        ),
        (
            "没执行完",
            _response(executed=False, http_status=None),
            "探针没跑完，没有事实可依据",
        ),
    ],
)
def test_non_2xx_cannot_refute(name: str, response: ProbeResponse, why: str) -> None:
    evidence = can_conclude_absence(_probe(), response, _MISS)
    assert evidence.conclusive is False, f"{name}：{why}"


def test_weak_judgement_cannot_refute() -> None:
    """判据本身没有否证力（如"响应里该出现 nonce 而没出现"）→ 不得证伪。

    只读探针天然有覆盖盲区：触发不了"写才发作"的漏洞。没看到痕迹，
    与"痕迹不存在"是两件事。
    """
    weak = _probe(technique=Technique.ECHO_NONCE, expected_kind=ExpectedKind.CONTENT_NONCE)
    evidence = can_conclude_absence(weak, _response(), _MISS)
    assert evidence.conclusive is False


def test_matched_probe_never_refutes() -> None:
    """命中了就谈不上证伪 —— 这一条是防止调用方把正负证据接反。"""
    matched = MatchResult(matched=True, observed="nonce 出现", reason="命中")
    assert can_conclude_absence(_probe(), _response(), matched).conclusive is False
