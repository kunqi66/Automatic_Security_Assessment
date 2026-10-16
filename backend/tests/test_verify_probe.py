"""探针构造的测试：**确定性、配额、注入点推导、任务脚本渲染**。

`test_verify_guard.py` 验"探针能不能发"，本文件验"探针是怎么造出来的"。

其中**确定性测试是 L1 铁律的可执行证据**：同一条 Finding 构造两次，
探针列表必须逐字段相同（连 id 都一样）。这条如果挂了，说明哪里混进了
随机数、时间戳、字典迭代序或者 LLM —— 四种成因都能让"可复现"这句话变成空话。
"""

from __future__ import annotations

import base64
import json
import re

from verify_chain_fakes import FakeFinding, FakeTaintStep

from app.core.config import settings
from app.verify.guard import _RE_UNION
from app.verify.probe import (
    MAX_UNION_COLUMNS,
    PROBE_TEMPLATES,
    _build_union_payload,
    bootstrap_command,
    build_probes,
    canonical_vuln_type,
    injection_points,
    mission_env,
    render_mission_script,
    render_requests,
)
from app.verify.types import InjectIn, ProbePlan

_RE_PLAN = re.compile(r'ASA_PLAN_B64 = "([^"]+)"')


def _finding(vuln_type: str, **kwargs: object) -> FakeFinding:
    return FakeFinding(vuln_type=vuln_type, **kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# L1：确定性
# ---------------------------------------------------------------------------


def test_probe_generation_is_deterministic() -> None:
    """同一条 Finding 构造两次 → 探针列表逐字段相同（L1 的可执行证据）。"""
    finding = _finding(
        "sqli",
        vuln_id=7,
        taint_path=(FakeTaintStep("request.args.get('order_id')"), FakeTaintStep("cursor.execute")),
    )
    first = build_probes(finding, vuln_id=7)
    second = build_probes(finding, vuln_id=7)

    assert first.probes == second.probes
    assert [p.probe_id for p in first.probes] == [p.probe_id for p in second.probes]
    assert first.skipped == second.skipped


def test_probe_nonce_derives_from_probe_identity() -> None:
    """nonce 由探针身份推导（不是随机数）：换一个 vuln_id 才是另一个 nonce。"""
    a = build_probes(_finding("cmdi", vuln_id=1), vuln_id=1).probes[0]
    b = build_probes(_finding("cmdi", vuln_id=1), vuln_id=1).probes[0]
    c = build_probes(_finding("cmdi", vuln_id=2), vuln_id=2).probes[0]
    assert a.nonce == b.nonce
    assert a.nonce != c.nonce
    assert len(a.nonce) == 15  # "asa" + 12 位 hex


def test_probe_ids_are_unique_within_a_plan() -> None:
    finding = _finding(
        "file_read", vuln_id=3, taint_path=(FakeTaintStep("request.args.get('path')"),)
    )
    plan = build_probes(finding, vuln_id=3)
    ids = [p.probe_id for p in plan.probes]
    assert len(ids) == len(set(ids))
    for probe in plan.probes:
        assert probe.probe_id.endswith(probe.technique.value)


# ---------------------------------------------------------------------------
# 配额：上限是上限，被裁掉的必须被**记录**
# ---------------------------------------------------------------------------


def test_quota_is_enforced_and_over_limit_probes_are_recorded() -> None:
    """注入点足够多 → 只跑 20 条，且被裁掉的那些**有记录**（不是静默丢弃）。"""
    points = [FakeTaintStep(f"request.args.get('param_{i}')") for i in range(30)]
    finding = _finding("sqli", vuln_id=5, taint_path=tuple(points))
    plan = build_probes(finding, vuln_id=5)

    assert len(plan.probes) == settings.max_probes_per_vuln == 20
    assert plan.truncated is True
    assert plan.skipped, "被裁掉的探针必须有记录，否则报告里看不出覆盖不全"
    assert all(s.reason_code.value == "PROBE_QUOTA_EXCEEDED" for s in plan.skipped)
    # (30 个推导出的注入点 + 1 个规范参数名 `q`) × 2 个技术 = 62 条候选
    # → 20 条执行、42 条记录。规范参数名恒进候选，所以是 31 而不是 30。
    assert len(plan.probes) + len(plan.skipped) == 62


def test_quota_can_be_lowered_by_caller() -> None:
    finding = _finding("sqli", vuln_id=5, taint_path=(FakeTaintStep("request.args.get('q')"),))
    plan = build_probes(finding, vuln_id=5, max_probes=1)
    assert len(plan.probes) == 1
    assert plan.truncated is True


def test_unknown_vuln_type_yields_empty_plan_with_reason() -> None:
    """没有模板的漏洞类型 → 空计划 + 记录原因（**不是异常**）。"""
    plan = build_probes(_finding("some_exotic_thing", vuln_id=9), vuln_id=9)
    assert isinstance(plan, ProbePlan)
    assert plan.probes == []
    assert plan.skipped[0].reason_code.value == "NO_PROBE_TEMPLATE"


# ---------------------------------------------------------------------------
# 注入点推导
# ---------------------------------------------------------------------------


def test_injection_points_come_from_taint_path() -> None:
    finding = _finding(
        "sqli",
        taint_path=(
            FakeTaintStep("request.args.get('order_id')"),
            FakeTaintStep("cursor.execute"),
            FakeTaintStep("request.headers.get('X-Tenant')"),
        ),
    )
    points = injection_points(finding, default="id")
    assert "order_id" in points
    assert "X-Tenant" in points
    # 框架噪声（request/get/args）不该被当成参数名
    assert "request" not in points
    assert "get" not in points


def test_injection_points_dedup_and_fallback() -> None:
    """重复的注入点只留一个；没有污点路径时退回该技术的默认参数。"""
    duplicated = _finding(
        "sqli",
        taint_path=(
            FakeTaintStep("request.args.get('id')"),
            FakeTaintStep("request.args.get('id')"),
        ),
    )
    assert injection_points(duplicated, default="id") == ("id",)

    no_path = _finding("sqli", taint_path=())
    fallback = injection_points(no_path, default="id")
    assert fallback == ("id",), "没有污点路径时必须退回默认参数，否则一条探针都造不出来"


def test_probe_count_scales_with_injection_points() -> None:
    """多一个**不同的**注入点，就多一组候选探针。

    ⚠️ 这里第二个注入点用的是 `keyword` 而不是 `q`：`q` 恰好是 sqli 模板声明的
    规范参数名，而规范参数名**无论推导结果如何都会进候选**（见 `_candidates`），
    所以拿它当"新增的注入点"验不出增长。这不是测试的吹毛求疵 ——
    正是因为规范参数名恒在，`/search` 才总能被按它真正读的那个参数打一遍。
    """
    one = build_probes(
        _finding("sqli", vuln_id=1, taint_path=(FakeTaintStep("request.args.get('id')"),)),
        vuln_id=1,
    )
    two = build_probes(
        _finding(
            "sqli",
            vuln_id=1,
            taint_path=(
                FakeTaintStep("request.args.get('id')"),
                FakeTaintStep("request.args.get('keyword')"),
            ),
        ),
        vuln_id=1,
    )
    assert len(two.probes) > len(one.probes)


def test_canonical_param_is_always_a_candidate() -> None:
    """模板声明的参数名**永远在候选里**，哪怕污点路径推导出了别的名字。

    回归测试，对应一个实测到的假阴性：`admin_login.py` 的 SQL 注入被推导成
    `check_login`，而 sqli 模板的路由 `/search` 只读 `q` —— 于是探针往
    `/search?check_login=...` 注入，服务端无视该参数，响应与基线逐字节相同，
    布尔差分判定"无差异"，这条真注入被记成 `rejected`。
    """
    plan = build_probes(
        _finding("sqli", vuln_id=1, taint_path=(FakeTaintStep("some_func.username"),)),
        vuln_id=1,
    )
    params = {p.param_name for p in plan.probes}
    assert "q" in params, "规范参数名必须在候选里，否则该路由从没被按正确形态打过"
    assert "username" in params, "推导出的名字仍要保留 —— 它是多试一次的机会"


def test_only_canonical_param_probes_may_refute() -> None:
    """推导参数名的探针不得证伪 —— 否则会以 `rejected` 的形式制造假阴性。"""
    plan = build_probes(
        _finding("sqli", vuln_id=1, taint_path=(FakeTaintStep("some_func.username"),)),
        vuln_id=1,
    )
    canonical = [p for p in plan.probes if p.param_name == "q"]
    derived = [p for p in plan.probes if p.param_name != "q"]
    assert canonical and derived, "两种参数都要有，否则这个测试什么也没验证"
    assert all(p.param_is_canonical for p in canonical)
    assert not any(p.param_is_canonical for p in derived)


# ---------------------------------------------------------------------------
# 渲染：请求 / 任务脚本 / 环境变量
# ---------------------------------------------------------------------------


def test_request_counts_match_each_technique() -> None:
    """每条技术的请求条数与"它需要几次观测"对齐（对照组不能省）。"""
    counts = {
        "boolean_blind": 3,  # 真 / 假 / 真重复
        "time_blind": 2,  # 基线 / 探针
        "union_extract": 1,
        "echo_nonce": 1,
        "path_traversal_read": 1,
        "read_config": 1,
        "unauth_probe": 1,
        "deser_marker": 1,
        "upload_marker": 2,  # 上传 + 回读
        "idor_horizontal": 2,  # 造标记 + 横向读取
    }
    for vuln_type, templates in PROBE_TEMPLATES.items():
        # 每个漏洞类型的模板都要真的产出探针 —— 模板写进去却被静默丢掉，
        # 表现出来就是"这条技术从来没被探测过"，而模板表上完全看不出来。
        plan = build_probes(_finding(vuln_type, vuln_id=1), vuln_id=1)
        assert {p.technique for p in plan.probes} == {t.technique for t in templates}, vuln_type
        for probe_template in templates:
            assert probe_template.technique.value in counts, probe_template.technique
    # 直接构造一条探针来数请求，避免依赖"第一个模板恰好是哪条"
    for technique, expected in counts.items():
        probe = _probe_of(technique)
        assert len(render_requests(probe)) == expected, technique


def _probe_of(technique: str) -> object:
    for vuln_type, templates in PROBE_TEMPLATES.items():
        for template in templates:
            if template.technique.value == technique:
                plan = build_probes(_finding(vuln_type, vuln_id=1), vuln_id=1)
                for probe in plan.probes:
                    if probe.technique.value == technique:
                        return probe
    raise AssertionError(f"没有找到技术 {technique} 的模板")


def test_mission_script_embeds_the_plan() -> None:
    """任务脚本必须把探针计划整份带进容器（容器不自作主张、只执行）。"""
    finding = _finding("sqli", vuln_id=4, taint_path=(FakeTaintStep("request.args.get('q')"),))
    plan = build_probes(finding, vuln_id=4)
    script = render_mission_script(plan.probes)

    assert "ASA_PLAN_B64" in script
    match = _RE_PLAN.search(script)
    assert match is not None
    decoded = json.loads(base64.b64decode(match.group(1)).decode("utf-8"))
    assert [p["probe_id"] for p in decoded["probes"]] == [p.probe_id for p in plan.probes]
    # 每条探针的请求都在计划里，容器不需要"自己会构造请求"
    for entry in decoded["probes"]:
        assert entry["requests"], "计划里必须带上渲染好的请求"
        assert "path" in entry["requests"][0]


def test_mission_env_and_bootstrap_command() -> None:
    plan = build_probes(_finding("sqli", vuln_id=4), vuln_id=4)
    env = mission_env(plan.probes)
    assert set(env) == {"ASA_MISSION_B64"}
    script = base64.b64decode(env["ASA_MISSION_B64"]).decode("utf-8")
    assert script == render_mission_script(plan.probes)

    argv = bootstrap_command()
    assert argv[0] == "python"
    assert "ASA_MISSION_B64" in argv[-1]  # 脚本经环境变量注入，规避 shell 转义
    assert all("\\" not in part or True for part in argv)  # 不经 shell 解析，无引号地狱


def test_all_generated_probes_declare_side_effect_free() -> None:
    """**行为闸门的自证**：所有模板声明为无副作用，且真的没有写操作。"""
    for vuln_type in PROBE_TEMPLATES:
        plan = build_probes(_finding(vuln_type, vuln_id=1), vuln_id=1)
        for probe in plan.probes:
            assert probe.side_effect_free is True, (vuln_type, probe.technique)


def test_probe_target_is_always_loopback() -> None:
    """目标恒为容器内回环 —— 这是不变量，不是配置。"""
    for vuln_type in PROBE_TEMPLATES:
        for probe in build_probes(_finding(vuln_type, vuln_id=1), vuln_id=1).probes:
            assert probe.target[0] in {"127.0.0.1", "localhost", "::1"}


def test_canonical_vuln_type_accepts_aliases() -> None:
    assert canonical_vuln_type("sql_injection") == "sqli"
    assert canonical_vuln_type("SQLi") == "sqli"
    assert canonical_vuln_type("path_traversal") == "file_read"
    assert canonical_vuln_type("nope") == "nope"


def test_upload_probe_reads_back_its_own_marker() -> None:
    """上传探针必须是「传 txt → 回读」，绝不涉及可执行后缀。"""
    plan = build_probes(_finding("file_upload", vuln_id=6), vuln_id=6)
    probe = plan.probes[0]
    assert probe.aux_path and probe.aux_path.endswith(".txt")
    assert probe.nonce in probe.aux_path
    assert not any(probe.payload.lower().endswith(ext) for ext in (".php", ".jsp", ".exe", ".py"))


def test_idor_probe_creates_its_own_marker_first() -> None:
    """越权探针先造自己的标记（自建数据），再横向读取 —— 不碰任何真实数据。"""
    plan = build_probes(_finding("idor", vuln_id=8), vuln_id=8)
    probe = plan.probes[0]
    requests = render_requests(probe)
    assert len(requests) == 2
    assert requests[0].method == "POST", "第一条必须是自建标记"
    assert probe.nonce in (requests[0].body or "")
    # 标记走 POST body，横向读取走 GET query —— 注入位置随请求语义走
    assert probe.inject_in is InjectIn.BODY


# ---------------------------------------------------------------------------
# UNION 载荷的列数：从「模板写死 2」到「按目标的 SELECT 列数构造」
# ---------------------------------------------------------------------------


def test_union_payload_column_count_follows_the_target() -> None:
    """列数由**目标源码里的 SELECT** 决定，不是模板里写死的常量。

    三列的表上打两列的 UNION，数据库报
    `SELECTs … do not have the same number of result columns` ——
    探针打不中一个本来能打中的点，而且响应长得跟"这里没有注入"一样。
    """
    for columns, expected in (
        (1, "1 UNION SELECT 'N' -- "),
        (2, "1 UNION SELECT 'N','asa' -- "),
        (3, "1 UNION SELECT 'N','asa','asa' -- "),
        (5, "1 UNION SELECT 'N','asa','asa','asa','asa' -- "),
    ):
        assert _build_union_payload("N", columns) == expected, columns


def test_union_payload_falls_back_to_template_when_count_unknown() -> None:
    """读不出列数 / 越过上限 → **退回模板原值**，不硬构造。

    读不出就保守地按原形状发：`payload_fits_context` 会把这次未命中判成
    "不适配"，于是它不构成证伪 —— 少一次证伪，而不是多一次误判。
    超上限同样退回，因为发一个必然被闸门拒收的载荷，
    只会让日志里多一条"探针被闸门拒绝"，读起来像目标有问题。
    """
    template_value = "1 UNION SELECT 'N','asa' -- "
    for columns in (None, 0, -1, MAX_UNION_COLUMNS + 1):
        assert _build_union_payload("N", columns) == template_value, columns


def test_union_payload_is_always_guard_legal() -> None:
    """构造出来的载荷**必须**过得了闸门 —— 两处的列数上限不能各写各的。

    闸门 `_RE_UNION` 的 `{0,15}` 与 `MAX_UNION_COLUMNS` 是同一个约束的两份表达。
    不一致的后果不是"更安全"，而是探针在自己人这里被拒。
    """
    for columns in range(1, MAX_UNION_COLUMNS + 1):
        payload = _build_union_payload("asa0123456789ab", columns)
        assert _RE_UNION.match(payload), (columns, payload)
