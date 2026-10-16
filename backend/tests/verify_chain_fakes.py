"""B5 的测试替身：假沙箱 + 假靶场响应 + 假 Finding。

## 为什么假沙箱要**真的把任务脚本解出来**

`FakeSandbox` 拿到 `ContainerSpec` 后，会从 `ASA_MISSION_B64` 里把容器任务脚本
与其中的探针计划（`ASA_PLAN_B64`）**真正解出来**，再按计划里的每一条请求
合成一次响应。也就是说，测试跑的是"探针真的被发出去过"那条路径：
探针 id、请求条数、注入位置、nonce 全部来自被测代码自己渲染的产物，
测试只负责扮演"靶场会怎么答"。

如果这里改成"测试自己编一批 probe_id 塞回去"，那么探针计划渲染错了、
少发了一条请求、nonce 没进载荷 —— 这些错误**测试一个都发现不了**，
因为回给被测代码的那份证据是测试自己造的。

## 绝不连真 Docker

`FakeSandbox` 满足契约 1 的 `Sandbox` 协议（`run_once` / `stats`），
不 import `app.sandbox.service`，也不碰任何 socket。
"""

from __future__ import annotations

import ast
import base64
import json
import re
from pathlib import Path
from typing import Any

from app.sandbox.ports import ExecResult
from app.verify.probe import canonical_vuln_type

#: 夹具源码里两个锚点的行号 —— **当场从文件里数出来，不写死**。
#:
#: 原先这里是硬编码的 20 / 22，结果给夹具补一行注释就让 sink 挪到了 24，
#: 绑定静默失配、runner 测试集体走"未绑定"那一支。行号本来就是**从源码推出**的
#: （分析器交给 finding 的也是行号），测试里就不该由人手维护。
_BINDABLE_APP = Path(__file__).parent / "fixtures" / "bindable_app" / "app.py"


def _dotted(node: ast.AST) -> str:
    """`request.args.get` 这样的点号全名；认不出来就返回空串。"""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _fixture_line(dotted_name: str) -> int:
    """按 **AST** 找 `dotted_name(...)` 调用的行号。

    ⚠️ 不能按文本找：夹具自己的 docstring 里就写着 `request.args.get("q")`，
    一行 `"..." in text` 会直接命中那行说明文字（本函数的第一版就是这么错的）。
    """
    tree = ast.parse(_BINDABLE_APP.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _dotted(node.func) == dotted_name:
            return node.lineno
    raise AssertionError(f"夹具 {_BINDABLE_APP} 里找不到 {dotted_name}() 调用：夹具被改动了？")


BINDABLE_SOURCE_LINE = _fixture_line("request.args.get")
BINDABLE_SINK_LINE = _fixture_line("cursor.execute")

_EVIDENCE_PREFIX = "ASA-EVIDENCE "
_RE_PLAN = re.compile(r'ASA_PLAN_B64 = "([^"]+)"')

#: 假靶场里"存在漏洞"的技术 → 它的响应长什么样。
#:
#: 键是**技术名**而不是漏洞类型：一次探测能不能命中，取决于靶场对这条技术的
#: 反应，而不是静态分析给它贴的标签。
_VULNERABLE_BODIES: dict[str, str] = {
    # 路径穿越 / 配置探测：锚点是**固定内容**，不是 nonce（见 types.FIXED_ANCHOR_TECHNIQUES）
    "path_traversal_read": (
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    ),
    "read_config": "APP_ENV=production\nSECRET_KEY=asa-demo-secret\nDB_PASSWORD=hunter2\n",
}

#: 漏洞已确认时，`unauth_probe` 该看到的业务 JSON
_UNAUTH_JSON = '{"code": 0, "data": [{"id": 1, "name": "admin"}]}'


class FakeFinding:
    """B4 `Finding` / B3 `FindingRef` 的最小可用替身。

    字段名照抄契约 2（`vuln_type` / `file_path` / `line_start` / `line_end` /
    `symbol` / `cvss_score`）。`status` 默认 `None` —— **和 B4 的 Finding 一样**：
    落库之前它压根没有这个字段。
    """

    def __init__(
        self,
        *,
        vuln_id: int = 1,
        vuln_type: str = "sql_injection",
        file_path: str = "app/api/order.py",
        line_start: int = 30,
        line_end: int = 32,
        symbol: str = "cursor.execute",
        cvss_score: float = 7.5,
        code: str | None = None,
        status: Any = None,
        taint_path: tuple[Any, ...] = (),
    ) -> None:
        self.vuln_id = vuln_id
        self.vuln_type = vuln_type
        self.file_path = file_path
        self.line_start = line_start
        self.line_end = line_end
        self.symbol = symbol
        self.cvss_score = cvss_score
        self.code = code if code is not None else f"VULN-2026-{vuln_id:04d}"
        self.status = status
        self.taint_path = taint_path

    @property
    def sink_symbol(self) -> str:
        return self.symbol


class FakeTaintStep:
    """`TaintStep` 的替身（探针注入点从它推导出来）。

    ⚠️ `file_path` / `line` 不是装饰性的：`verify.routes.bind_route` 靠它们回到
    源码里反查端点。少了 `file_path`，绑定**永远失败**，于是所有走 `FakeHandle`
    的用例都落进"未绑定 → potential"那一支 —— 那会让 runner 测试集体变绿
    却什么也没测到。默认值指向 `tests/fixtures/bindable_app/app.py` 的对应行。
    """

    def __init__(
        self,
        symbol: str,
        *,
        step_kind: str = "source",
        line: int = BINDABLE_SOURCE_LINE,
        file_path: str = "app.py",
    ) -> None:
        self.symbol = symbol
        self.step_kind = step_kind
        self.line = line
        self.file_path = file_path


class FakeHandle:
    """B1 `WorkspaceHandle` 的本模块视图（契约 5）。

    两个路径**是两个世界的路径**：`src_root` 在控制面本机，`mount_host_path`
    在 ECS 宿主侧。补丁干跑必须用前者，容器挂载必须用后者 —— 测试里把它们
    设成互不相同的值，就是为了让"用错了那个"立刻炸出来。
    """

    def __init__(
        self,
        *,
        project_id: int = 1,
        src_root: Any = None,
        mount_host_path: str = "/data/asa/projects/1/src",
    ) -> None:
        self.project_id = project_id
        self.src_root = src_root
        self.mount_host_path = mount_host_path


class FakeSandbox:
    """契约 1 `Sandbox` 协议的测试替身。**不连 Docker。**"""

    def __init__(
        self,
        *,
        vulnerable: set[str] | None = None,
        fail_times: int = 0,
        ready: bool = True,
        exit_code: int = 0,
        drop_evidence: set[str] | None = None,
        duration_ms: int = 1200,
    ) -> None:
        #: 靶场"存在"哪些技术（技术名集合）。空集合 = 一个都打不中。
        self.vulnerable = set(vulnerable or ())
        #: 前 N 次调用抛异常（模拟 SSH 断 / daemon 挂）
        self.fail_times = fail_times
        #: 靶场进程能不能起来（False → `ENV_DEPLOY_FAILED`）
        self.ready = ready
        self.exit_code = exit_code
        #: 这些 probe_id **不回传证据**（模拟整组超时被容器杀掉）
        self.drop_evidence = set(drop_evidence or ())
        self.duration_ms = duration_ms
        #: 记录收到的每一个 spec —— 隔离参数（无出网 / 只读根）就靠断言它
        self.specs: list[Any] = []
        self.calls = 0

    # -- 契约 1 -----------------------------------------------------------

    async def run_once(self, spec: Any) -> ExecResult:
        self.calls += 1
        self.specs.append(spec)
        if self.fail_times > 0:
            self.fail_times -= 1
            raise RuntimeError("ssh: connection closed by remote host")
        stdout = self.render_stdout(spec)
        return ExecResult(
            exit_code=self.exit_code,
            stdout=stdout,
            stderr="",
            duration_ms=self.duration_ms,
            timed_out=False,
        )

    async def stats(self, container_id: str) -> tuple[float, float]:
        return (0.1, 64.0)

    # -- 扮演靶场 ---------------------------------------------------------

    def render_stdout(self, spec: Any) -> str:
        plan = decode_plan(spec)
        lines = [
            _b64_line(
                {
                    "kind": "bootstrap",
                    "ready": bool(self.ready),
                    "error": None if self.ready else "start_failed: FileNotFoundError",
                }
            )
        ]
        for probe in plan["probes"]:
            if probe["probe_id"] in self.drop_evidence:
                continue
            lines.append(
                _b64_line(
                    {
                        "kind": "probe",
                        "probe_id": probe["probe_id"],
                        "responses": self._responses(probe),
                        "request_raw": _describe(probe["requests"]),
                    }
                )
            )
        return "\n".join(lines) + "\n"

    def _responses(self, probe: dict[str, Any]) -> list[dict[str, Any]]:
        technique = str(probe["technique"])
        requests = probe["requests"]
        hit = technique in self.vulnerable
        n = len(requests)

        if technique == "time_blind":
            # 两条请求：基线 + 探针。命中时探针明显更慢（sleep 真被执行）
            times = [180, 3300] if hit else [180, 195]
            return [_resp(200, "ok", ms=times[i]) for i in range(n)]

        if technique == "boolean_blind":
            # 三条请求：真 / 假 / 真重复。命中 = 真假长度不同且真分支稳定
            if hit:
                bodies = ["row: id=1, amount=100", "row: none", "row: id=1, amount=100"]
            else:
                bodies = ["row: none", "row: none", "row: none"]
            return [_resp(200, bodies[i % len(bodies)], ms=120) for i in range(n)]

        if technique == "unauth_probe":
            if hit:
                return [_resp(200, _UNAUTH_JSON, ms=110) for _ in range(n)]
            return [_resp(401, '{"error": "unauthorized"}', ms=90) for _ in range(n)]

        if not hit:
            return [_resp(200, "no such resource", ms=100) for _ in range(n)]

        # 其余技术都是**回显锚点**型：靶场把用户输入原样回显（或塞进报错里），
        # 于是探针自己的 nonce/标记出现在响应体中。把请求原文当响应体，等于
        # 「应用把我的输入回声了回来」这一最典型的注入证据。
        body = _VULNERABLE_BODIES.get(technique) or _describe(requests)
        return [_resp(200, body, ms=100) for _ in range(n)]


class BoomSandbox:
    """永远抛异常的沙箱（沙箱不可达）。"""

    def __init__(self, message: str = "docker daemon unreachable") -> None:
        self.message = message
        self.calls = 0

    async def run_once(self, spec: Any) -> ExecResult:
        self.calls += 1
        raise ConnectionError(self.message)

    async def stats(self, container_id: str) -> tuple[float, float]:
        raise ConnectionError(self.message)


# ---------------------------------------------------------------------------
# 证据编解码（测试与被测代码共用同一份格式约定）
# ---------------------------------------------------------------------------


def _b64_line(obj: dict[str, Any]) -> str:
    raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    return _EVIDENCE_PREFIX + base64.b64encode(raw).decode("ascii")


def decode_plan(spec: Any) -> dict[str, Any]:
    """从 `ContainerSpec` 的 env 里解出容器任务脚本中的探针计划。

    **走的是与容器执行器完全相同的路径**（base64 环境变量 → exec 的脚本源码 →
    脚本里的计划常量），因此被测代码少写一个字段、改一次编码，
    这里就会直接炸出来，而不是"测试因为自己造数据而依然通过"。
    """
    script = base64.b64decode(spec.env["ASA_MISSION_B64"]).decode("utf-8")
    match = _RE_PLAN.search(script)
    if match is None:
        raise AssertionError("容器任务脚本里没有 ASA_PLAN_B64 —— 探针计划没有注入进容器")
    return json.loads(base64.b64decode(match.group(1)).decode("utf-8"))


def _resp(status: int | None, body: str, *, ms: int, error: str | None = None) -> dict[str, Any]:
    return {"status": status, "body": body, "elapsed_ms": ms, "error": error}


def _describe(requests: list[dict[str, Any]]) -> str:
    chunks = []
    for r in requests:
        head = "{} {}".format(r["method"], r["path"])
        for k, v in (r.get("headers") or {}).items():
            head += f"\n{k}: {v}"
        if r.get("body"):
            head += "\n\n" + r["body"]
        chunks.append(head)
    return "\n\n===== 下一条请求 =====\n\n".join(chunks)


# ---------------------------------------------------------------------------
# 便捷构造
# ---------------------------------------------------------------------------

#: 一组"什么都打不中"的靶场（默认）
NO_VULNS: set[str] = set()


def vuln_for(vuln_type: str) -> set[str]:
    """某漏洞类型对应的、能让探针命中的技术名集合（写着方便，不代表全部）。"""
    canon = canonical_vuln_type(vuln_type)
    mapping: dict[str, set[str]] = {
        "sqli": {"union_extract", "boolean_blind"},
        "cmdi": {"time_blind", "echo_nonce"},
        "file_upload": {"upload_marker"},
        "idor": {"idor_horizontal"},
        "unauth_access": {"unauth_probe"},
        "info_disclosure": {"read_config"},
        "file_read": {"path_traversal_read"},
        "deserialization": {"deser_marker"},
    }
    return set(mapping.get(canon, set()))


def evidence_of(sandbox: FakeSandbox, spec: Any) -> dict[str, dict[str, Any]]:
    """把假沙箱给某个 spec 的 stdout 解成 `{probe_id: 证据}`（断言用）。"""
    from app.verify.fingerprints import parse_mission_output

    _bootstrap, probes = parse_mission_output(sandbox.render_stdout(spec))
    return probes
