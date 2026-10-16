"""特征闸门（④）—— **判定发生的唯一地方**（B5 设计 §4.2 / §4.3）。

## 为什么判定必须在这里，而不是在容器里的探针脚本里

容器里的执行器跑在靶场旁边，是本模块唯一不信任的一段代码。如果让它自己算完
再回一个 `{"matched": true}`，那么「证据」与「结论」出于同一处，
`poc_attempts` 里存的就成了「探针说它命中了」而不是「响应里确实出现了 nonce」。

所以执行器只回**原始事实**（三次响应的长度、两次请求的耗时、响应体原文），
判定全部由本文件的纯函数完成。这也让判定规则可以被穷举单测 ——
一个「误判率」无法被测试的判定器，在安全工具里是没有价值的。

## 四种判定方式（+1）

| `ExpectedKind` | 判据 | 为什么用差值/对照 |
|---|---|---|
| `CONTENT_NONCE` | 响应体匹配 `expected_pattern`（正则） | 直接命中，最强证据 |
| `ERROR_ECHO` | 同上，但接受「错误回显里带出 nonce」 | 反序列化探针靠它 |
| `TIME_WINDOW` | `探针耗时 - 基线耗时` 落入窗口 | **绝对值判定会把靶场冷启动误判成注入了 sleep** |
| `STATUS_CODE` | 状态码（`200` 或 `200+json`） | 未授权访问要的是业务数据，光 200 不够 |
| `BOOLEAN_DIFFERENTIAL` | 真/假分支长度不同 ∧ 真分支重复稳定 | 布尔盲注唯一的判据就是「差异」 |
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Any

from app.core.logging import get_logger
from app.verify.types import (
    FIXED_ANCHOR_TECHNIQUES,
    ExpectedKind,
    MatchResult,
    Probe,
    ProbeResponse,
)

logger = get_logger(__name__)

#: 容器内执行器回传证据的前缀（与 `probe._EXECUTOR_BODY` 一致）
EVIDENCE_PREFIX = "ASA-EVIDENCE "

#: 时间盲注的默认容差（毫秒）。
#:
#: 设计 §8 待定项 7 把「容差取值」列为待实测标定项，这里给一个保守默认值：
#: 探针改为**容器内计时**后不含跨面网络抖动（B5 设计 §4.2 末段），主要是
#: 线程调度与 Python 解释器启动开销。**判定用的是差值**，所以冷启动的
#: 绝对值被基线请求吸收了，容差只需覆盖抖动。
DEFAULT_TIME_TOLERANCE_MS = 600

#: 布尔盲注对「稳定」的要求：真分支两次响应长度必须完全一致。
#: 不用比例阈值 —— 长度抖动说明响应本身不确定（比如带时间戳），
#: 此时任何「差异」都不能作为注入证据。
_REQUIRE_STABLE_REPEAT = True


# ---------------------------------------------------------------------------
# 证据解析（纯字符串处理，可脱离沙箱单测）
# ---------------------------------------------------------------------------

_RE_TIME_WINDOW = re.compile(r"^\s*(\d+)\s*(?:\+/-|±|\+-)\s*(\d+)\s*$")


def parse_time_window(
    expr: str, *, tolerance_ms: int = DEFAULT_TIME_TOLERANCE_MS
) -> tuple[int, int]:
    """解析时间窗表达式 → (下界, 上界)，单位毫秒。

    支持 `3000+/-600`（纯 ASCII，便于进 `poc_attempts.expected_pattern` 这种
    `VARCHAR` 列而不引入编码问题）与 `3000±600`。解析不出来时用
    「数值本身 ± 默认容差」兜底，**不抛异常**：一个期望表达式写错不该让
    整个验证阶段失败，它最多让这条探针判不出来。
    """
    match = _RE_TIME_WINDOW.match(expr or "")
    if match:
        center, tol = int(match.group(1)), int(match.group(2))
        return center - tol, center + tol
    digits = re.findall(r"\d+", expr or "")
    if digits:
        center = int(digits[0])
        return center - tolerance_ms, center + tolerance_ms
    return 0, 0


def decode_evidence_line(line: str) -> dict[str, Any] | None:
    """解一行 `ASA-EVIDENCE <base64 json>`。**解析失败返回 None，不抛异常。**

    容器输出可能被日志、警告、编码错误污染（目标应用可能往 stdout 里打印任何东西）。
    一条解析不了的行应当被跳过 —— 它不该让整个 Finding 的验证崩掉。
    """
    payload = line[len(EVIDENCE_PREFIX) :].strip()
    if not payload:
        return None
    try:
        raw = base64.b64decode(payload, validate=True)
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.warning("容器证据行解析失败，已跳过：%s（%s）", payload[:40], exc)
        return None
    return obj if isinstance(obj, dict) else None


def parse_mission_output(stdout: str) -> tuple[dict[str, Any] | None, dict[str, dict[str, Any]]]:
    """把容器 stdout 解析成 (引导信息, {probe_id: 证据})。

    只有带 `kind="probe"` 的行才是探针证据；`kind="bootstrap"` 那行说明靶场
    有没有起来 —— **环境部署失败与探针未命中是两件不同的事**，
    必须能分开（设计 §6：前者 `ENV_DEPLOY_FAILED`，后者只是没打中）。
    """
    bootstrap: dict[str, Any] | None = None
    probes: dict[str, dict[str, Any]] = {}
    for line in stdout.splitlines():
        if not line.startswith(EVIDENCE_PREFIX):
            continue
        obj = decode_evidence_line(line)
        if obj is None:
            continue
        if obj.get("kind") == "bootstrap":
            bootstrap = obj
        elif obj.get("kind") == "probe" and obj.get("probe_id"):
            probes[str(obj["probe_id"])] = obj
    return bootstrap, probes


def responses_to_probe_response(probe: Probe, evidence: dict[str, Any] | None) -> ProbeResponse:
    """把容器回的一款证据翻译成 `ProbeResponse`。

    缺失证据 ⇒ `executed=False`：**容器没跑完这条探针**（超时被杀、容器 OOM、
    或者探针排在任务脚本后面而整组超时了）。它与 `executed=True 但 error!=None`
    是不同的事，但两者都不构成「漏洞不存在」的证据。
    """
    if evidence is None:
        return ProbeResponse(probe_id=probe.probe_id, executed=False)

    responses: list[dict[str, Any]] = list(evidence.get("responses") or [])
    if not responses:
        return ProbeResponse(
            probe_id=probe.probe_id, executed=True, error="容器未回传任何响应", evidence={}
        )

    primary = responses[0]
    errors = [r.get("error") for r in responses if r.get("error")]
    return ProbeResponse(
        probe_id=probe.probe_id,
        executed=True,
        request_raw=str(evidence.get("request_raw", "")),
        response_raw=str(primary.get("body", "")),
        http_status=primary.get("status"),
        elapsed_ms=int(primary.get("elapsed_ms") or 0),
        evidence={
            "responses": [
                {
                    "status": r.get("status"),
                    "body": str(r.get("body", "")),
                    "elapsed_ms": int(r.get("elapsed_ms") or 0),
                    "error": r.get("error"),
                }
                for r in responses
            ]
        },
        error="; ".join(str(e) for e in errors) if errors else None,
    )


# ---------------------------------------------------------------------------
# 判定器（每种 ExpectedKind 一个纯函数）
# ---------------------------------------------------------------------------


def match_content_nonce(probe: Probe, response: ProbeResponse) -> MatchResult:
    """响应体匹配期望模式。**期望模式里含的是本次探针的 nonce。**"""
    body = response.response_raw
    if not body:
        return MatchResult(matched=False, observed="响应体为空", reason="响应体为空，无从匹配")
    pattern = probe.expected_pattern or ""
    try:
        found = re.search(pattern, body, re.MULTILINE)
    except re.error as exc:  # 期望表达式写错：判不出来，但要说清楚是它写错了
        return MatchResult(matched=False, observed="", reason=f"期望特征不是合法正则：{exc}")
    if found:
        return MatchResult(
            matched=True,
            observed=found.group(0)[:120],
            reason=f"响应体匹配到期望特征 {pattern!r}（HTTP {response.http_status}）",
        )
    return MatchResult(
        matched=False,
        observed=body[:120],
        reason=f"响应体（HTTP {response.http_status}）未匹配期望特征 {pattern!r}",
    )


def match_error_echo(probe: Probe, response: ProbeResponse) -> MatchResult:
    """错误回显：nonce 出现在响应里（通常是异常信息或调试输出）。

    与 `CONTENT_NONCE` 的区别只在**解释口径**（回显来自错误路径说明参数到达了
    危险操作），判据本身一样 —— 所以共用同一段匹配代码，避免两套规则漂移。
    """
    result = match_content_nonce(probe, response)
    if result.matched:
        result.reason = (
            f"响应中回显了本次探针的标记（HTTP {response.http_status}）：{result.reason}"
        )
    return result


def match_status_code(probe: Probe, response: ProbeResponse) -> MatchResult:
    """状态码匹配，支持 `200` 与 `200+json`（要求响应体是 JSON）两种写法。

    `+json` 后缀存在的理由：未授权访问探针如果只看「HTTP 200」，会把所有
    「返回 200 的错误页」都算成漏洞 —— 假阳性正是这个模块最不能出的东西。
    """
    expr = (probe.expected_pattern or "").strip()
    want_json = expr.endswith("+json")
    raw_code = expr.removesuffix("+json")
    try:
        expected_status = int(raw_code)
    except ValueError:
        return MatchResult(
            matched=False,
            observed=str(response.http_status),
            reason=f"状态码表达式非法：{expr!r}",
        )

    actual = response.http_status
    if actual != expected_status:
        return MatchResult(
            matched=False,
            observed=str(actual),
            reason=f"实际状态码 {actual}，期望 {expected_status}",
        )
    if want_json:
        body = (response.response_raw or "").strip()
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError):
            return MatchResult(
                matched=False,
                observed=body[:120],
                reason=(
                    f"状态码 {actual} 符合，但响应体不是 JSON"
                    "（未授权访问要的是业务数据，不是一个 200）"
                ),
            )
        if not isinstance(parsed, (dict, list)) or not parsed:
            return MatchResult(
                matched=False,
                observed=body[:120],
                reason=f"状态码 {actual} 符合，但 JSON 响应体为空，不能证明业务数据可未授权读取",
            )
        return MatchResult(
            matched=True,
            observed=body[:120],
            reason=f"无凭证请求返回 {actual} 且响应体是可解析的业务 JSON（{len(body)} 字节）",
        )
    return MatchResult(matched=True, observed=str(actual), reason=f"状态码匹配 {expected_status}")


def match_time_window(probe: Probe, response: ProbeResponse) -> MatchResult:
    """时间盲注：`探针耗时 - 基线耗时` 落入期望窗口。

    **判定用差值，不用绝对值**：靶场冷启动、首次请求的模板编译、JIT 预热都会
    贡献几百毫秒。用绝对值判定的话，「注入成功」与「服务刚起来有点慢」将无法区分
    —— 而这两者的区别正是这个探针存在的意义。

    两次耗时都来自**容器内**自测（B5 设计 §3.2），不含控制面 → 数据面的往返抖动。
    """
    responses = list(response.evidence.get("responses") or [])
    if len(responses) < 2:
        return MatchResult(
            matched=False,
            observed="",
            reason="时间盲注需要「基线 + 探针」两次响应，证据不足",
        )
    baseline_ms = int(responses[0].get("elapsed_ms") or 0)
    probe_ms = int(responses[1].get("elapsed_ms") or 0)
    delta = probe_ms - baseline_ms
    low, high = parse_time_window(probe.expected_pattern or "")
    in_window = low <= delta <= high
    return MatchResult(
        matched=in_window,
        observed=f"delta={delta}ms（基线 {baseline_ms}ms，探针 {probe_ms}ms）",
        reason=(
            f"耗时增量 {delta}ms 落入期望窗口 [{low}, {high}]ms —— sleep 被真的执行了"
            if in_window
            else f"耗时增量 {delta}ms 不在期望窗口 [{low}, {high}]ms 内"
        ),
    )


def match_boolean_differential(probe: Probe, response: ProbeResponse) -> MatchResult:
    """布尔盲注：真/假分支响应长度不同 ∧ 真分支重复一次保持稳定。

    三个条件缺一不可：
    ① `len(真) != len(假)` —— 数据库因为 `1=1` 与 `1=2` 给出了不同结果；
    ② `len(真) == len(真重复)` —— 响应是确定性的，差异不是随机抖动；
    ③ `len(真) > 0` —— 不是「两边都是空响应」。

    少了 ② 的话，任何带时间戳/随机数的页面都会被误判成注入。
    """
    responses = list(response.evidence.get("responses") or [])
    if len(responses) < 3:
        return MatchResult(
            matched=False, observed="", reason="布尔盲注需要「真 / 假 / 真重复」三次响应，证据不足"
        )
    len_true = len(str(responses[0].get("body") or ""))
    len_false = len(str(responses[1].get("body") or ""))
    len_repeat = len(str(responses[2].get("body") or ""))
    stable = len_true == len_repeat
    differs = len_true != len_false
    nonempty = len_true > 0
    matched = differs and nonempty and (stable or not _REQUIRE_STABLE_REPEAT)
    observed = f"len(true)={len_true} len(false)={len_false} len(true-repeat)={len_repeat}"
    if matched:
        reason = f"真假分支响应长度不同且真分支稳定：{observed}"
    elif not differs:
        reason = f"真假分支响应长度一致，未观察到布尔差异：{observed}"
    elif not stable:
        reason = f"真分支重复请求长度不一致（{len_true} vs {len_repeat}），响应不确定，不作为证据"
    else:
        reason = f"真假分支均为空响应，不能证明注入：{observed}"
    return MatchResult(matched=matched, observed=observed, reason=reason)


_DISPATCH = {
    ExpectedKind.CONTENT_NONCE: match_content_nonce,
    ExpectedKind.ERROR_ECHO: match_error_echo,
    ExpectedKind.STATUS_CODE: match_status_code,
    ExpectedKind.TIME_WINDOW: match_time_window,
    ExpectedKind.BOOLEAN_DIFFERENTIAL: match_boolean_differential,
}


def evaluate(probe: Probe, response: ProbeResponse) -> MatchResult:
    """特征闸门（④）：按 `expected_kind` 分派到对应判定器。

    `executed=False` 的响应一律判「未命中」并说明原因 —— **未执行不是命中，
    也不是证伪**，这个区分要一路传到 `VerificationResult` 里。
    """
    if not response.executed:
        return MatchResult(
            matched=False, observed="", reason="该探针未在容器中执行完毕（无证据回传）"
        )
    matcher = _DISPATCH.get(probe.expected_kind)
    if matcher is None:  # pragma: no cover - ExpectedKind 是封闭枚举
        return MatchResult(
            matched=False, observed="", reason=f"未知的判定方式：{probe.expected_kind}"
        )
    return matcher(probe, response)


# ---------------------------------------------------------------------------
# 证伪判据（rejected 的唯一入口）
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NegativeEvidence:
    """「这条件探针跑透了、什么都没命中」是否足以证伪。"""

    conclusive: bool
    reason: str


def can_conclude_absence(
    probe: Probe, response: ProbeResponse, result: MatchResult
) -> NegativeEvidence:
    """负向结果是否**足以**支撑 `rejected`（设计 §4.1 ④ 与 B5-D3）。

    ⚠️ 这是本模块最容易被用错的地方，所以规则写死在这里、只有一个入口：

    **默认不证伪。** 只有同时满足下列全部条件才算「打穿了也没反应」：

    1. 探针确实执行了，且拿到了 HTTP 响应（`http_status` 非空）——
       连接被拒、超时、404 都不是「此处不可注入」，只是「这里没有那个端点」；
    2. 该技术带对照组（`TIME_WINDOW` / `BOOLEAN_DIFFERENTIAL`）或直接读取
       固定内容（`PATH_TRAVERSAL_READ` / `READ_CONFIG`）—— 换句话说，
       **要么有对照，要么读的是本来就存在的东西**；
    3. 响应状态码落在 2xx/3xx：4xx/5xx 说明请求根本没被正常处理。

    设计 §7 B5-D3 的取舍在这里落地：宁可多出 `potential` 让人工复核，
    也不要制造假阴性 —— 无害化探针天然有覆盖盲区（只读探针触发不了
    「写才发作」的漏洞），把「没打中」当成「不存在」是本系统绝不能犯的错。
    """
    if result.matched:
        return NegativeEvidence(False, "已命中，无需证伪")
    if not response.executed:
        return NegativeEvidence(False, "探针未执行完毕，不能据其否证")
    if response.http_status is None:
        return NegativeEvidence(
            False, f"未取得 HTTP 响应（{response.error or '无响应'}），不能据其否证"
        )
    status = int(response.http_status)
    if probe.expected_kind is ExpectedKind.STATUS_CODE and status in _DENIAL_STATUSES:
        # 401/403 是**例外，而且方向是反的**：这里的负向证据恰恰是最硬的那一种 ——
        # 请求被鉴权层挡了回来，"未授权访问"就没复现。若照搬下面的"4xx 一律不算"
        # 规则，未授权访问类漏洞的干净否证会被判成"请求没被正常处理"，
        # 于是 `rejected` 在整个未授权类里永远不可达 —— 那是一处静默的判定黑洞。
        return NegativeEvidence(True, f"HTTP {status}：请求被鉴权层明确拒绝，未复现未授权访问")
    if not (200 <= status < 400):
        return NegativeEvidence(False, f"HTTP {status} 说明请求未被正常处理，不能据其否证")
    if not _is_conclusive(probe):
        return NegativeEvidence(
            False,
            f"{probe.technique} 的 {probe.expected_kind} 判定在未命中时只是"
            f"「没看到痕迹」，不足以否证（可能是载荷没覆盖到真正的注入点）",
        )
    return NegativeEvidence(True, f"HTTP {status} 且对照组稳定，未观察到可注入迹象")


#: 「明确拒绝」的状态码：鉴权层答了话，说明端点存在且守住了 —— 这是否证力最强的一类否定
_DENIAL_STATUSES: frozenset[int] = frozenset({401, 403})


def _is_conclusive(probe: Probe) -> bool:
    """该项探针的「未命中」是否具备否证力。

    两个来源：①判定方式自带对照组（时间窗、布尔差分），或状态码本身就是结论
    （未授权访问）；②技术读的是**本来就存在的东西**（路径穿越读 `/etc/passwd`、
    配置探测读 `/.env`）—— 读不到就是真的读不到，不需要对照组。

    ⚠️ **外加一个前置条件：探针必须打在模板声明的那个参数上。**

    前两条判据看的都是「探针怎么判定」，但一个判定方式再硬，也硬不过
    「载荷根本没被服务端读过」这件事。实测踩到过：SQL 注入的布尔差分探针被
    推成了 `/search?username=...`，而 `/search` 只读 `q` —— 于是 `username`
    被无视，响应体与基线逐字节相同，布尔差分判据忠实地报告「无差异」，
    runner 忠实地据此写下 `rejected`。**三个环节每步都没错，结论是错的。**

    推导来的参数名（`param_is_canonical=False`）只能用来多试一个机会，
    不能用来下结论 —— 证伪要求的是「打穿了也没反应」，
    而打在一个不存在的参数上，连"打"都算不上。
    """
    if not probe.param_is_canonical:
        return False
    # 载荷进不了这个注入点的语法位置时，未命中同样没有否证力 ——
    # `1 AND 1=1` 打在 `username = '…'` 上会被拼成 `username = '1 AND 1=1'`，
    # 一条**合法但恒假**的 SQL。理由与 `param_is_canonical` 是同一条：
    # 「载荷没进入语法位置」与「注入不存在」在响应里长得一模一样。
    if not probe.payload_fits_context:
        return False
    return probe.expected_kind in _CONCLUSIVE_KINDS or probe.technique in FIXED_ANCHOR_TECHNIQUES


#: 带对照组或本身就是结论、因此「未命中」具备否证力的判定方式（封闭集合）
_CONCLUSIVE_KINDS: frozenset[ExpectedKind] = frozenset(
    {
        ExpectedKind.TIME_WINDOW,
        ExpectedKind.BOOLEAN_DIFFERENTIAL,
        ExpectedKind.STATUS_CODE,
    }
)
