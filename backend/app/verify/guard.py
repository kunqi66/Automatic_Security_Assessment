"""`HarmlessGuard` —— 无害化四道闸门（B5 设计 §4.1 / §4.3）。

## 这个文件是本项目的安全底线，所以它被写成纯函数

`check()` 不碰网络、不碰容器、不碰数据库、不读时钟 —— 同样的 `Probe` 永远得到
同样的 `GuardVerdict`。这不是为了好看：**「我们这个系统不会执行破坏性 payload」
这句话如果不可测试，它就只是一句话。** 纯函数意味着闸门的每一条规则都能被穷举
单测（`tests/test_verify_guard.py`），也意味着审查者可以只看这一个文件就回答
「什么能发出去、什么发不出去」。

## 黑名单 + 白名单，两层都要

黑名单（`_DESTRUCTIVE_TOKENS`）是必要的但不是充分的：`DR/**/OP`、十六进制、
大小写混写、Unicode 同形字 —— 绕过一个子串匹配有一百种办法。

所以真正的锁在**行为白名单**（`_PAYLOAD_SHAPE`）：每种技术的载荷形态必须匹配
一个正向正则。**不是「黑名单没命中就放行」，而是「载荷必须长得像它声称的那件事」。**
把不可枚举的对抗问题转成可枚举的正向约束 —— 这是本项目在「黑名单绕过怎么办」
这个问题上的正面答案。

## 顺序即成本序（B5 设计 §4.1）

长度 → 配额 → 破坏性词 → 反弹 shell → 写源码 → 形态白名单 → nonce → 反序列化目标。
全部是零成本的字符串运算，排在「建容器」之前。一个必然被拒的探针不该让阿里云上
（只有 2 vCPU）多起一个容器。
"""

from __future__ import annotations

import base64
import ipaddress
import json
import pickletools
import re
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger
from app.verify.types import (
    CONTRAST_KINDS,
    FIXED_ANCHOR_TECHNIQUES,
    MAX_PAYLOAD_BYTES,
    GateName,
    GuardVerdict,
    Probe,
    ProbeSurface,
    ReasonCode,
    Technique,
)

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# ① 行为闸门：技术白名单
# ---------------------------------------------------------------------------

#: 可执行的技术集合。等于 `Technique` 的全部成员 —— 但**写成显式的集合而不是
#: `set(Technique)`**：将来有人往枚举里加一个技术时，必须在这里再写一次，
#: 于是「这个新技术有没有对应的载荷形态约束」变成一次强制的自问，
#: 而不是一个新成员悄悄获得通行证。
TECHNIQUE_WHITELIST: frozenset[Technique] = frozenset(
    {
        Technique.BOOLEAN_BLIND,
        Technique.UNION_EXTRACT,
        Technique.TIME_BLIND,
        Technique.ECHO_NONCE,
        Technique.UPLOAD_MARKER,
        Technique.PATH_TRAVERSAL_READ,
        Technique.IDOR_HORIZONTAL,
        Technique.UNAUTH_PROBE,
        Technique.READ_CONFIG,
        Technique.DESER_MARKER,
    }
)


def check_technique(probe: Probe) -> GuardVerdict:
    """闸门 ① 行为（构造期，零成本）：技术 ∈ 白名单 ∧ 探针自证无副作用。"""
    if probe.technique not in TECHNIQUE_WHITELIST:
        return _reject(
            GateName.BEHAVIOR,
            ReasonCode.TECHNIQUE_NOT_WHITELISTED,
            f"探针技术 {probe.technique!r} 不在无害化技术白名单内，构造期即拒绝",
        )
    if not probe.side_effect_free:
        return _reject(
            GateName.BEHAVIOR,
            ReasonCode.BEHAVIOR_MISMATCH,
            "探针未自证无副作用（side_effect_free=False），按设计 §4.2 不进入执行",
        )
    return _pass()


# ---------------------------------------------------------------------------
# ② 载荷闸门：纯文本检查
# ---------------------------------------------------------------------------

#: 破坏性词表（B5 设计 §4.3）。**只扫注入内容侧，不扫端点路径** ——
#: 理由见 `ProbeSurface` 的注释：`/api/update` 是接口名，不是 `UPDATE` 语句。
_DESTRUCTIVE_TOKENS: tuple[str, ...] = (
    # SQL：写与 DDL。读操作（SELECT）刻意不在表内 —— 只读探测是本系统的允许动作
    "drop ",
    "delete ",
    "update ",
    "insert ",
    "truncate",
    "alter ",
    "grant ",
    "revoke ",
    "shutdown",
    "into outfile",
    "into dumpfile",
    "load_file",
    "create table",
    "call ",
    # Shell：删改与提权
    "rm -rf",
    "rm -f",
    "rm -r ",
    "mkfs",
    "dd if=",
    "dd of=",
    ":(){",
    "chmod ",
    "chown ",
    "useradd",
    "passwd ",
    "visudo",
    "kill -9",
    "reboot",
    "shutdown -",
    # Shell：外连（下载并执行是 RCE 的常见形态，一律不进载荷）
    "curl ",
    "wget ",
    "tftp ",
    "ftp ",
    "scp ",
    # Shell：重定向写文件
    "> /",
    ">>/",
    ">> /",
    "tee ",
)

#: 反弹 shell 特征表（单独一张表，便于扩展编码变体）。设计 §4.3 的四个 + 常见变体。
_REVERSE_SHELL_TOKENS: tuple[str, ...] = (
    "nc -e",
    "ncat ",
    "/dev/tcp/",
    "/dev/udp/",
    "bash -i",
    "sh -i",
    "socat ",
    "mkfifo",
    "telnet ",
    "exec 3<>",
    "exec 5<>",
    "socket.socket",
    "revshell",
)

#: 写源码目录的判据：载荷里出现工作区路径 + 任意写入算符
_WRITE_OPERATORS: tuple[str, ...] = (">", ">>", "tee", "rm ", "mv ", "cp ", "sed -i", "truncate")
_SOURCE_DIR_HINTS: tuple[str, ...] = ("/workspace", "/src/", "/srv/asa", "app.py")


def _payload_shape(probe: Probe) -> GuardVerdict:
    """行为白名单：载荷形态必须与声明的技术匹配。

    每种技术的**允许形态**写成一条正向正则。这里是本模块的核心主张 ——
    `TIME_BLIND` 的载荷只允许是「一个 shell 语句分隔符 + sleep + 注释」，
    别的什么都不行；`ECHO_NONCE` 只允许 `; echo <token>`。
    **一个能让 `; sleep 3` 通过的匹配器，不可能让 `; rm -rf /` 通过**，
    因为它压根没给 `rm` 留位置。
    """
    # ⚠️ 形态校验跑在 **payload 本身** 上，不是整个 surface 上：surface 里还拼着
    # 参数名与 header，把它们混进正向正则会让「载荷形态」变成「载荷 + 一堆别的
    # 字符串」的形态 —— 正则一放宽，白名单就漏了。
    text = probe.payload.strip()
    technique = probe.technique

    if technique is Technique.TIME_BLIND:
        if not _RE_TIME_BLIND.match(text):
            return _reject(
                GateName.PAYLOAD,
                ReasonCode.BEHAVIOR_MISMATCH,
                "时间盲注探针的载荷形态必须是「; sleep <秒数> [#注释]」，实际不符",
                matched_token=text[:80],
            )
    elif technique is Technique.ECHO_NONCE:
        if not _RE_ECHO.match(text):
            return _reject(
                GateName.PAYLOAD,
                ReasonCode.BEHAVIOR_MISMATCH,
                "回显探针的载荷形态必须是「; echo <token> [#注释]」，实际不符",
                matched_token=text[:80],
            )
    elif technique is Technique.UNION_EXTRACT:
        if not _RE_UNION.match(text):
            return _reject(
                GateName.PAYLOAD,
                ReasonCode.BEHAVIOR_MISMATCH,
                "UNION 探针只允许「<值> UNION SELECT '<字面量>','<字面量>'」的只读形态",
                matched_token=text[:80],
            )
    elif technique is Technique.BOOLEAN_BLIND:
        if not _RE_BOOLEAN.match(text):
            return _reject(
                GateName.PAYLOAD,
                ReasonCode.BEHAVIOR_MISMATCH,
                "布尔盲注探针只允许「<值> AND 1=1」/「<值> AND 1=2」的对照形态",
                matched_token=text[:80],
            )
    elif technique is Technique.PATH_TRAVERSAL_READ:
        if not _RE_RELPATH.match(text):
            return _reject(
                GateName.PAYLOAD,
                ReasonCode.BEHAVIOR_MISMATCH,
                "文件读取探针只允许相对路径（可含 ../），不得含写算符或命令分隔符",
                matched_token=text[:80],
            )
    elif technique is Technique.UPLOAD_MARKER:
        if not _RE_UPLOAD_NAME.match(text):
            return _reject(
                GateName.PAYLOAD,
                ReasonCode.BEHAVIOR_MISMATCH,
                "上传探针只允许上传 .txt/.md/.json 标记文件，禁止可执行后缀",
                matched_token=text[:80],
            )
    elif technique is Technique.DESER_MARKER:
        return _check_deser_payload(probe)
    # UNAUTH_PROBE / READ_CONFIG / IDOR_HORIZONTAL：没有命令注入面
    # （前两者是空载荷 + header 注入；后者是纯标记值），只需 nonce 检查兜底。

    return _pass()


def check_payload(
    probe: Probe,
    *,
    probe_index: int = 0,
    max_probes: int | None = None,
) -> GuardVerdict:
    """闸门 ② 载荷（执行前，零成本）。**七道检查按成本序短路。**"""
    limit = max_probes if max_probes is not None else settings.max_probes_per_vuln
    surface = ProbeSurface.of(probe)
    lowered = surface.payload_text.lower()

    # 1) 长度
    if len(probe.payload.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        return _reject(
            GateName.PAYLOAD,
            ReasonCode.LENGTH_EXCEEDED,
            f"载荷长度超过 {MAX_PAYLOAD_BYTES} 字节上限（该长度已不是探测而是传输）",
        )

    # 2) 配额。构造期已截断过，这里是**第二道**：探针可以从别的路径构造出来
    #    （比如将来由 LLM 提议候选），第二道闸门保证「20 条上限」不依赖于
    #    调用方是否老实走了 build_probes。
    if probe_index >= limit:
        return _reject(
            GateName.PAYLOAD,
            ReasonCode.PROBE_QUOTA_EXCEEDED,
            f"该漏洞的探针已达上限 {limit}，本条不再执行"
            f"（探针是探测行为，打多了等于对目标做压力测试）",
        )

    # 3) 破坏性词
    for token in _DESTRUCTIVE_TOKENS:
        if token in lowered:
            return _reject(
                GateName.PAYLOAD,
                ReasonCode.DESTRUCTIVE_TOKEN,
                f"载荷命中破坏性词表：{token.strip()!r} —— 本系统只做只读探测",
                matched_token=token.strip(),
            )

    # 4) 反弹 shell
    for token in _REVERSE_SHELL_TOKENS:
        if token in lowered:
            return _reject(
                GateName.PAYLOAD,
                ReasonCode.REVERSE_SHELL,
                f"载荷命中反弹 shell 特征：{token!r} —— 绝不建立回连通道",
                matched_token=token,
            )

    # 5) 写靶场源码
    if any(hint in surface.all_text for hint in _SOURCE_DIR_HINTS) and any(
        op in surface.payload_text for op in _WRITE_OPERATORS
    ):
        return _reject(
            GateName.PAYLOAD,
            ReasonCode.WRITE_SOURCE,
            "载荷同时出现源码目录路径与写入算符，拒绝（与容器 ro 只读挂载双保险）",
        )

    # 6) 形态白名单（本模块的核心约束，见函数注释）
    shape = _payload_shape(probe)
    if not shape.passed:
        return shape

    # 7) 锚点完备性。**判据是「特征闸门有没有可判定的锚点」**，而现在锚点有两种：
    #
    #    a) **nonce** —— 我们自己注进去的唯一标记（含 nonce 的探针都走这条）。
    #       检查范围是探针的全部出口字符串（载荷 / 对照 / body / header 值），
    #       而不只是 `payload`：时间盲注的 nonce 藏在 shell 注释里，
    #       反序列化探针的 nonce 在 base64 blob 之外的明文 marker 字段里。
    #       只盯 `payload` 会把这两类合法探针误杀。
    #
    #    b) **固定内容** —— 路径穿越与配置探测这两类探针**刻意不注入任何东西**：
    #       它们发的是「请求一个本来就在的文件（/etc/passwd）」或「请求一个本来就
    #       不该可达的路径（/.env）」。锚点是那个资源的已知内容
    #       （`root:x:0:0:` / `SECRET_KEY=`），而不是我们的标记。
    #       这不是给闸门开后门：白名单只有两个技术、且都是**只读读取**，
    #       集合是封闭的、可枚举的 —— 与「黑名单没命中就放行」是两回事。
    if not _has_anchor(probe, surface):
        return _reject(
            GateName.PAYLOAD,
            ReasonCode.NONCE_MISSING,
            "探针既没有携带唯一 nonce，也没有可判定的固定内容锚点 —— 命中与否将无法判定，直接拒绝",
        )

    return _pass()


def _has_anchor(probe: Probe, surface: ProbeSurface) -> bool:
    """探针是否留下了一个能被特征闸门判定的锚点。**三种锚点，都是封闭集合。**"""
    if probe.nonce and surface.contains(probe.nonce):
        return True
    if probe.technique in FIXED_ANCHOR_TECHNIQUES and bool(probe.expected_pattern):
        return True
    # 对照组锚点：判定靠「对照 vs 探针」的差异，差异本身就是锚点 ——
    # 布尔盲注的真/假分支不需要我方标记，时间盲注的基线/延时同理。
    return bool(probe.control_payload) and probe.expected_kind in CONTRAST_KINDS


# ---------------------------------------------------------------------------
# ③ 网络闸门：目标白名单
# ---------------------------------------------------------------------------

#: 绝对 URL / IP 字面量的探测正则（用于发现「载荷想连出去」）
_RE_ABSOLUTE_URL = re.compile(r"\b(?:https?|ftp|gopher|dict)://([^\s/'\"<>]+)", re.IGNORECASE)
_RE_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def check_network(probe: Probe, *, allowed_hosts: frozenset[str] | None = None) -> GuardVerdict:
    """闸门 ③ 网络（环境就绪后、发包前）。

    两件事：**目标必须在回环白名单内**（探针只打容器内自己），
    **载荷不得出现回环之外的地址**（不得外连）。

    第二件事是「绝不外连」这条红线在代码里的落点：容器本身 `network_disabled=True`
    是基础设施层的保险，这里是业务层的保险 —— 两层都留着，是因为前者的失效方式
    （Docker 网络策略配错、internal 网络被改成 bridge）与后者完全不同，
    而任何一个失效的后果都是「探测结果被发往外部地址」。
    """
    hosts = allowed_hosts if allowed_hosts is not None else settings_hosts()

    host, port = probe.target
    if host not in hosts:
        return _reject(
            GateName.NETWORK,
            ReasonCode.TARGET_NOT_WHITELISTED,
            f"探针目标 {host!r} 不在回环白名单内 —— 探针只允许请求容器自身的 localhost",
            matched_token=host,
        )
    if not (0 < int(port) < 65536):
        return _reject(
            GateName.NETWORK,
            ReasonCode.TARGET_NOT_WHITELISTED,
            f"探针目标端口 {port!r} 非法",
        )

    surface = ProbeSurface.of(probe)
    text = surface.all_text
    for match in _RE_ABSOLUTE_URL.finditer(text):
        target_host = match.group(1).split(":")[0]
        if target_host not in hosts:
            return _reject(
                GateName.NETWORK,
                ReasonCode.EXTERNAL_TARGET,
                f"载荷中出现非回环地址 {match.group(0)!r} —— 绝不外连，已拒绝",
                matched_token=match.group(0),
            )
    for match in _RE_IPV4.finditer(text):
        ip = match.group(1)
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:  # pragma: no cover - 正则已保证是 IPv4 形态
            continue
        if not parsed.is_loopback:
            return _reject(
                GateName.NETWORK,
                ReasonCode.EXTERNAL_TARGET,
                f"载荷中出现非回环 IP {ip!r} —— 绝不外连，已拒绝",
                matched_token=ip,
            )

    return _pass()


def settings_hosts() -> frozenset[str]:
    """默认回环白名单。**不读配置** —— 这是不变量，不是可调项。

    「探针能不能打 10.0.0.5」这个问题的答案永远是「不能」，把它做成配置项
    就给了它变成「能」的可能，而那个可能性没有任何正当用途。
    """
    return frozenset({"127.0.0.1", "localhost", "::1"})


# ---------------------------------------------------------------------------
# 反序列化载荷的专项校验
# ---------------------------------------------------------------------------

#: 反序列化载荷允许的 `__reduce__` 目标 —— **白名单，只有 `getattr`**。
#:
#: 只放行 `getattr` 的理由：我们的载荷需要「调用一个必然失败、且完全没有副作用
#: 的函数」来把 nonce 带进错误信息。`getattr("builtins", "<nonce>")` 正好如此
#: —— 查找一个不存在的属性，只会抛 `AttributeError`。任何其它目标
#: （`os.system` / `subprocess.Popen` / `eval` / `posix.system` …）都进不来。
_ALLOWED_REDUCE_TARGETS: frozenset[tuple[str, str]] = frozenset({("builtins", "getattr")})

#: pickle 协议 < 3 里 `builtins` 的旧写法（`pickle._compat_pickle.NAME_MAPPING`
#: 在**写**的时候会把 `builtins` 改写成 `__builtin__`，读的时候再改回来）。
#:
#: 不做这层归一化的话，同一个 `getattr` 会因为协议号不同而变成两个不同的字符串，
#: 白名单就会莫名其妙地拦掉自己的载荷 —— 白名单比对的应该是**目标本身**，
#: 而不是目标在当前协议下的拼写。
_LEGACY_MODULE_NAMES: dict[str, str] = {"__builtin__": "builtins"}


def _normalize_target(module: str, name: str) -> tuple[str, str]:
    return (_LEGACY_MODULE_NAMES.get(module, module), name)


def _check_deser_payload(probe: Probe) -> GuardVerdict:
    """反序列化探针的专项校验：**解出 pickle 的 reduce 目标并核对白名单**。

    这是本文件里唯一需要「打开载荷看里面」的地方，也是唯一一处不能只靠正则
    的地方：pickle 是图灵完备的序列化格式，用黑名单禁 `os.system` 是禁不完的
    （`posix.system`、`subprocess.Popen`、`builtins.eval` 都是等价物，还能动态拼）。

    所以这里换一个方向：**载荷是我们自己造的，因此可以白名单校验** ——
    把 pickle 的 opcode 逐个走一遍，只允许存在一个 `getattr("builtins", <字面量>)`
    的 reduce 目标。任何别的调用目标一律拒绝。这比黑名单强得多，因为它不依赖
    「我想到的攻击手法比你多」。
    """
    try:
        envelope = json.loads(probe.payload)
    except (TypeError, ValueError):
        return _reject(
            GateName.PAYLOAD,
            ReasonCode.BEHAVIOR_MISMATCH,
            "反序列化探针的载荷必须是 JSON 信封 {'data': <base64 pickle>, 'marker': <nonce>}",
        )
    if not isinstance(envelope, dict) or "data" not in envelope:
        return _reject(
            GateName.PAYLOAD,
            ReasonCode.BEHAVIOR_MISMATCH,
            "反序列化探针的载荷缺少 data 字段",
        )
    try:
        blob = base64.b64decode(str(envelope["data"]), validate=True)
    except (ValueError, TypeError) as exc:
        return _reject(
            GateName.PAYLOAD,
            ReasonCode.BEHAVIOR_MISMATCH,
            f"反序列化探针的 data 不是合法 base64：{exc}",
        )

    targets, failure = _reduce_targets(blob)
    if failure is not None:
        return _reject(GateName.PAYLOAD, ReasonCode.BEHAVIOR_MISMATCH, failure)
    if not targets:
        return _reject(
            GateName.PAYLOAD,
            ReasonCode.BEHAVIOR_MISMATCH,
            "反序列化探针的载荷里没有可调用的 reduce 目标，无法证明对象会被反序列化",
        )
    for raw_target in targets:
        target = _normalize_target(*raw_target)
        if target not in _ALLOWED_REDUCE_TARGETS:
            return _reject(
                GateName.PAYLOAD,
                ReasonCode.BEHAVIOR_MISMATCH,
                f"反序列化载荷的调用目标 {target[0]}.{target[1]} 不在白名单内"
                f"（只允许 builtins.getattr）",
                matched_token=f"{target[0]}.{target[1]}",
            )
    return _pass()


def _reduce_targets(blob: bytes) -> tuple[list[tuple[str, str]], str | None]:
    """遍历 pickle opcode，收集全部调用目标；解析失败时返回原因。

    **不用 `pickle.loads` 探测** —— 那正是我们要防的动作。`pickletools.genops`
    只做词法解析、不执行任何东西，因此可以安全地用在不受信任的字节上。
    """
    targets: list[tuple[str, str]] = []
    try:
        for opcode, arg, _pos in pickletools.genops(blob):
            if opcode.name in ("GLOBAL", "INST"):
                # ⚠️ `pickletools` 把 GLOBAL 的 arg 拼成 `"module name"`（**空格**分隔），
                # 而不是 pickle 字节流里真正的那个换行 —— 别照着格式文档写成
                # `.partition("\n")`，那样会得到 module="builtins getattr"，
                # 于是"白名单永远不命中"，看上去却像"载荷有问题"。
                # 模块名/属性名都是标识符、不含空白，所以 split() 是安全的。
                parts = str(arg).split()
                if len(parts) != 2:
                    return targets, f"无法解析 GLOBAL 的调用目标：{arg!r}"
                targets.append((parts[0], parts[1]))
            elif opcode.name == "STACK_GLOBAL":
                # STACK_GLOBAL 从栈上取 module / name，静态解析不出目标 ——
                # 我们的载荷不使用它，出现即拒（**保守拒绝优于解释不了就放过**）
                return targets, (
                    "反序列化载荷使用了 STACK_GLOBAL（动态取目标），无法静态校验，已拒绝"
                )
    except (ValueError, TypeError, IndexError) as exc:
        return targets, f"反序列化载荷不是可解析的 pickle：{exc}"
    return targets, None


# ---------------------------------------------------------------------------
# 组合
# ---------------------------------------------------------------------------


class HarmlessGuard:
    """四道闸门的门面。**无状态** —— 每次调用都从零开始判定。"""

    def __init__(self, *, max_probes: int | None = None) -> None:
        self.max_probes = max_probes if max_probes is not None else settings.max_probes_per_vuln

    #: 兼容 `GuardVerdict` 的调用习惯
    def check_technique(self, probe: Probe) -> GuardVerdict:
        return check_technique(probe)

    def check(self, probe: Probe, *, probe_index: int = 0) -> GuardVerdict:
        """闸门 ① + ② 的顺序执行（设计 §4.1 的短路序）。

        ① 行为（技术白名单）在前：它断言的是「这个探针该不该存在」，
        比「这个探针该不该发」更靠前一层。
        """
        verdict = check_technique(probe)
        if not verdict.passed:
            return verdict
        return check_payload(probe, probe_index=probe_index, max_probes=self.max_probes)

    def check_network(
        self, probe: Probe, *, allowed_hosts: frozenset[str] | None = None
    ) -> GuardVerdict:
        return check_network(probe, allowed_hosts=allowed_hosts)


# ---------------------------------------------------------------------------
# 形态白名单正则（模块级编译一次）
# ---------------------------------------------------------------------------
#
# 每一条都刻意写得**窄**：允许的字符集有限、结构固定。宽一点会让探针更"灵活"，
# 而灵活正是我们要消灭的东西 —— 探针不需要创造力，它需要可预测。

_RE_TIME_BLIND = re.compile(r"^;\s*sleep\s+\d{1,2}(\.\d+)?\s*(#\S*)?$")
_RE_ECHO = re.compile(r"^;\s*echo\s+[A-Za-z0-9_]{1,64}\s*(#\S*)?$")
#: UNION 探针的形状：**一串字符串字面量**，第一个是 nonce。
#:
#: 第二列从 `version()` 换成字面量，是闸门与靶场对齐的结果：`version()` 是
#: MySQL/PG 专有函数，SQLite 上直接 `no such function`，而 PRD §10.1 的靶场
#: 就是 SQLite。字面量在所有方言上都合法，且**比函数调用更明显无副作用** ——
#: 闸门要证明的本来就是「注入点接受任意 SELECT」，不是「能读到版本号」。
#:
#: ## 列数从「正好 2」放宽到「1–16」，为什么这不削弱白名单
#:
#: 原先这里是 `'…'\s*,\s*'…'` —— 正好两个字面量。放宽的**唯一**理由是
#: 目标 SELECT 的列数不一定等于 2：`SELECT id, name, price FROM products`
#: 是三列，两列的 UNION 在数据库那一侧直接报
#: `SELECTs … do not have the same number of result columns`，
#: 于是探针**永远打不中一个本来能打中的点**，而且失败得毫无线索。
#: 现在列数由 `context.SinkContext.columns`（从 finding 自己的 SQL 前缀数出来）
#: 决定，见 `probe._build_union_payload`。
#:
#: **白名单本身没有被放宽**，这一点是这次改动的全部安全性所在：
#: 每一列仍然只能是 `'[A-Za-z0-9_]{1,64}'`（单引号里的纯标识符字面量），
#: 变的只是**这种字面量有几个**。函数调用、子查询、分号多语句、
#: `INTO OUTFILE`、注释里的东西 —— 一个都没有变得可表达，
#: 因为它们从来就不匹配这串字符集。上限 16 是给载荷大小封顶，
#: 免得一个畸形 finding 让我们构造出几千列的载荷。
#:
#: 第**一**列必须仍是 nonce：指纹就是靠它在响应里找证据的，
#: 让 nonce 出现在后面的列里会让「命中」的判定依赖数据库的列顺序。
_RE_UNION = re.compile(
    r"^\s*[0-9A-Za-z_\-']{0,64}\s+UNION\s+SELECT\s+'(?:[A-Za-z0-9_]{1,64}|\{N\})'"
    r"(?:\s*,\s*'[A-Za-z0-9_]{1,64}'){0,15}\s*(--\s*)?$",
    re.IGNORECASE,
)
_RE_BOOLEAN = re.compile(r"^\s*[0-9A-Za-z_\-']{0,64}\s+AND\s+1\s*=\s*[12]\s*$", re.IGNORECASE)
_RE_RELPATH = re.compile(r"^(?:\.\./)+[A-Za-z0-9_./\-]{1,128}$")
_RE_UPLOAD_NAME = re.compile(r"^[A-Za-z0-9_\-]{1,64}\.(?:txt|md|json)$")


def _pass() -> GuardVerdict:
    return GuardVerdict(passed=True)


def _reject(
    gate: GateName,
    code: ReasonCode,
    reason: str,
    *,
    matched_token: str | None = None,
) -> GuardVerdict:
    logger.info("无害化闸门拒绝探针：gate=%s code=%s reason=%s", gate, code, reason)
    return GuardVerdict(
        passed=False,
        failed_gate=gate,
        reason_code=code,
        reason=reason,
        matched_token=matched_token,
    )


#: 供 runner 在日志/证据里解释「为什么这个探针没发出去」时复用
GATE_ORDER: tuple[GateName, ...] = (
    GateName.BEHAVIOR,
    GateName.PAYLOAD,
    GateName.NETWORK,
    GateName.FEATURE,
)


def describe_gates() -> dict[str, Any]:
    """给文档/自检用的一张快照：四道闸门各自管什么。

    存在的理由是「面试官问『你们怎么保证无害化』时，代码里要有一个能指得出来的
    地方」——比翻三个文件的 docstring 快。
    """
    return {
        GateName.BEHAVIOR: "技术在白名单内 ∧ 探针自证无副作用（构造期，零成本）",
        GateName.PAYLOAD: "长度 / 配额 / 破坏性词 / 反弹 shell / 写源码 / 形态白名单 / nonce",
        GateName.NETWORK: "目标 ∈ 回环白名单 ∧ 载荷不含外连地址",
        GateName.FEATURE: "响应含 nonce / 时间差入窗 / 状态码匹配（判定全在控制面）",
    }
