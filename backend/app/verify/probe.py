"""探针构造 —— **确定性模板，不是 LLM 生成**（B5 设计 §4.2）。

## 为什么这里一个 LLM 调用都没有

探针是**要发出去打目标的东西**。「让模型生成攻击载荷」听起来很酷，但在这个项目里
是三重错误：①它把不可复现引入了最不该抖动的地方（同一份代码两次扫，探针不同，
结论不同）；②它把 L1 铁律捅穿了（载荷决定验证结论，等于 LLM 进控制流）；
③也是最要命的 —— **载荷的合法性就不再有边界**。

所以本文件是一张**声明式模板表**：`(漏洞类型, 技术) → (端点提示, 载荷模板, 判定方式)`。
新增一种探针 = 追加一条数据；载荷形态因此是**可枚举、可审计、可穷举单测**的。

## 无害化在这里的第一道落点

模板表里的每一条载荷都是**只读 / 只算 / 只回显 / 只 sleep** 的。这里没有一张
「危险载荷黑名单」需要维护 —— 因为候选集本身就是**白名单生成**的：
能进候选集的载荷，只可能是本文件里写死的那几条模板 + nonce 替换。
`guard.py` 的载荷闸门是第二层（防的是「模板被改坏」与「未来探针来源扩大」）。
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from app.analysis.parser import make_fs_reader
from app.core.config import settings
from app.core.logging import get_logger
from app.verify.context import SinkContext, infer_context_for, payload_fits_context
from app.verify.routes import PATH_PAYLOAD_SLOT, RouteBinding, bind_route
from app.verify.types import (
    MAX_EVIDENCE_BODY_BYTES,
    MAX_PAYLOAD_BYTES,
    ExpectedKind,
    FindingLike,
    InjectIn,
    Probe,
    ProbePlan,
    ProbeSkip,
    ReasonCode,
    RenderedRequest,
    Technique,
)

logger = get_logger(__name__)

#: nonce 前缀。用纯 ASCII 字母数字：它会出现在 URL、表单、Shell 注释与 JSON 里，
#: 任何一个需要转义的字符都会让「命中了」变成「可能是转义问题」。
NONCE_PREFIX = "asa"
_NONCE_HEX = 12


# ---------------------------------------------------------------------------
# 漏洞类型归一
# ---------------------------------------------------------------------------
#
# **为什么需要这张别名表**：`vulnerabilities.vuln_type` 是 `VARCHAR(64)` 而不是枚举
# （`models/vulnerability.py` 的注释：「取值随规则库演进，故用字符串」），
# 而两份上游文档对同一类漏洞的写法并不一致 —— B5 设计 §4.5 的原子表写 `sqli` /
# `file_read`，`models/vulnerability.py` 的注释写 `sql_injection` / `path_traversal`。
# 两边都对，因为它们描述的是不同抽象层。归一表把这条缝**显式地**焊在一处，
# 而不是散在 `if vuln_type == ...` 里 —— 后者会让「新增一种别名」变成翻遍全库。

VULN_TYPE_ALIASES: dict[str, str] = {
    # SQL 注入
    "sqli": "sqli",
    "sql_injection": "sqli",
    "sql_inject": "sqli",
    "blind_sql_injection": "sqli",
    # 命令注入 / 代码执行
    "cmdi": "cmdi",
    "command_injection": "cmdi",
    "os_command_injection": "cmdi",
    "shell_injection": "cmdi",
    "code_execution": "cmdi",
    # 任意文件读取 / 路径穿越
    "file_read": "file_read",
    "path_traversal": "file_read",
    "arbitrary_file_read": "file_read",
    "directory_traversal": "file_read",
    "lfi": "file_read",
    # 文件上传
    "file_upload": "file_upload",
    "unrestricted_file_upload": "file_upload",
    "arbitrary_file_upload": "file_upload",
    # 越权
    "idor": "idor",
    "broken_access_control": "idor",
    "insecure_direct_object_reference": "idor",
    # 未授权访问
    "unauth_access": "unauth_access",
    "unauthorized_access": "unauth_access",
    "missing_authentication": "unauth_access",
    # 敏感信息泄露
    "info_disclosure": "info_disclosure",
    "information_disclosure": "info_disclosure",
    "sensitive_data_exposure": "info_disclosure",
    "hardcoded_secret": "info_disclosure",
    "hardcoded_credential": "info_disclosure",
    # 反序列化
    "deserialization": "deserialization",
    "unsafe_deserialization": "deserialization",
    "insecure_deserialization": "deserialization",
    "pickle_deserialization": "deserialization",
}


def canonical_vuln_type(vuln_type: str) -> str:
    """把任意写法的 `vuln_type` 归一到模板表的键。未登记的原样返回（⇒ 无模板）。"""
    return VULN_TYPE_ALIASES.get(vuln_type.strip().lower(), vuln_type.strip().lower())


# ---------------------------------------------------------------------------
# 载荷模板
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Template:
    """一条探针模板。**纯数据，无分支** —— 与 B5 设计 §4.6 的规则表同一思路。"""

    technique: Technique
    expected_kind: ExpectedKind
    method: str
    url_path: str
    default_param: str
    #: 载荷模板，`{N}` 为 nonce 占位。**这里只允许出现无害操作**，见模块头注释。
    payload: str
    #: 期望特征模板（正则或窗口表达式），`{N}` 为 nonce 占位
    expected: str
    #: 对照组载荷模板（布尔盲注 / 时间盲注需要）
    control: str = ""
    inject_in: InjectIn = InjectIn.QUERY
    aux_path: str | None = None
    timeout_s: int = 30
    #: 该技术的判定在「无命中」时是否足以**证伪**（见 runner 的证伪条件）。
    #: 只有拿到了对照组的差异结论，才能说「这里打不穿」。
    conclusive_on_negative: bool = False
    #: 排序权重：小的先跑。截断时先牺牲的是排在后面的技术。
    priority: int = 100
    #: 行为闸门自证。任何一项置 False 的模板都**不生成探针**（宁可漏测也不打）。
    side_effect_free: bool = True
    #: 本条技术吃不吃「路由绑定」（`routes.bind_route` 反查出的端点）。
    #:
    #: 默认 True：绝大多数技术就是「把载荷投进本条 finding 的参数里」，
    #: 所以反查出的路由 / 方法 / 参数名 / 注入位置应当**整体替换**模板里那套写死的值。
    #:
    #: 置 False 的是**一条请求装不下**的技术 —— 见 `idor` 模板上的说明。
    #: 对它强制绑定不是"更精确"，而是**把判定本身弄坏**（实测：绑完之后
    #: IDOR 探针发的是 `POST /api/user/<nonce>/profile`，而那个路由只收 GET，
    #: 于是 404，IDOR 永远测不出来）。
    binds_route: bool = True
    #: `binds_route=False` 的模板专用：读侧那条请求，用**哪个资源 id** 去补。
    #:
    #: 置了它，读侧 URL 就**从绑定反查出的路由生成**（把路由里的载荷占位换成
    #: 这个 id），而不是照抄 `aux_path` 里写死的那串 URL。差别是实的：
    #: 照抄的话，"命中的是这一类漏洞的标准形态路由"，命中只能算类别级；
    #: 从源码反查出来，命中就是**本条自己的端点**，才算逐点。
    #:
    #: 为什么 id 是个常量 `2`：IDOR 的判定必须去读一个**不属于调用者**的资源，
    #: 而"具体是哪个 id"对判定毫无影响（只要它存在、且不是你）。固定成 `2`
    #: 是为了确定性 —— 同一份源码跑两次，请求逐字节相同。
    #: 代价是它假定目标至少有 2 号用户；不成立时探针**不命中**，
    #: 落回"没能确认"，不会误报成"确认存在"。
    aux_resource_id: str | None = None


def _t(**kwargs: Any) -> _Template:
    return _Template(**kwargs)


#: 漏洞类型 → 探针模板表（B5 设计 §4.2 的实现）。
#:
#: 每个模板后面那段注释就是面试时被追问「这个载荷为什么是无害的」的答案，
#: 所以写得比代码本身长 —— 这是刻意的。
PROBE_TEMPLATES: dict[str, tuple[_Template, ...]] = {
    # ------------------------------------------------------------------
    "sqli": (
        _t(
            technique=Technique.UNION_EXTRACT,
            expected_kind=ExpectedKind.CONTENT_NONCE,
            method="GET",
            url_path="/search",
            default_param="q",
            # 只读 UNION，第二列是一个常量。没有分号、没有多语句 —— 一个注入点
            # 能不能被 UNION 命中，不需要付出任何写代价就能回答。
            #
            # 第二列**原本是 `version()`**，改成字面量是实测逼出来的：`version()`
            # 是 MySQL/PG 专有函数，SQLite 上直接 `no such function: version`，
            # 而 PRD §10.1 规定的靶场正是 SQLite —— 交付的载荷打不穿自己文档
            # 规定的靶场。字面量在所有方言上都合法，且证明力不变：
            # 闸门要证的是「注入点接受任意 SELECT」，不是「能读到版本号」。
            payload="1 UNION SELECT '{N}','asa' -- ",
            expected="{N}",
            priority=10,
            conclusive_on_negative=True,
        ),
        _t(
            technique=Technique.BOOLEAN_BLIND,
            expected_kind=ExpectedKind.BOOLEAN_DIFFERENTIAL,
            method="GET",
            url_path="/search",
            default_param="q",
            # 布尔盲注：真分支与假分支的响应体长度差 + 真分支重复一次以确认稳定。
            # 载荷里一个写操作都没有，纯粹是让数据库多算一次比较。
            payload="1 AND 1=1",
            control="1 AND 1=2",
            expected="differential",
            priority=20,
            conclusive_on_negative=True,
        ),
        # 设计 §4.2 的 SQL 注入只列了「布尔盲注」与「只读 UNION」两种技术，
        # 这里刻意不加「报错注入」：它需要一个单引号去触发语法错误，而
        # `_RE_UNION` / `_RE_BOOLEAN` 之外的形态无法用正向白名单描述 ——
        # 与其为它开一条形态校验的例外，不如不提供（漏测一种技术，
        # 结果是 unverified，而不是「闸门出现了一条说不清的通道」）。
    ),
    # ------------------------------------------------------------------
    "cmdi": (
        _t(
            technique=Technique.TIME_BLIND,
            expected_kind=ExpectedKind.TIME_WINDOW,
            method="GET",
            url_path="/api/ping",
            default_param="host",
            # 只 sleep。`#` 把 nonce 变成 Shell 注释 —— nonce 进了载荷文本（特征闸门
            # 要有锚点）却永远不会被执行，这一个小技巧同时满足了两条约束。
            payload="; sleep 3 #asa{N}",
            control="; : #asa{N}",
            expected="3000+/-600",
            priority=10,
            conclusive_on_negative=True,
        ),
        _t(
            technique=Technique.ECHO_NONCE,
            expected_kind=ExpectedKind.CONTENT_NONCE,
            method="GET",
            url_path="/api/ping",
            default_param="host",
            # 只 echo。无重定向、无管道、无文件、无网络。
            payload="; echo asa{N} #",
            expected="{N}",
            priority=20,
            conclusive_on_negative=True,
        ),
    ),
    # ------------------------------------------------------------------
    "file_read": (
        _t(
            technique=Technique.PATH_TRAVERSAL_READ,
            expected_kind=ExpectedKind.CONTENT_NONCE,
            method="GET",
            url_path="/api/file",
            default_param="path",
            # 读 /etc/passwd：容器内的文件，只读、不改状态、判定锚点固定
            # （`root:x:0:0:` 是它的第一行，任何发行版都一样）。
            # **不读宿主机的任何东西**——容器是隔离的，它看不到宿主机文件系统。
            payload="../../../../etc/passwd",
            expected=r"root:[x*]?:0:0:",
            priority=10,
            conclusive_on_negative=True,
        ),
        _t(
            technique=Technique.PATH_TRAVERSAL_READ,
            expected_kind=ExpectedKind.CONTENT_NONCE,
            method="GET",
            url_path="/api/download",
            default_param="file",
            payload="../../../../etc/hostname",
            expected=r"^[a-f0-9]{12}$",
            priority=30,
        ),
    ),
    # ------------------------------------------------------------------
    "file_upload": (
        _t(
            technique=Technique.UPLOAD_MARKER,
            expected_kind=ExpectedKind.CONTENT_NONCE,
            method="POST",
            url_path="/api/upload",
            default_param="file",
            # 传 `<nonce>.txt` 再回读。**不上传 WebShell、不上传任何可执行后缀** ——
            # 这不是保守，这正是 B5 设计 §4.7 判定「链的最后一环只能是推演」的原因：
            # 我们能证明「上传点可达且没有后缀白名单」，不能（也不该）证明
            # 「传上去能执行」。
            payload="asa{N}.txt",
            expected="{N}",
            inject_in=InjectIn.BODY,
            aux_path="/uploads/asa{N}.txt",
            priority=10,
        ),
    ),
    # ------------------------------------------------------------------
    "idor": (
        _t(
            technique=Technique.IDOR_HORIZONTAL,
            expected_kind=ExpectedKind.CONTENT_NONCE,
            method="POST",
            url_path="/api/user/profile",
            default_param="nickname",
            # 先用一个匿名会话写入**自造的标记值**，再匿名读别人的资源。
            # 判定锚点是我们自己写进去的 nonce —— 读到它，就同时证明了
            # 「接口缺鉴权」与「资源缺归属校验」两件事，而且证据完全来自自造数据。
            #
            # 关于「写入」：这一条是本模块唯一的写操作，它写的是**一次性容器内的
            # 自造记录**，随容器销毁一并消失（B5 设计 §7 B5-D10 定案）。它不触碰
            # 任何持久资产，因此不属于「破坏性 payload」；真正的红线是
            # 删数据 / 改真实记录 / 反弹 shell / 外连，那三样在本模块的模板表里
            # 一条都不存在。
            payload="asa{N}",
            expected="{N}",
            inject_in=InjectIn.BODY,
            aux_path="/api/user/2/profile",
            priority=10,
            # ⚠️ **IDOR 不吃路由绑定** —— 这是实测撞出来的，理由很实在：
            #
            # 本条探针要发**两条**请求，而且它们**故意打在不同的端点上**：
            #   ① `POST /api/user/profile`      写一个自造标记（url_path）
            #   ② `GET  /api/user/2/profile`    去读**别人**的资源（aux_path）
            #
            # 路由绑定只反查出**一个**端点（finding 的污点参数被用在哪个路由上），
            # 于是它把 ① 的 URL 也换成了 finding 的路由，还顺手把 nonce 注进了路径 ——
            # 发出去就是 `POST /api/user/<nonce>/profile`。那个路由只收 GET，404。
            # IDOR 因此**永远测不出来**，而且失败原因看起来像"目标没有这个接口"。
            #
            # 更根本的是：IDOR 的判定**必须**用"另一个合法用户的 id"。把 nonce
            # 注进路径只会请求一个不存在的用户，等于把要测的东西测没了。
            # 所以这一条的两条请求都得由模板给死，不能让绑定改。
            binds_route=False,
            # 读侧 URL 仍然从**反查出的路由**生成 —— 把路由里的载荷占位换成
            # `aux_resource_id`，于是 `GET /api/user/<int:user_id>/profile`
            # 这条 finding 的端点被真的打到了，只是 id 换成 2。
            # 落到具体目标上就是 `/api/user/2/profile`；换一个路由形状不同的
            # 目标，它跟着变 —— 不再依赖模板里那串写死的 URL。
            aux_resource_id="2",
        ),
    ),
    # ------------------------------------------------------------------
    "unauth_access": (
        _t(
            technique=Technique.UNAUTH_PROBE,
            expected_kind=ExpectedKind.STATUS_CODE,
            method="GET",
            url_path="/api/user/list",
            default_param="token",
            # 不带任何凭证。这个"载荷"其实是**空载荷** —— 我们注入的是
            # 「什么都不注入」，请求里刻意不出现 Authorization 头。
            payload="",
            expected="200+json",
            inject_in=InjectIn.HEADER,
            priority=10,
            conclusive_on_negative=True,
        ),
    ),
    # ------------------------------------------------------------------
    "info_disclosure": (
        _t(
            technique=Technique.READ_CONFIG,
            expected_kind=ExpectedKind.CONTENT_NONCE,
            method="GET",
            url_path="/.env",
            default_param="X-ASA-Probe",
            # 请求一个**本该不可达**的静态路径。载荷同样是空载荷 ——
            # 危险的不是我们发了什么，是服务端回了什么。
            payload="",
            expected=r"(SECRET_KEY|DB_PASSWORD|DATABASE_URL|API_KEY|PASSWORD|TOKEN)\s*[:=]",
            inject_in=InjectIn.HEADER,
            priority=10,
            conclusive_on_negative=True,
        ),
        _t(
            technique=Technique.READ_CONFIG,
            expected_kind=ExpectedKind.CONTENT_NONCE,
            method="GET",
            url_path="/debug/config",
            default_param="X-ASA-Probe",
            payload="",
            expected=r"(SECRET_KEY|DB_PASSWORD|DATABASE_URL|API_KEY|PASSWORD|TOKEN)\s*[:=]",
            inject_in=InjectIn.HEADER,
            priority=20,
        ),
    ),
    # ------------------------------------------------------------------
    "deserialization": (
        _t(
            technique=Technique.DESER_MARKER,
            expected_kind=ExpectedKind.ERROR_ECHO,
            method="POST",
            url_path="/api/deserialize",
            default_param="data",
            # 载荷 = 「只会失败、不会做事」的 pickle：`getattr("builtins", "<nonce>")`
            # 是一次**必然失败的属性查找** —— 它没有副作用（字符串没有这个属性），
            # 但异常信息里会带上 nonce，于是「对象被反序列化了」这件事变得可观测。
            # 不用 __reduce__ 指向 eval/exec/import：那才是真的在构造 RCE 载荷，
            # 哪怕我们只想让它回显一个字符串。
            payload="__ASA_DESER_PAYLOAD__",
            expected="{N}",
            inject_in=InjectIn.BODY,
            priority=10,
        ),
    ),
}


# ---------------------------------------------------------------------------
# nonce
# ---------------------------------------------------------------------------


def make_nonce(*, vuln_id: int, technique: Technique, param_name: str, index: int) -> str:
    """由 (漏洞, 技术, 参数, 序号) 确定性派生 nonce。

    **不用随机数**（虽然 `secrets.token_hex` 更"安全"）：L1 铁律要求同一份输入
    两次运行得到同样的结论，而探针列表是结论的一部分。用哈希派生还附带两个好处：
    ①同一个 (技术, 参数) 永远得到同一个 nonce，重跑时旧证据仍可对齐；
    ②不同探针之间不会撞 nonce，因为派生输入里带了 index。
    """
    seed = f"{vuln_id}|{technique.value}|{param_name}|{index}".encode()
    return NONCE_PREFIX + hashlib.sha256(seed).hexdigest()[:_NONCE_HEX]


# ---------------------------------------------------------------------------
# UNION 载荷的列数
# ---------------------------------------------------------------------------

#: UNION 载荷最多补到几列。与闸门 `guard._RE_UNION` 的 `{0,15}` **必须一致**
#: （那边是"额外的列数 ≤15"，即总共 ≤16）—— 两处不一致的后果是：
#: 我们构造出一个闸门拒收的载荷，探针在闸门那一步被拒，看起来像"目标有问题"。
MAX_UNION_COLUMNS = 16


def _build_union_payload(nonce: str, columns: int | None) -> str:
    """按目标 SELECT 的列数构造只读 UNION 载荷。

    ## 为什么列数必须对上

    `SELECT id, name, price FROM products` 是三列。两列的 UNION 打上去，
    数据库直接报 `SELECTs to the left and right of UNION do not have the same
    number of result columns` —— 探针打不中一个**本来能打中**的注入点，
    而且失败在响应里长得跟"这里没有注入"一模一样。

    ## 列数从哪来

    `columns` 是 `context.SinkContext.columns`，由 `_column_count()` 从
    **finding 自己的 SQL 前缀**数出来（`SELECT` 与 `FROM` 之间的顶层逗号 +1）。
    也就是说它来自**目标的源码**，不是我猜的、也不是写死的常量 ——
    这正是原先那个 `'…','asa'` 两列写死的载荷缺的东西。

    `columns` 为 None（读不出列数）、小于 1、或超过闸门上限时返回**模板原值**
    （两列）：**读不出就不改**，保守地按原来的形状发。这条路径下
    `payload_fits_context` 会判"不适配"，于是未命中不构成证伪 ——
    少一次证伪，而不是多一次误判。超上限同样退回模板而不是硬构造：
    发一个必然被闸门拒收的载荷，只会让日志里多一条"探针被闸门拒绝"，
    读起来像目标有问题。

    ## 填充列为什么是这个常量

    填充值是 `'asa'`（与模板里第二列相同）。它不是随机串：闸门 `_RE_UNION`
    只放行 `'[A-Za-z0-9_]{1,64}'`，而 nonce 已经占了第一列 ——
    填充列**不必**唯一，因为指纹找的是 nonce，其余列只是为了让列数对上。

    `columns=1` 由 `range(0)` 自然落成 `1 UNION SELECT '<nonce>' -- `，
    不需要单开一个分支。
    """
    if columns is None or columns < 1 or columns > MAX_UNION_COLUMNS:
        # 模板原值就是两列（见 `PROBE_TEMPLATES["sqli"]`）
        return f"1 UNION SELECT '{nonce}','asa' -- "
    padding = "".join(",'asa'" for _ in range(columns - 1))
    return f"1 UNION SELECT '{nonce}'{padding} -- "


def _build_deser_payload(nonce: str) -> str:
    """构造「必然失败但零副作用」的 pickle 标记载荷（见模板表里的注释）。

    返回 JSON 字符串：`{"data": "<base64 pickle>", "marker": "<nonce>"}`。
    marker 明文放一份，是为了让 nonce 完备性检查（载荷必须含唯一标记）
    与「错误回显」两件事都不依赖 base64 的解码细节。
    """
    import pickle  # 局部导入：只有这一个技术需要它

    class _Marker:
        """反序列化时会调用 `getattr("builtins", nonce)` —— 一个必失败的查找。

        不实现 `__reduce__` 指向任何可执行调用，是本条载荷无害的全部秘密。
        """

        def __reduce__(self) -> tuple[Any, tuple[Any, ...]]:
            return (getattr, ("builtins", nonce))

    # ⚠️ `protocol=2` **不是随便选的**：Python 3.8 起 `pickle.dumps` 默认用协议 5，
    # 它用 `STACK_GLOBAL` 从栈上取调用目标 —— 那是静态校验不出来的（闸门 ② 会拒），
    # 因为目标名在运行时才拼出来。协议 2 用 `GLOBAL`，模块名与函数名是载荷里的
    # 字面量，`pickletools.genops` 能一遍读出全部调用目标并逐个比对白名单。
    #
    # 换句话说：探针载荷要"可被静态审阅"，这决定了它的序列化协议。
    # 而反序列化端的读取器（pickle.loads）无视协议号，协议 2 一样能被触发。
    blob = base64.b64encode(pickle.dumps(_Marker(), protocol=2)).decode("ascii")
    return json.dumps({"data": blob, "marker": nonce}, ensure_ascii=False)


# ---------------------------------------------------------------------------
# 注入点推导
# ---------------------------------------------------------------------------

#: 从 `TaintStep.symbol` 里抠出「参数名」的形态：`request.args.get('id')` →
#: `id`；`payload` → `payload`；`q` → `q`。
#: 引号里的参数名。**允许连字符** —— `request.headers.get('X-Tenant')` 里的
#: `X-Tenant` 是一个真实的请求头名，不含连字符的写法（`[A-Za-z0-9_]`）会把它
#: 截成 `Tenant`，于是探针打到一个不存在的参数上，白白吃掉配额。
_QUOTED = re.compile(r"['\"]([A-Za-z_][A-Za-z0-9_-]*)['\"]")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

#: **请求侧**符号的特征词。只有含这些词的符号才可能是"用户输入进来的那个参数"。
#:
#: 存在的理由：`finding.symbol` 在 B4 的模型里是**下沉点**（`cursor.execute`），
#: 把它当参数名会造出一条打向 `execute` 参数的探针 —— 目标应用里根本没有这个参数，
#: 于是这次探测的结论是"未命中"，而这与"没有漏洞"完全不是一回事。
#: 宁可退回默认参数名，也不要用一个明显不对的参数名去凑探针数。
_REQUEST_HINTS = (
    "request",
    "args",
    "form",
    "json",
    "param",
    "query",
    "payload",
    "body",
    "header",
    "cookie",
    "input",
    "data",
)

#: 这些符号名不是参数名，是框架里到处都有的东西，拿来当注入点只会浪费探针额度
_SYMBOL_NOISE = frozenset(
    {
        "request",
        "args",
        "get",
        "form",
        "json",
        "values",
        "self",
        "str",
        "int",
        "query",
        "data",
        "body",
        "app",
        "route",
    }
)


def _attr(obj: Any, name: str, default: Any = None) -> Any:
    """容错取属性 —— `FindingRef` 上没有 `taint_path` / `sink_kind` 这些字段。"""
    return getattr(obj, name, default)


def injection_points(finding: FindingLike, *, default: str) -> tuple[str, ...]:
    """从污点路径推导注入点（参数名）列表，**去重且保序**。

    顺序即优先级：source 那一跳的符号最可能是「用户输入进来的那个参数」，
    所以排在最前；推导不出来时退回该技术的默认参数名 —— 而不是报错，
    因为「推导不出参数名」是常态（B3 手上只有 `FindingRef` 时尤其如此）。
    """
    points: list[str] = []
    for step in _attr(finding, "taint_path", ()) or ():
        if _attr(step, "step_kind", "") not in ("source", "propagate"):
            continue
        symbol = str(_attr(step, "symbol", "") or "")
        if not symbol:
            continue
        quoted = _QUOTED.search(symbol)
        if quoted:
            candidate = quoted.group(1)
        else:
            tokens = [t for t in _IDENT.findall(symbol) if t not in _SYMBOL_NOISE]
            if not tokens:
                continue
            candidate = tokens[-1]  # 取末位：`request.args.get` 里最有信息量的是最后一段
        if candidate and candidate not in points:
            points.append(candidate)

    # 污点路径没给出可用参数名时，退一步看 `symbol` 本身是不是**请求侧**符号
    # （B4 的 Finding 里 `symbol` 是下沉点，通常在这里帮不上忙 —— 那正是这段
    # 判断的意义：帮不上忙就别硬凑，直接走默认参数名）。
    symbol = str(_attr(finding, "symbol", "") or "")
    lowered = symbol.lower()
    if symbol and any(hint in lowered for hint in _REQUEST_HINTS):
        tokens = [t for t in _IDENT.findall(symbol) if t not in _SYMBOL_NOISE]
        if tokens and tokens[-1] not in points:
            points.append(tokens[-1])

    if not points:
        points.append(default)
    return tuple(points)


# ---------------------------------------------------------------------------
# 计划构造
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Candidate:
    template: _Template
    param_name: str
    index: int
    binding: RouteBinding | None = None
    """本条候选**绑到 finding 自己的端点**上时的绑定结果；None = 走模板的固定路由。

    绑定成功时候选集**塌缩成一条**（见 `_candidates`）—— 路由与参数都已经是从
    源码里读出来的事实，再张量积几十个猜出来的注入点，就是把已经确定的东西
    重新变成猜的。
    """

    ctx: SinkContext | None = None
    """注入点的 SQL 语法上下文（仅绑定成功时有）。见 `context.py`。"""


def _candidates(
    finding: FindingLike,
    canon: str,
    binding: RouteBinding | None = None,
    ctx: SinkContext | None = None,
) -> list[_Candidate]:
    """候选集：模板 × 注入点。**顺序完全由模板表与污点路径决定，无随机。**

    ## 绑定成功时：塌缩成「每个模板一条，打在 finding 自己的端点上」

    这是本模块最重要的一次行为改变。绑定成功后，路由、参数名、注入位置
    **全部来自源码反查**（`routes.bind_route`），不再有"猜"的成分 ——
    于是既没有必要、也有害地保留那几十个推导出来的注入点：
    它们打的是**同一个端点上的其它参数**，命中与否都不说明本行代码的问题，
    却照样能投出证伪票。

    ## 绑定失败时：维持张量积（原行为）

    绑不上是**正常结果**（`config.py` 的硬编码密钥就没有端点）。
    这时仍然按模板的固定路由打一遍，但探针标 `bound_to_finding=False` ——
    它证明的是「该类漏洞在本目标上存在」，只能落 `potential`。

    ⚠️ **模板自己声明的参数名排在推导出来的前面**，这条顺序是有后果的，不是风格：

    路由是模板写死的，参数却是从 finding 推导的。推导出来的名字经常是
    **那个路由根本不读的** —— `request.files.get("file")` 推成 `files`、
    `def check_login(...)` 推成 `check_login`。拿这种名字去打固定路由，
    请求会正常返回 200，但服务端压根没碰这个参数：

        POST /api/upload   name="files"  → 400「缺少 file 字段」
        GET  /search?username=...        → 200，商品页原样返回

    前者把一条真上传漏洞从 `verified` 压成 `potential`，后者把一条真 SQL 注入
    压成 `rejected`。两个都不是"漏报"，是**报错了**。

    所以先打规范形态：推对了是加分项，推错了不该变成减分项。
    """
    templates = PROBE_TEMPLATES.get(canon, ())
    out: list[_Candidate] = []
    index = 0

    if binding is not None:
        for template in templates:
            # `param_name` 为 None 时用模板声明的默认名补上：路由已经反查确认，
            # 补的只是**字段名**（实测 `app.py:147` 的 snippet 只到 `request.files`）。
            out.append(
                _Candidate(
                    template=template,
                    param_name=binding.param_name or template.default_param,
                    index=index,
                    binding=binding,
                    ctx=ctx,
                )
            )
            index += 1
        return out

    for template in templates:
        # ⚠️ 规范参数名要**显式补进去**，不能只排序 ——
        # `injection_points` 的语义是「推导得出就用推导的，推导不出才用默认」，
        # 所以推出来的名字一存在，默认名就**根本不在列表里**，排序无从谈起。
        # 实测就是栽在这里：`admin_login.py` 推成 `check_login` 之后，
        # 探针列表里再也没有 `q`，于是 `/search` 永远没被按规范形态打过。
        points = [template.default_param]
        points += [
            p
            for p in injection_points(finding, default=template.default_param)
            if p != template.default_param
        ]
        for point in points:
            out.append(_Candidate(template=template, param_name=point, index=index))
            index += 1
    return out


def build_probes(
    finding: FindingLike,
    *,
    vuln_id: int | None = None,
    max_probes: int | None = None,
    src_root: str | Path | None = None,
) -> ProbePlan:
    """从一个 Finding 确定性地产出探针计划（B5 设计 §4.2）。

    **上限语义：20 是上限，不是目标。** 探针是探测行为 —— 打多了等于对目标做
    压力测试，那超出了「评估」的授权范围（B5 设计 §7 B5-D7）。所以超限时
    不是静默丢弃，而是把被裁掉的探针写进 `plan.skipped`：
    报告里「本次只验证了 3 个注入点」与「本次一个都没验证」必须是分得开的结论。

    ## `src_root`：把探针绑到 finding 自己的端点上

    给了 `src_root` 就多做一件事：从 finding 的污点路径反查它**自己的**端点
    （`routes.bind_route`），探针改打那个端点，并标 `bound_to_finding=True`。
    不给则维持原行为（打模板的固定路由）—— 靶场基准与单测大量依赖后者，
    而且**绑定失败时本来就要退回前者**，两条路径都得留着。

    `src_root` 是**源码根目录**，不是沙箱里的路径：反查发生在控制面，
    读的是 B1 工作区里那份源码（`handle.src_root`）。
    """
    limit = max_probes if max_probes is not None else settings.max_probes_per_vuln
    vuln_id = vuln_id if vuln_id is not None else int(_attr(finding, "vuln_id", 0) or 0)
    canon = canonical_vuln_type(str(_attr(finding, "vuln_type", "")))

    if canon not in PROBE_TEMPLATES:
        # 没有模板 ≠ 不存在漏洞。这里刻意**不产出任何探针**，让 runner 落
        # `unverified` + `POTENTIAL` —— 断言「不支持探测」和断言「没有漏洞」
        # 是两件完全不同的事，混起来就是假阴性。
        logger.info("漏洞类型 %r 无无害化探针模板，跳过探测（不影响其存在性结论）", canon)
        return ProbePlan(
            probes=[],
            skipped=[
                ProbeSkip(
                    probe_id="",
                    technique="",
                    reason_code=ReasonCode.NO_PROBE_TEMPLATE,
                    reason=f"漏洞类型 {canon!r} 尚无无害化探针模板，未能执行任何探测",
                )
            ],
        )

    binding: RouteBinding | None = None
    ctx: SinkContext | None = None
    if src_root is not None:
        reader = make_fs_reader(Path(src_root))
        binding = bind_route(reader, finding)
        if binding is not None:
            ctx = infer_context_for(reader, finding, binding)
            logger.info(
                "漏洞 %s 已绑定到自己的端点：%s %s（参数 %s，位置 %s）",
                vuln_id,
                binding.methods[0],
                binding.url_path,
                binding.param_name,
                binding.inject_in.value,
            )

    candidates = _candidates(finding, canon, binding=binding, ctx=ctx)
    probes: list[Probe] = []
    skipped: list[ProbeSkip] = []

    for cand in candidates:
        probe = _render(finding, vuln_id, cand)
        # ① 行为闸门（构造期）：技术白名单表反查载荷形态。设计 §4.1 的短路顺序里
        # 这一门成本为零，所以放在最前面 —— 一个必然被拒的探针不该走到后面任何一步。
        if not cand.template.side_effect_free:
            skipped.append(
                ProbeSkip(
                    probe_id=probe.probe_id,
                    technique=probe.technique.value,
                    reason_code=ReasonCode.BEHAVIOR_MISMATCH,
                    reason="该技术的模板标记为非无副作用，按设计 §4.2 不进候选集",
                )
            )
            continue
        if len(probe.payload.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            skipped.append(
                ProbeSkip(
                    probe_id=probe.probe_id,
                    technique=probe.technique.value,
                    reason_code=ReasonCode.LENGTH_EXCEEDED,
                    reason=f"载荷长度超过 {MAX_PAYLOAD_BYTES} 字节上限",
                )
            )
            continue
        if len(probes) >= limit:
            skipped.append(
                ProbeSkip(
                    probe_id=probe.probe_id,
                    technique=probe.technique.value,
                    reason_code=ReasonCode.PROBE_QUOTA_EXCEEDED,
                    reason=(
                        f"已达单漏洞探针上限 {limit}，本条未执行"
                        f"（探针是探测行为，超限执行等同于对目标做压力测试）"
                    ),
                )
            )
            continue
        probes.append(probe)

    truncated = any(s.reason_code is ReasonCode.PROBE_QUOTA_EXCEEDED for s in skipped)
    if truncated:
        logger.warning(
            "漏洞 %s 的探针候选 %d 条超过上限 %d，已截断（被裁 %d 条已记录）",
            vuln_id,
            len(candidates),
            limit,
            sum(1 for s in skipped if s.reason_code is ReasonCode.PROBE_QUOTA_EXCEEDED),
        )

    return ProbePlan(
        probes=probes, skipped=skipped, truncated=truncated, candidate_count=len(candidates)
    )


def _render(finding: FindingLike, vuln_id: int, cand: _Candidate) -> Probe:
    """把一条模板渲染成一个具体探针。**纯函数**：同输入必然同输出。

    ## ⚠️ 路由来自模板，**不来自 finding** —— 这条限制要读清楚

    `url_path` 取的是 `template.url_path`，而不是从 finding 反推出来的路由。
    两者在靶场上必然一致（靶场是按模板的路由造的），但在真实项目上**会不一致**：

    * 靶场一的 SQL 注入有三处（`/search`、`/api/order/query`、`admin_login.py`），
      而 `sqli` 的两条模板 `url_path` 都是 `/search` —— 于是三条 finding 各自
      跑了一遍**同一个** `/search` 探针，得到同一个结论。
    * 靶场三若把注入点放在别的路由上，探针会打到 `/search`；靶场里没有这个路由
      时它 404，finding 落 `unverified` —— 那是"碰巧诚实"，不是设计使然。

    **这不是漏改，是当前的设计边界**：B5 的探针表是**标准形态**的确认
    （"在这一类漏洞的标准无害化请求下，靶场是否确认"），不是逐点复现。
    逐点复现需要从 finding 的 `file_path` + `line_start` 反查该行的路由装饰器
    （`handle.src_root` 已在手边，tree-sitter 也是现成的），
    但那样 `build_probes` 就不再是纯函数、要读文件、要处理路由变量
    （`<int:user_id>` 得填一个具体值，模板现在用 `aux_path` 把这个值写死为 2）。

    ## 后果比"归属不准"严重 —— 这是端到端跑出来才看清的

    初版这段注释写的是"三条 finding 各自跑了一遍同一个探针，结论被张冠李戴"。
    实跑一遍才发现方向反了：**它会制造假阴性，并且是以 `rejected` 的形式断言**。

    同一份靶场上：

        vuln 18  sql_injection  app.py:114      → 探针用 ?q=        → verified
        vuln 16  sql_injection  admin_login.py  → 探针用 ?username=  → rejected

    两条都是真注入，差别只在推导出来的参数名碰巧对不对。`/search` 只读 `q`，
    `?username=` 被无视、响应体与基线逐字节相同 —— 而布尔差分的判据正是
    "没有差异即不可注入"，于是 `rejected`。

    所以路由/参数的错配**不是**"结论归属不准"这种可以接受的模糊，
    是把「没测到」写成了「不存在」。两处修正（参数名规范优先 + 非规范参数
    不得证伪）落在 `_candidates` 与 `fingerprints._is_conclusive`。

    仍然如实记在这里、不靠靶场恰好满足模板来掩盖的是：
    报告里的 `verified` 应读作「该类漏洞的标准形态已在沙箱确认」，
    而不是「你看到的那一行代码所在的端点已被打通」。
    """
    template = cand.template
    nonce = make_nonce(
        vuln_id=vuln_id,
        technique=template.technique,
        param_name=cand.param_name,
        index=cand.index,
    )
    probe_id = f"P{vuln_id:04d}-{cand.index:02d}-{template.technique.value}"

    binding = cand.binding if template.binds_route else None
    if binding is not None:
        # 绑定成功：路由 / 方法 / 参数 / 注入位置**全部**改用反查结果。
        # 四个一起换，不能只换路由 —— 路由对了但参数名还是猜的，
        # 就回到了"打在对的参数上、名字是错的"那种半对状态。
        url_path = binding.url_path
        method = binding.methods[0]
        param_name = cand.param_name
        inject_in = binding.inject_in
    elif not template.binds_route:
        # 不吃绑定的模板：**参数名也必须回到模板自己的 `default_param`**。
        #
        # 这一格是实测撞出来的：idor 的 finding 污点参数是 `user_id`
        # （**读**接口的路径形参），而写入接口要的是 `nickname`。
        # 用 `cand.param_name` 会把标记值写进 `user_id` 这一格 ——
        # `UPDATE ... SET nickname = ?` 于是把昵称置成空串，
        # 第二步读回来的当然没有 nonce，探针必然不命中。
        # 路由不由模板定，参数名就得由模板定，两件事是同一个理由。
        url_path = template.url_path
        method = template.method
        param_name = template.default_param
        inject_in = template.inject_in
    else:
        url_path = template.url_path
        method = template.method
        param_name = cand.param_name
        inject_in = template.inject_in

    # 载荷在这个注入点的语法上下文里成立吗？绑定成功才有上下文可谈 ——
    # 打模板固定路由时没有"这一个注入点"，也就无从谈起（见 `context.py`）。
    #
    # ⚠️ `ctx` 必须在**构造载荷之前**算出来：UNION 载荷的列数取自
    # `ctx.columns`（见 `_build_union_payload`）。原先这两段是反过来的顺序，
    # 那样写的话载荷会先按模板的两列定型，列数适配就永远只能"事后判定不适配"，
    # 而不是"按目标的形状构造"。
    ctx = cand.ctx if binding is not None else None

    payload = template.payload.replace("{N}", nonce)
    control = template.control.replace("{N}", nonce)
    expected = template.expected.replace("{N}", nonce)
    aux_path = template.aux_path.replace("{N}", nonce) if template.aux_path else None

    # 读侧那条请求能不能也改成"打在本条自己的端点上"？
    # 只有当模板声明了要读哪个资源 id、**且**反查出的路由里真有载荷占位时才成立 ——
    # 占位不在路由里（例如污点参数在请求体里），替换就是空操作，
    # 那会把读侧 URL 变成"这条 finding 的写入端点"，比模板原值还错。
    aux_from_route = False
    if cand.binding is not None and template.aux_resource_id is not None:
        derived = cand.binding.url_path.replace(PATH_PAYLOAD_SLOT, template.aux_resource_id)
        if derived != cand.binding.url_path:
            aux_path = derived
            aux_from_route = True

    if template.technique is Technique.DESER_MARKER:
        payload = _build_deser_payload(nonce)
    elif template.technique is Technique.UNION_EXTRACT:
        # 列数按**目标的** SELECT 来，而不是模板里写死的那两列。
        payload = _build_union_payload(nonce, ctx.columns if ctx is not None else None)

    return Probe(
        probe_id=probe_id,
        vuln_id=vuln_id,
        technique=template.technique,
        payload=payload,
        control_payload=control,
        method=method,
        url_path=url_path,
        param_name=param_name,
        # 是不是模板自己声明的那个参数名。**只有它是 True，未命中才谈得上证伪**
        # —— 理由见 `Probe.param_is_canonical` 与 `fingerprints._is_conclusive`。
        param_is_canonical=cand.param_name == template.default_param,
        # 探针是不是打在 **finding 自己**的端点上。命中的含义因此完全不同：
        # True = 这一条成立；False = 这一类在本目标上成立。见 `Probe.bound_to_finding`。
        #
        # `aux_from_route` 也算：idor 那条探针的**主请求**走模板（它打的写入端点
        # 根本不是这条 finding），但**判定命中的那一条**是从反查出的路由生成的，
        # 打的就是本条自己的端点 —— 命中的归属由它决定。
        bound_to_finding=binding is not None or aux_from_route,
        payload_fits_context=payload_fits_context(template.technique, payload, ctx),
        inject_in=inject_in,
        aux_path=aux_path,
        nonce=nonce,
        expected_kind=template.expected_kind,
        expected_pattern=expected,
        # 目标恒为容器内回环 —— 这是不变量，不是配置（见 guard.check_network）
        target=("127.0.0.1", 5000),
        timeout_s=template.timeout_s,
        side_effect_free=template.side_effect_free,
    )


# ---------------------------------------------------------------------------
# 请求渲染（在控制面完成，容器里只发请求不构造载荷）
# ---------------------------------------------------------------------------


def _inject(
    payload: str, param_name: str, inject_in: InjectIn
) -> tuple[str, dict[str, str], str | None]:
    """按注入位置把载荷放到 query / body / header 里。

    返回 (附加的 query 串, 附加的 header, body)。**载荷在这里已经被 URL 编码**：
    编码发生在控制面，所以闸门检查的字符串与实际发出的字符串是同一个来源。
    """
    encoded = quote(payload, safe="")
    if inject_in is InjectIn.HEADER:
        # 空载荷 + header 注入 = 刻意不注入（未授权访问 / 配置探测用的就是这种形态）
        return "", ({param_name: payload} if payload else {}), None
    if inject_in is InjectIn.BODY:
        return "", {}, f"{quote(param_name, safe='')}={encoded}"
    if inject_in is InjectIn.PATH:
        # 路径注入的载荷**不进 query/header/body** —— 它替换 `url_path` 里的
        # `{payload}` 占位（见 `_request`）。这里返回空是**对的**，不是没实现。
        return "", {}, None
    return f"{quote(param_name, safe='')}={encoded}", {}, None


def _request(
    probe: Probe, payload: str, *, label: str, method: str | None = None, path: str | None = None
) -> RenderedRequest:
    extra_query, extra_headers, body = _inject(payload, probe.param_name, probe.inject_in)
    headers = dict(probe.headers)
    headers.update(extra_headers)
    target_path = path if path is not None else probe.url_path
    if probe.inject_in is InjectIn.PATH and PATH_PAYLOAD_SLOT in target_path:
        # 路径段注入：把载荷填进 `{payload}` 占位。
        # ⚠️ 这一支**以前是完全没有的** —— `_inject` 对 PATH 返回空，
        # `_request` 又原样用 `probe.url_path`，于是路径参数的探针
        # **发出去的是不带载荷的干净请求**，然后"未命中"。静默失效，
        # 因为请求确实发了、响应确实回来了。
        # 编码时放行 `/` 与 `.`：`../` 必须原样到达服务端，
        # WSGI 会在路由前把它解码回来，`<path:name>` 才对得上。
        target_path = target_path.replace(PATH_PAYLOAD_SLOT, quote(payload, safe="/."))
    if extra_query:
        separator = "&" if "?" in target_path else "?"
        target_path = f"{target_path}{separator}{extra_query}"
    return RenderedRequest(
        method=method or probe.method,
        path=target_path,
        headers=headers,
        body=body,
        timeout_s=probe.timeout_s,
        label=label,
    )


def render_requests(probe: Probe) -> list[RenderedRequest]:
    """把一个探针渲染成**要在容器里发出的请求序列**。

    控制面负责「发什么」，容器只负责「发」。这使得载荷闸门检查的对象与真正
    发出去的内容**在类型上就是同一个东西** —— 不存在「容器里才拼出来的载荷」。

    序列长度随技术而定：

    - 布尔盲注：真 / 假 / 真重复（三次）—— 没有对照组就没有「差异」这个判据；
    - 时间盲注：基线 / 探针（两次）—— 判定用**差值**而不是绝对值，见 fingerprints；
    - 上传：上传 / 回读（两次）—— 证明「传得上去」的是回读得到，不是上传返回 200；
    - 其余：一次。
    """
    technique = probe.technique

    if technique is Technique.BOOLEAN_BLIND:
        return [
            _request(probe, probe.payload, label="true-branch"),
            _request(probe, probe.control_payload, label="false-branch"),
            _request(probe, probe.payload, label="true-branch-repeat"),
        ]

    if technique is Technique.TIME_BLIND:
        return [
            _request(probe, probe.control_payload, label="baseline"),
            _request(probe, probe.payload, label="probe"),
        ]

    if technique is Technique.UPLOAD_MARKER:
        body = _multipart_body(probe)
        return [
            RenderedRequest(
                method=probe.method,
                path=probe.url_path,
                headers={"Content-Type": f"multipart/form-data; boundary={_BOUNDARY}"},
                body=body,
                timeout_s=probe.timeout_s,
                label="upload",
            ),
            _request(probe, "", label="readback", method="GET", path=probe.aux_path or ""),
        ]

    if technique is Technique.IDOR_HORIZONTAL:
        return [
            _request(probe, probe.payload, label="create-marker", method="POST"),
            _request(probe, "", label="read-other-user", method="GET", path=probe.aux_path or ""),
        ]

    return [_request(probe, probe.payload, label="probe")]


#: multipart 分隔串。固定值（确定性）+ 带非 ASCII 不可能出现的字符集。
_BOUNDARY = "----ASAProbeBoundary7d1a"


def _multipart_body(probe: Probe) -> str:
    """把 `<nonce>.txt` 编成一个 multipart 表单体。

    内容就是 nonce 本身 —— **不是任何可执行内容、不是任何脚本**。
    上传探针要证明的是「上传点可达 + 没有后缀白名单」，而这件事只需要一个
    能回读出来的文本文件作为凭证。
    """
    filename = probe.payload
    content = probe.nonce
    lines = [
        f"--{_BOUNDARY}",
        f'Content-Disposition: form-data; name="{probe.param_name}"; filename="{filename}"',
        "Content-Type: text/plain",
        "",
        content,
        f"--{_BOUNDARY}--",
        "",
    ]
    return "\r\n".join(lines)


# ---------------------------------------------------------------------------
# 容器内执行器（哑执行器：只发请求、只回事实，判定全在控制面）
# ---------------------------------------------------------------------------

#: 容器内执行器源码。**不含任何载荷构造逻辑** —— 载荷已经在控制面渲染完毕。
#:
#: 这样切分的理由：容器跑在靶场旁边，是我们唯一不信任的那一段。如果让它
#: 「自己拼载荷」，闸门检查的内容与真正发出去的内容就可能不一致（一个变量替换
#: 顺序的差异就够）。把构造全部留在控制面之后，闸门看到的字符串**就是**发出的字符串。
_EXECUTOR_BODY = """\
import base64 as _b64
import json as _json
import socket as _socket
import subprocess as _subprocess
import sys as _sys
import time as _time
import urllib.error as _uerr
import urllib.request as _ureq

_sys.stdout.reconfigure(encoding="utf-8")

_PLAN = _json.loads(_b64.b64decode(ASA_PLAN_B64).decode("utf-8"))
_HOST, _PORT = _PLAN["target_host"], int(_PLAN["target_port"])
_MAX_BODY = _PLAN["max_body_bytes"]


def _emit(obj):
    line = _b64.b64encode(_json.dumps(obj, ensure_ascii=False).encode("utf-8")).decode("ascii")
    _sys.stdout.write("ASA-EVIDENCE " + line + "\\n")
    _sys.stdout.flush()


def _describe(requests):
    chunks = []
    for r in requests:
        head = "%s %s" % (r["method"], r["path"])
        for k, v in (r.get("headers") or {}).items():
            head += "\\n%s: %s" % (k, v)
        if r.get("body"):
            head += "\\n\\n" + r["body"]
        chunks.append(head)
    return "\\n\\n===== 下一条请求 =====\\n\\n".join(chunks)


def _issue(r):
    url = "http://%s:%d%s" % (_HOST, _PORT, r["path"])
    body = r.get("body")
    data = body.encode("utf-8") if body is not None else None
    req = _ureq.Request(url, data=data, method=r["method"])
    for k, v in (r.get("headers") or {}).items():
        req.add_header(k, v)
    started = _time.monotonic()
    status, text, error = None, "", None
    try:
        with _ureq.urlopen(req, timeout=r.get("timeout_s", 30)) as resp:
            status = resp.status
            text = resp.read(_MAX_BODY).decode("utf-8", "replace")
    except _uerr.HTTPError as exc:
        status = exc.code
        text = exc.read(_MAX_BODY).decode("utf-8", "replace")
    except Exception as exc:          # 连接被拒 / 超时 / 解析失败
        error = "%s: %s" % (type(exc).__name__, exc)
    return {
        "status": status,
        "body": text,
        "elapsed_ms": int((_time.monotonic() - started) * 1000),
        "error": error,
    }


def _start_app():
    try:
        proc = _subprocess.Popen(
            [_sys.executable, _PLAN["app_entry"]],
            cwd=_PLAN["workdir"],
            stdout=_subprocess.DEVNULL,
            stderr=_subprocess.DEVNULL,
        )
    except OSError as exc:
        return None, "start_failed: %s" % exc
    return proc, None


def _wait_port(timeout_s):
    deadline = _time.monotonic() + timeout_s
    while _time.monotonic() < deadline:
        sock = _socket.socket()
        sock.settimeout(0.5)
        try:
            if sock.connect_ex((_HOST, _PORT)) == 0:
                return True
        finally:
            sock.close()
        _time.sleep(0.25)
    return False


def main():
    proc, error = _start_app()
    ready = proc is not None and _wait_port(_PLAN["port_ready_timeout_s"])
    _emit({"kind": "bootstrap", "ready": ready, "error": error})
    for probe in _PLAN["probes"]:
        requests = probe["requests"]
        responses = [_issue(r) for r in requests]
        _emit(
            {
                "kind": "probe",
                "probe_id": probe["probe_id"],
                "responses": [
                    {
                        "status": r["status"],
                        "body": r["body"],
                        "elapsed_ms": r["elapsed_ms"],
                        "error": r["error"],
                    }
                    for r in responses
                ],
                "request_raw": _describe(requests),
            }
        )
    if proc is not None:
        proc.terminate()


main()
"""


def render_mission_script(probes: Sequence[Probe]) -> str:
    """渲染容器内的一次性任务脚本（部署靶场 + 跑完全部探针）。

    **为什么一次容器跑完一个 Finding 的全部探针，而不是一探针一容器**：
    契约 1 的 `run_once` 是「建容器 → 跑命令 → 删容器」的一次性语义，
    「部署一次环境、跑多条探针」只能在**一条命令内**完成；而且容器启动的成本
    远高于一次 HTTP 往返，20 条探针各起一个容器在 2 vCPU 上是纯浪费
    （B5 设计 §7 B5-D7 的耗时账就是按「每组部署一次」算的）。

    附带收益：`elapsed_ms` 由容器内自测，不含控制面 → 数据面的网络抖动，
    时间盲注的窗口因此可以收窄（B5 设计 §4.2 末段）。
    """
    plan = {
        "target_host": probes[0].target[0] if probes else "127.0.0.1",
        "target_port": probes[0].target[1] if probes else 5000,
        "app_entry": "app.py",
        "workdir": "/workspace",
        "port_ready_timeout_s": 30,
        "max_body_bytes": MAX_EVIDENCE_BODY_BYTES,
        "probes": [
            {
                "probe_id": p.probe_id,
                "technique": p.technique.value,
                "requests": [r.model_dump() for r in render_requests(p)],
            }
            for p in probes
        ],
    }
    encoded = base64.b64encode(json.dumps(plan, ensure_ascii=False).encode("utf-8")).decode("ascii")
    return f'ASA_PLAN_B64 = "{encoded}"\n' + _EXECUTOR_BODY


def render_probe_script(probe: Probe) -> str:
    """单探针脚本（B5 设计 §3.2 的 `render_probe_script`）。

    就是只含一条探针的任务脚本 —— 复用同一条代码路径，避免「单探针版本」与
    「批量版本」两份执行器各自演化出偏差（那正是「本地跑得通、线上不对」的经典成因）。
    """
    return render_mission_script([probe])


def bootstrap_command() -> list[str]:
    """容器启动命令：把任务脚本经环境变量注入（base64 规避 Shell 转义），
    再由一段极短的引导语句 exec 出来。

    `command` 是 argv 列表、不经 shell 解析（契约 1 的 `ContainerSpec`），
    所以这里既没有引号地狱，也不会把非 ASCII 交给容器里的 shell。
    """
    return [
        "python",
        "-c",
        "import base64,os;exec(base64.b64decode(os.environ['ASA_MISSION_B64']))",
    ]


def mission_env(probes: Sequence[Probe], spec_env: dict[str, str] | None = None) -> dict[str, str]:
    """构造容器环境变量：任务脚本本体 + 调用方附加项。"""
    script = render_mission_script(probes)
    env = {"ASA_MISSION_B64": base64.b64encode(script.encode("utf-8")).decode("ascii")}
    if spec_env:
        env.update(spec_env)
    return env
