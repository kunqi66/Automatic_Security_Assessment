"""B5-A 内部值对象与跨模块协议（B5 模块设计 §3.3）。

**为什么单开一个 `types.py` 而不是把定义散进各文件**（与 B1 `projects/types.py`
同一理由）：`Probe` 被 `probe.py` 造、被 `guard.py` 查、被 `runner.py` 跑；
`VerificationResult` 被 `runner.py` 产出、被 B3 消费。定义散在四处必然出现
「probe 定义了 technique，guard 又定义一遍」的漂移。

**这里只放值对象与协议，不放任何逻辑** —— 逻辑在 `probe.py` / `guard.py` /
`fingerprints.py` / `runner.py`，那是四个能各自单测的确定性模块。
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, Field

from app.core.config import settings
from app.models.enums import VulnStatus

# ---------------------------------------------------------------------------
# 技术白名单与判定方式（B5 设计 §4.2 / §4.3 的封闭集合）
# ---------------------------------------------------------------------------


class Technique(StrEnum):
    """探针技术 —— **封闭集合**。

    「封闭」是安全属性不是整理癖：`guard.py` 的行为闸门做的就是
    「载荷形态 ↔ 声明技术的白名单式一致性校验」。集合一旦开放，
    闸门就只能退回黑名单匹配，而黑名单永远可以绕过（`DRO/**/P`、十六进制、
    大小写混写）。**能枚举的技术才能被白名单守住。**
    """

    BOOLEAN_BLIND = "boolean_blind"  #: SQL 布尔盲注：1=1 与 1=2 的响应长度差
    #: SQL 只读 UNION：回显 nonce。原名 `UNION_VERSION` —— 载荷当时取的是
    #: `version()`，而那是 MySQL/PG 专有函数，**SQLite 没有**（实测：
    #: `no such function: version`）。PRD §10.1 的靶场恰恰是 SQLite，
    #: 也就是说交付的载荷打不穿自己文档规定的靶场。改成常量表达式后
    #: 与方言无关，因此一并改名 —— 名字里留着 version 会让人以为还要取版本号。
    UNION_EXTRACT = "union_extract"
    TIME_BLIND = "time_blind"  #: 命令/时间盲注：sleep 造成的耗时增量
    ECHO_NONCE = "echo_nonce"  #: 命令注入回显：echo nonce
    UPLOAD_MARKER = "upload_marker"  #: 上传 `<nonce>.txt` 再回读
    PATH_TRAVERSAL_READ = "path_traversal_read"  #: 读一个已知只读文件
    IDOR_HORIZONTAL = "idor_horizontal"  #: 用 A 的会话读 B（均为自造数据）的接口
    UNAUTH_PROBE = "unauth_probe"  #: 无凭证直取只读接口
    READ_CONFIG = "read_config"  #: 探测配置/调试接口
    DESER_MARKER = "deser_marker"  #: 无副作用标记对象的反序列化回显


class ExpectedKind(StrEnum):
    """特征闸门的判定方式（B5 设计 §3.3）。

    `BOOLEAN_DIFFERENTIAL` 是**对设计文档的扩展**，理由见其注释。
    """

    CONTENT_NONCE = "content_nonce"
    TIME_WINDOW = "time_window"
    STATUS_CODE = "status_code"
    ERROR_ECHO = "error_echo"
    #: ⚠️ 设计 §3.3 只列了上面四种，这里多一种。理由是**判定必须留在控制面的
    #: 确定性代码里**：布尔盲注的本质是「两次响应的差异 + 对照组的稳定性」，
    #: 如果让容器内的探针脚本自己算完再回一个 true/false，那「判定依据」就变成
    #: 探针脚本自证 —— 而它正是我们唯一不信任的那一段（它跑在靶场旁边）。
    #: 所以脚本只回原始事实（三个响应长度），由 `fingerprints.py` 做判定。
    BOOLEAN_DIFFERENTIAL = "boolean_differential"


class InjectIn(StrEnum):
    """载荷注入位置（B5 设计 §8 待定项 6）。**同样是封闭集合。**"""

    QUERY = "query"
    BODY = "body"
    HEADER = "header"
    PATH = "path"


#: 判定依据是**固定的、与注入无关的特征**的技术 —— **封闭集合，可枚举**。
#:
#: 这三类探针刻意不注入任何标记，因为它们的结论不依赖"我注入了什么"：
#:   * `PATH_TRAVERSAL_READ` —— 读一个**本来就存在**的文件，锚点是它的已知内容
#:     （`root:x:0:0:`；读不到就是真的读不到）；
#:   * `READ_CONFIG` —— 请求一个**本就不该可达**的路径，锚点是配置项的特征
#:     （`SECRET_KEY=`）；
#:   * `UNAUTH_PROBE` —— **不带任何输入**地请求一个静态分析判定「缺鉴权」的端点，
#:     锚点是"无凭证却拿到了业务 JSON"这个形态本身。
#:
#: 这与"黑名单没命中就放行"是两回事：集合是封闭的、可枚举的，且三者都是只读动作。
#: 任何新增技术想进这个集合，都要先回答"它的锚点凭什么不依赖注入"。
FIXED_ANCHOR_TECHNIQUES: frozenset[Technique] = frozenset(
    {Technique.PATH_TRAVERSAL_READ, Technique.READ_CONFIG, Technique.UNAUTH_PROBE}
)

#: 靠「对照组 vs 探针」的差异下结论的判定方式。
#:
#: 这类探针也不需要注入标记 —— **对照本身就是锚点**：命中与否取决于两次响应的
#: 差异（真/假分支、基线/延时），而这个差异是本次运行独有的。
CONTRAST_KINDS: frozenset[ExpectedKind] = frozenset(
    {ExpectedKind.BOOLEAN_DIFFERENTIAL, ExpectedKind.TIME_WINDOW}
)


class GateName(StrEnum):
    """四道闸门（B5 设计 §4.1）。**顺序即短路顺序**。"""

    BEHAVIOR = "behavior"  #: ① 构造期：技术 ∈ 白名单、探针自证无副作用
    PAYLOAD = "payload"  #: ② 执行前：纯文本检查，零成本
    NETWORK = "network"  #: ③ 环境就绪后发包前：目标 ∈ 硬白名单
    FEATURE = "feature"  #: ④ 响应回收后：nonce / 时间窗命中


class ReasonCode(StrEnum):
    """闸门拒绝原因（B5 设计 §3.3 的封闭集合 + 三处扩展）。

    这个枚举直接进 `poc_attempts.failure_reason` 与前端提示，
    所以取值必须是**机器可判定的短码**，不是一句话。
    """

    # 这是**分类名**不是口令：它给「破坏性语句里的关键字」这一类比命个名，
    # 用于匹配 `DROP TABLE` 这类载荷。S105 在这里是误报。
    DESTRUCTIVE_TOKEN = "DESTRUCTIVE_TOKEN"  # noqa: S105
    REVERSE_SHELL = "REVERSE_SHELL"
    WRITE_SOURCE = "WRITE_SOURCE"
    LENGTH_EXCEEDED = "LENGTH_EXCEEDED"
    PROBE_QUOTA_EXCEEDED = "PROBE_QUOTA_EXCEEDED"
    BEHAVIOR_MISMATCH = "BEHAVIOR_MISMATCH"
    NONCE_MISSING = "NONCE_MISSING"
    TARGET_NOT_WHITELISTED = "TARGET_NOT_WHITELISTED"
    #: 扩展 ①：载荷里出现了回环之外的地址。设计把「外连」并进 `REVERSE_SHELL`，
    #: 这里拆出来是因为**成因不同、修法不同**：反弹 shell 是载荷形态问题，
    #: 外连是目标地址问题（比如 LLM 或模板顺手写了个 http:// 收集端）。
    EXTERNAL_TARGET = "EXTERNAL_TARGET"
    #: 扩展 ②：技术不在白名单表里（没有对应探针模板），构造期就拦掉。
    TECHNIQUE_NOT_WHITELISTED = "TECHNIQUE_NOT_WHITELISTED"
    #: 扩展 ③：该漏洞类型没有无害化探针模板。**不等于「不存在」**，
    #: 所以它落在 `unverified` 而不是任何「已证伪」的分支上。
    NO_PROBE_TEMPLATE = "NO_PROBE_TEMPLATE"


class Verdict(StrEnum):
    """单 Finding 验证行为的**三态结论**。

    - `VERIFIED`：探针跑通且特征闸门命中 —— 漏洞在沙箱中真实可利用。
    - `UNVERIFIED`：探针跑了（或本该跑而没跑成）却**没能确认**。
      ⚠️ **「没验证出来」不等于「不存在」**：只读探测天然有覆盖盲区
      （只读探针触发不了「写才发作」的漏洞）。落库时这一态还要再细分，
      见 `VerificationResult.status`。
    - `SKIPPED`：**这个 Finding 的验证动作根本没发生** —— 沙箱不可达，
      或探针额度在构造期就被耗尽。它是基础设施问题，不是漏洞问题。
    """

    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    SKIPPED = "skipped"


class SkipReason(StrEnum):
    """`Verdict.SKIPPED` 的具体成因。给 B3 判断「阶段要不要整体标 skipped」。"""

    SANDBOX_UNREACHABLE = "SANDBOX_UNREACHABLE"
    PROBE_QUOTA_EXCEEDED = "PROBE_QUOTA_EXCEEDED"


# ---------------------------------------------------------------------------
# 探针（B5 设计 §3.3）
# ---------------------------------------------------------------------------


class RenderedRequest(BaseModel):
    """一条已经渲染好的 HTTP 请求。

    存在的意义是**把载荷构造留在控制面**：容器里的执行器只是一个「发这些请求、
    回原始事实」的哑执行器，它不含任何构造逻辑，也就不存在「载荷在容器里才拼出来、
    闸门没看到过」的盲区。过闸门的字符串与真正发出去的字符串是同一个。
    """

    method: str
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    timeout_s: int = 30
    #: 该请求在本次探针里的角色，进证据让前端能解释「这三条请求分别是什么」
    label: str = ""


class Probe(BaseModel):
    """一个探针 = 一次无害化探测的最小单元（B5 设计 §3.3）。

    相对设计文档多了三个字段（`payload` / `inject_in` / `aux_path`），
    每个都是被闸门或渲染器实际需要的，注释里写明理由。
    """

    probe_id: str
    vuln_id: int
    technique: Technique
    #: ⚠️ 设计 §3.3 漏了 `payload`。它是**载荷闸门唯一的检查对象**、
    #: 也是 `poc_attempts.payload` 列的内容、还是行为白名单反查形态的依据 ——
    #: 没有它，「无害化」这句话在数据模型里就没有落点。
    payload: str
    method: str
    url_path: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    #: 对照组载荷。布尔盲注的 `1=2` 形式、时间盲注的基线请求（`; :`）——
    #: **没有对照组就没有「差异」**，而「差异」是这两类技术唯一的判据。
    #: 空白表示本技术不需要对照组。
    control_payload: str = ""
    #: 载荷落在哪个参数上（query key / form key / header name）。
    #: 构造期从污点路径的符号名推导，推导失败则用该技术的默认参数名。
    param_name: str = ""
    #: `param_name` 是否**就是该模板声明的参数名**（`default_param`）。
    #:
    #: ⚠️ 这个字段决定「未命中」能不能拿去证伪，理由是实测出来的：
    #: 模板的路由是**写死**的（`/search` 永远读 `q`），而参数是从 finding 的
    #: 污点路径推导的。两者一旦不一致，探针就是在**往一个不读该参数的路由**
    #: 上注入 —— `/search?username=...` 里的 `username` 会被 Flask 直接忽略，
    #: 响应体与基线一模一样。而 SQL 注入的判定方式是布尔差分：
    #: 「无差异」于是被读成「此处不可注入」，一条真注入被记成 `rejected`。
    #:
    #: 所以：**推导来的参数名只能用来找机会，不能用来下结论。** 见
    #: `fingerprints.py::_is_conclusive`。
    param_is_canonical: bool = True
    #: 本探针的**路由与参数是否来自 finding 自己**（`routes.bind_route` 反查所得）。
    #:
    #: ⚠️ 这个字段决定「命中了」能不能算作**这一条** finding 的证据。理由是实测出来的：
    #: 模板把路由写死（sqli 两条模板都是 `/search`），于是三条 SQL 注入 finding
    #: —— 分别在 `/search`、`/api/order/query`、`/admin/login` —— 各跑了一遍同一个
    #: `/search?q=` 探针，然后**各自**都被记成「已通过动态验证」。
    #: 靶场实测：15 条 finding 里 10 条的"验证"发生在**别的端点**上。
    #:
    #: **「该类漏洞在本目标上存在」与「这一行被跑通了」是两件事。**
    #: `True` = 探针打在 finding 自己的端点上，命中即这一条成立；
    #: `False` = 打的是模板的固定路由，命中只证明类别成立，只能算 `potential`。
    #: 见 `runner.py` 的裁决分支与 `docs/探针路由绑定.md`。
    bound_to_finding: bool = False
    #: 载荷在**这个注入点的语法上下文**里成立吗（`context.infer_sink_context`）。
    #:
    #: ⚠️ 路由绑定对了之后才看得见的一个新坑：`1 AND 1=1` 打
    #: `/search`（`WHERE id = ` + q）是真注入，打 `/admin/login`
    #: （`username = '…'`）会被拼成 `username = '1 AND 1=1'` ——
    #: **一条合法但恒假的 SQL**，响应无差异，于是"没测到"又被写成"不存在"。
    #: `False` = 载荷进不了语法位置，**未命中不再有否证力**。
    payload_fits_context: bool = True
    #: 载荷注入位置。设计 §8 待定项 6（query/body/header/cookie）在详细设计定稿为
    #: 前三者 + 路径段；cookie 未纳入，因为靶场不使用 cookie 传递用户输入。
    inject_in: InjectIn = InjectIn.QUERY
    #: 二次请求路径：上传后回读、正文之外的第二个端点。为空表示本探针只需一条请求。
    aux_path: str | None = None
    nonce: str = ""
    expected_kind: ExpectedKind = ExpectedKind.CONTENT_NONCE
    expected_pattern: str = ""
    #: 容器内 (host, port)。**恒为回环地址** —— 见 `guard.check_network`。
    target: tuple[str, int] = ("127.0.0.1", 5000)
    timeout_s: int = 30
    #: 行为闸门自证：构造期置 False 的探针**不生成**（见 probe.py 的模板表）。
    side_effect_free: bool = True


#: 单条探针载荷的长度上限（B5 设计 §4.3）。不是「大载荷更危险」这一条理由 ——
#: 是**一枚 8KB 的载荷说明它已经不是在探测，而是在传输**。
MAX_PAYLOAD_BYTES = 8 * 1024

#: 容器内执行器回传单条响应体的上限。响应只用来做特征匹配与证据留存，
#: 不设上限等于让靶场（或被控靶场）用一个巨型响应撑爆控制面的内存。
MAX_EVIDENCE_BODY_BYTES = 8 * 1024


class ProbeSkip(BaseModel):
    """被裁掉 / 拒绝的探针。

    **超限的探针必须留下记录，不能静默丢弃**：报告里「本次只验证了 N 个注入点」
    与「一个都没验证」是完全不同的结论，而这两者只看 `probes` 列表是分不出来的。
    """

    probe_id: str
    technique: str
    reason_code: ReasonCode
    reason: str


class ProbePlan(BaseModel):
    """一个 Finding 的探针计划。"""

    probes: list[Probe] = Field(default_factory=list)
    skipped: list[ProbeSkip] = Field(default_factory=list)
    #: 是否因 `max_probes_per_vuln` 被截断
    truncated: bool = False
    #: 完整候选集的规模（截断前）。`len(probes) + len(skipped)` 不一定等于它 ——
    #: 被闸门在构造期拒掉的探针不计入 skipped（它们从未成为候选）。
    candidate_count: int = 0


# ---------------------------------------------------------------------------
# 闸门与判定结果
# ---------------------------------------------------------------------------


class ProbeSurface:
    """探针「实际发出去的全部字符串」的投影。

    ⚠️ **载荷闸门必须跑在它上面，而不是只跑在 `payload` 上。** 载荷可以落在
    query、form body、header 或 URL 段里（`InjectIn`），只盯 `payload` 字段
    既会漏（header 注入的载荷不在 payload 里）也会误杀（`payload` 里是占位符、
    真实值在渲染后的 URL 上）。

    但 `url_path` / `aux_path` **不参与破坏性词扫描** —— 它们是我们写死的端点提示
    （`/api/update` 是「更新接口」而不是 `UPDATE` 语句），把端点名当载荷审查
    会制造一整类误报。它们只参与「外连目标」与「注入锚点」两类检查。
    """

    __slots__ = ("_payload_parts", "_route_parts")

    def __init__(self, payload_parts: list[str], route_parts: list[str]) -> None:
        self._payload_parts = [p for p in payload_parts if p]
        self._route_parts = [p for p in route_parts if p]

    @classmethod
    def of(cls, probe: Probe) -> ProbeSurface:
        return cls(
            # 只收**内容**：header 的**值**是内容（载荷可能藏在里面），
            # header 的**名**与参数名是标识符 —— 一个叫 `delete` 的表单字段名
            # 不该被当成 `DELETE` 语句。这个区分能让误报少一整类。
            payload_parts=[
                probe.payload,
                probe.control_payload,
                probe.body or "",
                *probe.headers.values(),
            ],
            route_parts=[probe.url_path, probe.aux_path or "", probe.param_name],
        )

    @property
    def payload_text(self) -> str:
        """注入内容侧的全部文本（供破坏性词 / 反弹 shell 扫描）。"""
        return "\n".join(self._payload_parts)

    @property
    def all_text(self) -> str:
        """全部出口文本（供 nonce 完备性与外连目标检查）。"""
        return "\n".join([*self._payload_parts, *self._route_parts])

    def contains(self, needle: str) -> bool:
        return bool(needle) and needle in self.all_text


class GuardVerdict(BaseModel):
    """一道闸门的判定（B5 设计 §3.3）。**确定性纯函数的返回值。**"""

    passed: bool
    failed_gate: GateName | None = None
    reason_code: ReasonCode | None = None
    reason: str = ""  #: 中文，直接进 poc_attempts 与前端提示
    matched_token: str | None = None  #: 命中的黑名单词，便于解释


class MatchResult(BaseModel):
    """特征闸门（④）的判定结果。

    `evidence` 是给人看的**判定依据**（「响应体第 3 行出现了 nonce abc123」
    「基线 120ms、探针 3120ms，差值落在 3000±600 窗口内」）——
    没有它，`matched=True` 只是一个不可追问的布尔值。
    """

    matched: bool
    observed: str = ""
    reason: str = ""


class ProbeResponse(BaseModel):
    """探针在容器内执行后的原始事实集合。

    **这一层刻意不含任何判定**：状态码、响应体、耗时、错误 —— 全是事实。
    判定在 `fingerprints.py` 里做，因为那里是纯函数、可穷举单测。
    """

    probe_id: str
    executed: bool = True
    request_raw: str = ""
    response_raw: str = ""
    http_status: int | None = None
    elapsed_ms: int = 0
    #: 容器内执行器的原始证据（响应长度组、基线耗时等）。结构随技术不同，
    #: 由 `fingerprints.py` 按 `probe.expected_kind` 解释。
    evidence: dict[str, Any] = Field(default_factory=dict)
    #: 容器内异常（连接被拒 / 超时 / 解析失败）。**不是漏洞不存在** —— 它只说明
    #: 这一次探测没拿到结论。
    error: str | None = None


# ---------------------------------------------------------------------------
# 验证结果（→ B3 → poc_attempts / vulnerabilities）
# ---------------------------------------------------------------------------


class PocAttempt(BaseModel):
    """一次探针的执行记录 ↔ `poc_attempts` 表。

    字段名**逐字照抄 `app/models/vulnerability.py` 的 `PocAttempt` 列名**（契约 2 的
    同一条规则：DTO 叫 probe、列叫 technique 这种映射是纯翻译税，而且字段错位
    最容易藏在这种地方）。B5 不 import `app/db/`，所以这里只给可序列化的 DTO，
    落库由 B3 做。

    ⚠️ **下面三个字段没有对应的 ORM 列**，B5 侧照常产出它们（证据链只多不少），
    **落库那一步由 B3 决定怎么映射**（已定案）：

    - `probe_id`（设计 §8 待定项 1 未定案）→ **不落库**。`technique` + `payload`
      已能唯一定位到具体探针；`app/schemas/` 与前端都没有消费者读它，
      为它加列是给一个不存在的需求做迁移。
    - `failed_gate` / `reason_code` → **压进 `failure_reason` 一列**，
      形如 `[gate=HARMLESS_GUARD reason=PAYLOAD_REJECTED] 载荷含破坏性动词`。
      依据是 PRD §6 对 `failure_reason` 的定义：
      「未通过验证的原因 / **被闸门拦截的原因**」—— 正好就是这两个码要说的事。

    为什么不补列：**PRD §6 是列名的唯一来源**（本项目命名 SSOT），加列要先改 PRD。
    见 `app/agents/poc_verify.py` 的 `_failure_reason`，以及
    `tests/test_agents_contract.py::test_落库关键字都是真实的_ORM_列` ——
    那条测试用 AST 扫源码，防的正是「DTO 字段与 ORM 列漂移、跑到那条分支才抛
    `TypeError`」这一类错。
    """

    vulnerability_id: int
    #: ⚠️ **`poc_attempts` 表没有 `probe_id` 列**（B5 设计 §8 待定项 1 未定案），B3 已定案不落库。
    #: 这里先带上，让 B3 有机会在迁移落地后写进去；不写也不会丢信息 ——
    #: `technique` + `payload` 已经能定位到具体是哪一条探针。
    probe_id: str = ""
    payload: str = ""
    technique: str = ""
    request_raw: str = ""
    response_raw: str = ""
    expected_pattern: str = ""
    matched: bool = False
    elapsed_ms: int = 0
    http_status: int | None = None
    harmless_guard_passed: bool = False
    failure_reason: str | None = None
    #: 被哪道闸门拦下的（仅闸门拦截时有值），便于前端区分「被拦下」与「没打中」
    failed_gate: GateName | None = None
    reason_code: ReasonCode | None = None


class VerificationResult(BaseModel):
    """单 Finding 的完整验证闭环结果（B5 设计 §3.3 + 本次扩展）。

    **两个结论字段并存是刻意的，它们回答不同的问题**：

    - `verdict`（三态）：**这次的验证动作**得到了什么。B3 据此决定阶段是否降级、
      前端据此显示「已验证 / 未验证 / 未执行」。
    - `status`（四态）：`vulnerabilities.status` 该落什么值。`unverified` 还要再分成
      `potential`（风险模式仍在，只是没证实）与 `rejected`（被动态证伪）——
      这是 B5 作为**状态唯一裁决者**的产出（B5 设计 §1.2），**B4 不产出这两态**。

    设计 §3.3 把这两个问题压进了一个 `verdict: verified|potential|rejected` 字段，
    结果是「沙箱连不上」这个既非潜在也非证伪的状态无处安放。拆开后：
    `Verdict.SKIPPED` + `status=POTENTIAL` 就表达得出来。
    """

    vuln_id: int
    verdict: Verdict
    status: VulnStatus
    matched_probe_id: str | None = None
    attempts: list[PocAttempt] = Field(default_factory=list)
    cvss_before: float = 0.0
    cvss_after: float = 0.0
    #: 中文，直接进报告与前端：**为什么它只是 potential / 为什么它被证伪**
    unverified_reason: str | None = None
    skip_reason: SkipReason | None = None
    executed_probe_count: int = 0
    skipped_probe_count: int = 0  #: 因超额 / 闸门 / 无模板而未执行的探针数
    #: 本条验证（含容器部署与全部探针）的真实墙钟耗时
    elapsed_ms: int = 0


class VerifyOutcome(BaseModel):
    """一个批次的验证结果（B5 设计 §3.1）。B3 的 `PocVerifyAgent` 的产出类型。"""

    results: list[VerificationResult] = Field(default_factory=list)
    #: False ⇒ 沙箱整体不可达，**B3 必须把阶段标 `skipped` 并继续跑后续阶段**（L4）
    sandbox_reachable: bool = True
    probe_count: int = 0
    executed_count: int = 0
    verified_count: int = 0
    unverified_count: int = 0
    skipped_count: int = 0
    #: 落库口径（四态），与上面的行为口径分开计数 —— 混在一起会让
    #: 「3 个未验证」这句话有两种读法
    potential_count: int = 0
    rejected_count: int = 0
    elapsed_ms: int = 0


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------


class SandboxConfig(BaseModel):
    """B5 侧的沙箱参数视图。

    ⚠️ **这不是 `sandbox_configs` 表那一行，也不是 B2 的 ORM 视图。**
    同名三处、语义各不相同（ORM 行 / 本视图 / `schemas.admin.SandboxConfigOut`），
    别混用。

    来源两条，优先级明确：

    1. `from_admin_config(row)` —— 管理页配的默认沙箱。B3 在**每次运行开始时**
       读 `sandbox_configs` 里 `is_default` 那行，注入 `AssessmentContext.sandbox_config`
       （总纲 §6.1 的那个注入点）。
    2. `from_settings()` —— 回落。表为空、行读坏了、或调用方没传 `cfg` 时走这条。

    回落是**允许的降级**（总纲 L3）：它保证「管理页没配」不会让动态验证失败，
    只会退回 `core/config.py` 的默认值 —— 也就是接通管理页之前的行为。
    """

    preset_image: str
    #: 下面三个的上下界与 `SandboxConfigUpdate`、数据库校验层**同一套值**。
    #: 这里再加一道，是因为写接口不是唯一的写入途径：直接改库能绕过接口的
    #: `ge/le`，而一个 `memory_limit_mb=0` 的行在 Docker 里意味着**不限内存** ——
    #: 部署机是 2 vCPU / 7.3G 无 swap，后果是一次静默的全机 OOM，不是一条报错。
    #: 越界值在这里抛错，由 `engine._resolve_sandbox_config` 捕获后回落并告警。
    cpu_limit: float = Field(default=0.5, gt=0, le=16)
    memory_limit_mb: int = Field(default=256, ge=128, le=32768)
    #: 单探针上限（配置项 `sandbox_exec_timeout_seconds`，默认 30s）。
    #: 20 × 30s = 600s 是单 Finding 的病态上界（B5 设计 §7 B5-D7）——
    #: 上限不是目标，是最坏情况的封顶。
    probe_timeout_s: int = Field(default=30, ge=1, le=3600)
    #: 该批次的容器总时长上限（部署 + 全部探针）。到点由 B2 强杀。
    #:
    #: 720s 来自设计 §7 B5-D7 的账：20 探针 × 30s 超时 = 600s（病态上界）
    #: + 环境部署 ≤ 60s + 余量。取 180s 会把一个「探针多但都很快」的正常组
    #: 拦腰截断，而截断的表现是「后面的探针没有证据」——那不是错误，是静默降级，
    #: 最难查的一类问题。
    container_timeout_s: int = 720
    max_probes_per_vuln: int = 20
    #: 回环地址硬白名单。**不是配置项而是不变量**：探针只在容器内打自己，
    #: 任何非回环目标都不该出现，出现即拒。
    allowed_hosts: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
    target_port: int = 5000
    workdir: str = "/workspace"
    #: 靶场启动入口（相对 workdir）。依赖已预置进镜像，**运行期不 pip install**
    #: （B5 设计 §7 B5-D13：容器无出网，pip 需要联网，二者互斥）。
    app_entry: str = "app.py"
    #: 端口就绪探活的等待上限
    port_ready_timeout_s: int = 30

    @classmethod
    def from_settings(cls, **overrides: Any) -> SandboxConfig:
        return cls(
            preset_image=settings.sandbox_default_image,
            probe_timeout_s=settings.sandbox_exec_timeout_seconds,
            max_probes_per_vuln=settings.max_probes_per_vuln,
            **overrides,
        )

    @classmethod
    def from_admin_config(cls, row: Any) -> SandboxConfig:
        """把管理页那一行（`sandbox_configs` 表）转成引擎侧参数。

        参数是**鸭子类型**、不是 ORM 类型：本模块不许 import `db/`（分层铁律），
        所以这里只按属性名取值，由 B3 负责把行读出来递给它。

        **只映射真正生效的字段。** 没映射的四个各有原因，写在这里是为了下次
        有人想加回 `network_policy` 时能先看到这段话：

        - `network_policy` —— 容器**恒为** `network_disabled=True`（`runner.py`），
          这跟 `allowed_hosts` 一样是**不变量而不是配置项**。让管理页能改网络模式，
          等于给一个自动化攻击工具开出一条出网的路；写入侧的 `_guard_network`
          只拦 `bridge`，真正兜底的是这里根本不读它。
        - `max_concurrency` —— 调度并发由 worker 固定为 1（总纲 §8.1），
          引擎侧没有对应的执行参数可填。
        - `is_default` / `name` —— 这两个是用来**选**这一行的，不是行内的参数。
        """
        return cls(
            preset_image=row.base_image,
            cpu_limit=row.cpu_limit,
            memory_limit_mb=row.memory_limit_mb,
            probe_timeout_s=row.timeout_seconds,
        )


# ---------------------------------------------------------------------------
# 跨模块协议（输入侧）
# ---------------------------------------------------------------------------
#
# 三个 Protocol 的存在理由相同：**B5 要的只是「形状」，不是「类型」**。
#
# B4 的 `Finding`（契约 2 说在 `app/analysis/types.py`）与 B3 上下文里的
# `FindingRef`（`orchestrator/context.py`，只有 vuln_id / rule_id / vuln_type /
# severity / file_path / line_start）是**两种不同的东西**，而 B5 两种都要能吃：
# 探针构造需要 `Finding` 的污点路径与 sink 符号，而调度阶段 B3 手上只有
# `FindingRef`（完整记录在 `vulnerabilities` 表里，按需回表）。
#
# 如果 B5 硬 import `app.analysis.types.Finding`，那么 B4 落地前后、以及
# 「B3 传 ref 还是传 Finding」这两件事都会变成 B5 的编译错误。
# 用 Protocol 表达「我只需要这些属性」，两个来源都能对上，且
# **B5 对 B4 保持纯数据依赖**（B5 设计 §1.2 的关键边界）。


class TaintStepLike(Protocol):
    """污点路径上的一跳（契约 2 的 `TaintStep`）。"""

    step_index: int
    file_path: str
    line: int
    column: int
    symbol: str
    step_kind: str
    snippet: str


class FindingLike(Protocol):
    """B5 消费的 Finding 视图。

    字段名与企业 `Finding` 一致（契约 2）；标 `?` 的在 `FindingRef` 上不存在，
    取值时用 `_attr()` 兜默认值，**不得假设它一定有**。
    """

    vuln_type: str  #: `VulnType`（StrEnum，是 str 子类）
    file_path: str
    # --- FindingRef 已有 ---
    rule_id: str
    severity: Any
    line_start: int
    # --- 仅完整 Finding 有 ---
    line_end: int
    symbol: str
    cwe_id: str | None
    cvss_vector: str
    cvss_score: float
    confidence: float
    source_kind: str
    sink_kind: str
    guard_blocked: bool
    taint_path: tuple[TaintStepLike, ...]


class WorkspaceHandleLike(Protocol):
    """B1 `WorkspaceHandle` 的本模块视图。

    `src_root` 是**控制面**本地路径（补丁校验要在本地副本上干跑）；
    `mount_host_path` 是**ECS 宿主侧**路径（`ContainerSpec.source_mount` 由远端
    Docker 解析）。两者不可互换 —— 契约 5 要求绝对路径只在 `projects/workspace.py`
    与 `sandbox/` 两处换算，所以 B5 只**用**这两个值，不自己拼。
    """

    project_id: int
    src_root: Any  #: pathlib.Path（控制面）
    mount_host_path: str  #: 数据面宿主路径


class AssessmentContextLike(Protocol):
    """B5 用到的上下文视图（B3 `AssessmentContext` 的子集）。

    只读 `assessment_id`（打日志用）。**不 import `app.orchestrator/`** ——
    那是 L3 内部的横向依赖，B5 设计 §1.2 明确「B5 是被调用的引擎，不是协调者」。
    """

    assessment_id: int
