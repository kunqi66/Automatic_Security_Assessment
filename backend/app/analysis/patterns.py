"""非数据流规则（设计文档 §2 的 patterns、§4.5 的 IDOR 流程）。

数据流追不到的两类漏洞，必须用**结构化模式**判：

- **IDOR**：漏洞本体是「缺少一次鉴权判断」，不是「数据从 A 流到 B」。
  数据流图里根本没有「本该存在但不存在」的边 —— 这是污点分析的原理性盲区，
  不是实现不够好。
- **硬编码凭据**：没有任何 source，秘密本身就写在代码里。

**两类规则都标 `detection_method=PATTERN`**（`app/models/enums.py`）。
这个字段是给人看的：TAINT_INTRA / TAINT_INTER / PATTERN 三档，
让复核者一眼知道「这条是靠数据流定的，还是靠形状猜的」，
从而决定该花多少时间去验。把三种证据强度混成一种，是这个模块最容易挨问的设计。

**误报是这类规则的死穴**（设计文档 §7.2 取舍 3）：两条规则都往「宁可漏」一侧配 ——
IDOR 要求「路由 + id 形参 + 体内用到 + **全程找不到任何鉴权痕迹**」四条同时成立，
少一条就不报。
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from app.analysis.finding import make_finding
from app.analysis.parser import (
    ParsedFile,
    call_args,
    call_function_node,
    dotted_name,
    node_line,
    snippet_of,
    walk_named,
)
from app.analysis.symbols import FunctionDef, SymbolTable
from app.analysis.types import Finding, TaintStep, VulnType
from app.models.enums import DetectionMethod, TaintStepType

# ---------------------------------------------------------------------------
# 规则置信度（设计文档 §4.5 的公式只适用于数据流 Finding，pattern 类各自定）
# ---------------------------------------------------------------------------

#: IDOR：四条判据同时成立才报，但「没有鉴权」这一条是**基于命名**的推断 ——
#: 自定义的鉴权中间件、装饰器、SaCheckPermission 这类框架注解都可能看不出来。
#: 0.55 表达的就是这个不确定度，而不是「约等于半对」。
IDOR_CONFIDENCE = 0.55

#: 未授权访问：与 IDOR 同为**缺席证明**（"函数体里找不到鉴权痕迹"），
#: 不确定度同源。比 IDOR 低一点，是因为它多了一条**基于表名**的推断
#: （"这条路由读的是账号数据"），而表名同样可能被绕开
#: （视图、ORM 实体、`FROM t_user`）。两条推断叠起来，置信度就该低于单条。
UNAUTH_ACCESS_CONFIDENCE = 0.5

#: 硬编码凭据：字面量本身是硬事实（不依赖任何推断），不确定的只是
#: 「这个值是不是真的凭据」（可能是占位符）。所以比 IDOR 高。
HARDCODED_SECRET_CONFIDENCE = 0.6

#: pattern 类 Finding 的 `source_kind` / `sink_kind` 取值。
#:
#: 注意：`source_kind` 在数据流 Finding 里来自 `sources.CHANNELS`
#: （http_param / env …）。pattern 类的「来源」是源码本身或路由形参声明，
#: 用 `source_code` / `route_param` 两个新词。这一点要在契约里写清楚，
#: 否则下游按 CHANNELS 做枚举校验时这两条会被判成脏数据。
PATTERN_SOURCE_CODE = "source_code"
PATTERN_ROUTE_PARAM = "route_param"
IDOR_SINK_KIND = "pattern:id_param_without_authz"
UNAUTH_SINK_KIND = "pattern:account_read_without_auth"
SECRET_SINK_KIND = "pattern:literal_secret"  # noqa: S105 —— 是规则名，不是口令

# ---------------------------------------------------------------------------
# IDOR（设计文档 §4.5）
# ---------------------------------------------------------------------------

#: 「像对象标识」的形参名。`_id` 结尾、或这几个约定俗成的短名。
_ID_EXACT_NAMES = frozenset({"id", "uid", "uuid", "pk", "oid", "gid"})

#: 以 `id` 结尾但**明显不是标识**的英文词。
#:
#: 用「以 id 结尾」而不是枚举 `order_id/ticket_id/...` 是为了不随靶场增补而膨胀，
#: 但代价是 `valid` / `paid` / `solid` 这类词会被误判成 id。
#: 与其把正则写成枚举，不如把已知的误伤词列出来 —— 这张表**可枚举**，
#: 而且加一个词的代价是零。空表也能跑（只是误报多一点），不是必需依赖。
_NON_ID_WORDS = frozenset(
    {
        "valid",
        "invalid",
        "paid",
        "unpaid",
        "void",
        "avoid",
        "solid",
        "rapid",
        "humid",
        "liquid",
        "android",
    }
)


def is_id_like(name: str) -> bool:
    """形参名是否像对象标识（IDOR 判据之一）。"""
    lowered = name.lower()
    if lowered in _ID_EXACT_NAMES:
        return True
    if lowered.endswith("_id"):
        return True
    return lowered.endswith("id") and lowered not in _NON_ID_WORDS


#: 鉴权**装饰器**的末段名（`@login_required` / `@jwt_required()`）。
_AUTH_DECORATORS = frozenset(
    {
        "login_required",
        "requires_auth",
        "require_auth",
        "auth_required",
        "jwt_required",
        "permission_required",
        "requires_permission",
        "roles_required",
        "roles_accepted",
        "requires_roles",
        "authenticated",
        "ensure_authenticated",
        "verify_token",
        "token_required",
        "admin_required",
        "sa_check_permission",
        "check_permission",
    }
)

#: 鉴权**函数调用**的末段名。命中任意一个即认为「体内有鉴权」→ 不报 IDOR。
_AUTH_CALLS = _AUTH_DECORATORS | {
    "get_current_user",
    "get_current_active_user",
    "get_user_or_404",
    "current_user_or_404",
    "load_user",
    "identify_user",
    "verify_jwt",
    "decode_token",
    "decode_access_token",
    "authenticate",
    "authorize",
    # FastAPI 的权限依赖惯用名：`Depends(require(Permission.X))`。
    # 单段名 `require` 用后缀匹配会误伤 `require_optional()` 之类无关调用，
    # 但这里是**「有证据就不报」**的方向 —— 认错的代价是漏一条 IDOR，
    # 而不认的代价是每个带权限依赖的接口都报（本项目自扫 21 条全是这类）。
    "require",
    "assert_permission",
    "verify_permission",
    "is_authorized",
    "has_permission",
    "has_role",
    "check_owner",
    "assert_owner",
    "verify_owner",
    "is_owner",
    "check_access",
    "can_access",
    "require_login",
    "login_required",
    "permission_denied",
    "forbidden",
    "unauthorized",
    "validate_csrf",
}

#: 鉴权**对象/属性**的点分尾名（`request.user` / `current_user` / `g.user`）。
_AUTH_OBJECTS = frozenset(
    {
        "request.user",
        "request.identity",
        "g.user",
        "g.current_user",
        "current_user",
        "login_manager.current_user",
        "session.user",
    }
)

#: 条件里出现这些**局部名**即认为有归属校验（`if owner != session["uid"]`）。
_AUTH_LOCAL_NAMES = frozenset(
    {
        "current_user",
        "is_admin",
        "is_authenticated",
        "authenticated",
        "authorized",
        "owner",
        "owner_id",
        "user_id",
        "permission",
        "permissions",
        "role",
        "roles",
        "has_access",
    }
)

#: `abort(...)` / `send_error(...)` 里这几个状态码代表「已做访问控制」。
_DENY_STATUS_CODES = frozenset({"401", "403"})


#: 注解里出现的「调用名」：`Annotated[User, Depends(require(...))]` → `require`。
#: 只从注解里取**调用**，不取标识符 —— `user_id: int` 这种注解遍地都是，
#: 把它当鉴权证据会让所有「id 参数 + 带注解」的真实漏洞全部被压掉。
_ANNOTATION_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def collect_auth_aliases(table: SymbolTable) -> frozenset[str]:
    """项目里被定义成「权限依赖类型别名」的名字。

    FastAPI 项目普遍这么写：

    ```python
    ProjectViewer = Annotated[User, Depends(require(Permission.PROJECT_VIEW))]
    ...
    async def get_project(project_id: int, _viewer: ProjectViewer) -> ProjectOut: ...
    ```

    鉴权证据全在**模块级赋值**里，函数签名上只剩一个名字。
    不看这张别名表，这类接口会被整片判成「没有任何鉴权痕迹」——
    实测本仓库自扫时，21 条 IDOR 里有 19 条是这一种。
    """
    aliases: set[str] = set()
    for assignments in table.module_assignments.values():
        for assignment in assignments:
            for node in walk_named(assignment.node):
                if node.type != "call":
                    continue
                inner = call_function_node(node)
                if inner is None:
                    continue
                if dotted_name(inner).rsplit(".", 1)[-1] in _AUTH_CALLS:
                    aliases.add(assignment.name)
                    break
    return frozenset(aliases)


def _has_authz_evidence(function: FunctionDef, auth_aliases: frozenset[str] = frozenset()) -> bool:
    """函数里是否存在**任何**鉴权痕迹（五条判据，见模块 docstring）。

    实现上刻意用「宽进」的名字匹配：只要出现一个像鉴权的符号就叫停。
    代价是漏报（真有漏洞但作者恰好写了个叫 `owner` 的无关变量），
    收益是不误报。对 IDOR 这种**「本该有而没有」**的漏洞，
    误报率直接决定这个规则能不能开 —— 一条总在喊的规则最终会被关掉。
    """
    for decorator in function.decorators:
        if decorator.rsplit(".", 1)[-1] in _AUTH_DECORATORS:
            return True

    # 形参默认值 `Depends(get_current_user)` 也是鉴权（FastAPI 的主流写法）
    for default in function.defaults.values():
        for node in walk_named(default):
            if node.type == "call":
                inner = call_function_node(node)
                if inner is not None and dotted_name(inner).rsplit(".", 1)[-1] in _AUTH_CALLS:
                    return True

    # 形参注解：`Annotated[User, Depends(require(...))]`，或签到了权限依赖别名
    for annotation in function.annotations.values():
        for called in _ANNOTATION_CALL_RE.findall(annotation):
            if called in _AUTH_CALLS:
                return True
        for alias in auth_aliases:
            if re.search(rf"\b{re.escape(alias)}\b", annotation):
                return True

    for node in walk_named(function.body):
        node_type = node.type
        if node_type == "call":
            inner = call_function_node(node)
            if inner is None:
                continue
            dotted = dotted_name(inner)
            tail = dotted.rsplit(".", 1)[-1]
            if tail in _AUTH_CALLS:
                return True
            if tail in ("abort", "send_error") and _has_deny_status(node):
                return True
        elif node_type == "attribute":
            dotted = dotted_name(node)
            if dotted in _AUTH_OBJECTS or dotted.rsplit(".", 1)[-1] in {
                "current_user",
                "is_authenticated",
            }:
                return True
        elif node_type == "identifier":
            text = node.text.decode("utf-8", errors="replace")
            # 形参名本身**不作为**鉴权证据。
            #
            # `user_id` / `owner_id` 在 `_AUTH_LOCAL_NAMES` 里的本意是
            # 「体内出现了归属标识，说明作者写了归属校验」。但 `user_id`
            # 同时是路由路径形参最常见的名字，而**形参出现在函数体里是必然的**
            # （不用它才是 bug）—— 于是判据 ② 与判据 ④ 互相抵消：
            # 凡是形参叫 `user_id` 的 IDOR，四条判据永远凑不齐。
            # 实测：`/api/user/<user_id>/profile`（PRD §10.2 的 V5 形状）
            # 因此被静默压掉，而这是 IDOR 最标准的一种写法。
            #
            # 同一道理本模块已对**注解**用过一次（见 `_ANNOTATION_CALL_RE` 的
            # 注释：「`user_id: int` 这种注解遍地都是」）；函数体这一支当时漏了。
            # 形参若真被用作鉴权（`if user_id != session["uid"]`），
            # 证据在比较的另一侧（`session[...]`），不在形参本身。
            if text in function.params:
                continue
            if text in _AUTH_OBJECTS or text in _AUTH_LOCAL_NAMES:
                return True
    return False


def _has_deny_status(call_node: object) -> bool:
    """`abort(403)` / `abort(401)` —— 只认**字面量**状态码。"""
    for value in call_args(call_node):
        if value.type == "integer":  # type: ignore[attr-defined]
            if value.text.decode("utf-8", errors="replace") in _DENY_STATUS_CODES:  # type: ignore[attr-defined]
                return True
    return False


def _first_use_line(function: FunctionDef, param_name: str) -> tuple[int, str] | None:
    """形参在函数体里**第一次被用到**的行与片段。

    返回 None 表示「声明了但没用」—— 这类形参不产出 Finding：
    没被用过的 id 参数不可能构成越权访问，报了就是纯噪声。
    """
    best: tuple[int, str] | None = None
    for node in walk_named(function.body):
        if node.type != "identifier":
            continue
        if node.text.decode("utf-8", errors="replace") != param_name:
            continue
        line = node_line(node)
        snippet = snippet_of(node.parent) if node.parent is not None else snippet_of(node)
        if best is None or line < best[0]:
            best = (line, snippet)
    return best


def detect_idor(files: tuple[ParsedFile, ...], table: SymbolTable) -> tuple[Finding, ...]:
    """IDOR 模式规则（设计文档 §4.5 的流程图）。

    四条判据**全部**成立才产出 Finding：

    1. 该函数是路由处理器（有路由装饰器）；
    2. 存在一个「像对象标识」的形参（`uid` / `order_id` / `id`）；
    3. 该形参在函数体里被用到；
    4. 函数体与装饰器里找不到任何鉴权痕迹。

    第 4 条是本规则的**全部难度所在**，也是精度的主要上限：
    它只能认出「命名像鉴权」的代码。自定义的鉴权中间件、
    `@SaCheckPermission` 这类第三方注解、或在**调用方**做的校验，
    都会让它误报。所以置信度 0.55，且 `detection_method=PATTERN`
    如实标注证据强度。
    """
    findings: list[Finding] = []
    # 别名表在**全项目**层面算一次：它由模块级赋值构成，与具体路由无关
    auth_aliases = collect_auth_aliases(table)
    for function in sorted(table.functions.values(), key=lambda f: f.qualname):
        if not function.is_route:
            continue
        for param_name in function.params:
            if not is_id_like(param_name):
                continue
            # 路由模板里显式出现 `{uid}` 时，参数一定是外部可控的；
            # 没有模板（Flask 的 `request.args.get` 写法）也照样报 ——
            # 名字像 id 就已经足够可疑，剩下的交给人工复核
            usage = _first_use_line(function, param_name)
            if usage is None:
                continue
            if _has_authz_evidence(function, auth_aliases):
                continue
            usage_line, usage_snippet = usage
            param_line = next(
                (node_line(node) for name, node in function.param_nodes if name == param_name),
                function.line,
            )
            steps = (
                TaintStep(
                    step_index=0,
                    file_path=function.file_path,
                    line=param_line,
                    column=0,
                    symbol=param_name,
                    step_kind=TaintStepType.SOURCE,
                    snippet=snippet_of(function.node),
                ),
                TaintStep(
                    step_index=1,
                    file_path=function.file_path,
                    line=usage_line,
                    column=0,
                    symbol=param_name,
                    step_kind=TaintStepType.SINK,
                    snippet=usage_snippet,
                ),
            )
            findings.append(
                make_finding(
                    vuln_type=VulnType.IDOR,
                    file_path=function.file_path,
                    line_start=usage_line,
                    line_end=usage_line,
                    symbol=param_name,
                    steps=steps,
                    source_kind=PATTERN_ROUTE_PARAM,
                    sink_kind=IDOR_SINK_KIND,
                    guard_blocked=False,
                    detection_method=DetectionMethod.PATTERN,
                    confidence=IDOR_CONFIDENCE,
                )
            )
            break  # 一个路由只报一条：多个 id 形参重复报会让复核者很快失去耐心
    return tuple(findings)


# ---------------------------------------------------------------------------
# 未授权访问（设计文档 §4.5 之外的第五类；PRD §10.2 的 V6）
# ---------------------------------------------------------------------------

#: 账号 / 用户类表名（`FROM` 后面那串）。判据 5 用它来判断
#: 「这条路由读的是不是账号数据」。
#:
#: **公开数据不算**：`/search` 无鉴权是设计而不是缺陷 —— 一个把
#: `SELECT ... FROM products` 的路由报成未授权访问，会让这条规则
#: 在每个真实项目上刷屏，然后被关掉。所以这里只收账号类实体。
_ACCOUNT_TABLES = frozenset(
    {
        "user",
        "users",
        "sys_user",
        "sys_users",
        "admin_user",
        "admin_users",
        "account",
        "accounts",
        "member",
        "members",
        "customer",
        "customers",
        "employee",
        "employees",
        "staff",
        "profile",
        "profiles",
    }
)

#: 路径或函数名里带这些片段的端点**本来就该匿名可达**：登录、注册、找回密码。
#: 它们没有鉴权装饰器是设计，报出来是最吵的那种误报 —— 几乎每个项目都有。
_AUTH_ROUTE_HINTS = (
    "login",
    "logout",
    "signin",
    "signup",
    "register",
    "token",
    "captcha",
    "password",
    "auth",
    "oauth",
    "sso",
)

#: SQL 里的写操作关键字。出现即**不**报未授权访问（判据 5 的只读要求）。
_WRITE_SQL_RE = re.compile(
    r"\b(?:INSERT|UPDATE|DELETE|REPLACE|DROP|ALTER|TRUNCATE|CREATE)\b", re.IGNORECASE
)
_SELECT_RE = re.compile(r"\bSELECT\b", re.IGNORECASE)
_FROM_RE = re.compile(r"\bFROM\s+([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)


def _sql_literals(function: FunctionDef) -> Iterator[tuple[object, str]]:
    """函数体里**作为调用实参**出现的字符串字面量。

    ⚠️ 只认调用实参，不认"所有字符串"。理由是硬的：函数的 docstring 也是
    字符串，而它里面**会**出现 SQL 关键字 —— 本文件往下的 `update_profile`
    夹具说明里就写着"写入"，靶场里也大量出现 `SELECT` 这个词。
    扫全文的话，一句说明文字就能凭空造出一条读操作、或者把一条读操作
    压成写操作，而且**两个方向都不报错**。
    """
    for node in walk_named(function.body):
        if node.type != "call":
            continue
        for arg in call_args(node):
            if arg.type == "string":
                yield arg, arg.text.decode("utf-8", errors="replace")


def _route_paths(function: FunctionDef) -> tuple[str, ...]:
    """路由装饰器里的路径字面量（`@app.route("/api/user/list")` → `/api/user/list`）。"""
    out: list[str] = []
    for decorator in function.decorator_nodes:
        if decorator.type != "call":
            continue
        for arg in call_args(decorator):
            if arg.type == "string":
                out.append(arg.text.decode("utf-8", errors="replace").strip("\"'"))
    return tuple(out)


def _looks_like_auth_route(function: FunctionDef) -> bool:
    """登录/注册类端点 —— 它们**本该**匿名可达，不报。"""
    haystack = " ".join((function.qualname, *_route_paths(function))).lower()
    return any(hint in haystack for hint in _AUTH_ROUTE_HINTS)


def _account_read(function: FunctionDef) -> tuple[int, str, str] | None:
    """函数体里有没有「对账号表的只读 SELECT」。返回 `(行号, 表名, 片段)`。"""
    for node, text in _sql_literals(function):
        if not _SELECT_RE.search(text) or _WRITE_SQL_RE.search(text):
            continue
        for table in _FROM_RE.findall(text):
            if table.lower() in _ACCOUNT_TABLES:
                return node_line(node), table.lower(), snippet_of(node)
    return None


def _has_write_sql(function: FunctionDef) -> bool:
    return any(_WRITE_SQL_RE.search(text) for _, text in _sql_literals(function))


def detect_unauth_access(files: tuple[ParsedFile, ...], table: SymbolTable) -> tuple[Finding, ...]:
    """未授权访问规则（PRD §10.2 的 V6）。

    与 IDOR 同源 —— 两者都是**缺席证明**（"本该有的那一行不在"），
    所以复用同一套「宽进」的鉴权痕迹匹配（`_has_authz_evidence`）。
    但判据刻意错开，因为两条规则的**证据必须是两件事**：

    1. 该函数是路由处理器；
    2. 函数体与装饰器里找不到任何鉴权痕迹；
    3. 它不是登录 / 注册类端点（那些本来就不该有鉴权）；
    4. 它**既没有 id 形参、也没有路由路径形参** —— 有的话归 IDOR；
    5. 它读的是**账号类表**，且是**只读**的。

    ## 判据 4：和 IDOR 的分界线

    带 id 形参 = "认了人但没校验这个资源是不是他的" → **IDOR**。
    不带 id 形参 = "压根没问来人是谁，整张表端出去" → **未授权访问**。
    同一条路由同时满足两者的情况不存在（判据 4 直接排除了），
    所以一个端点只会被其中一条规则报，不会重复计一条 finding。

    ## 判据 5：精度全在这里，方向是「宁可漏报」

    「读的是账号数据」靠表名匹配，而表名可以被绕开（视图、ORM 实体、
    `FROM t_user`、把表名拼进变量）。认不出来就**不报** ——
    对这个规则来说，"没认出来"的代价是漏一条，而"认错了"的代价是
    每个项目都刷屏然后规则被关掉。两条 `_WRITE_SQL_RE` 的同理：
    写操作的未授权（未授权**修改**）是另一个类别，本项目暂时没有规则覆盖它，
    所以这里显式排除，而不是顺手报成 V6。
    """
    findings: list[Finding] = []
    auth_aliases = collect_auth_aliases(table)
    for function in sorted(table.functions.values(), key=lambda f: f.qualname):
        if not function.is_route:
            continue
        if _looks_like_auth_route(function):
            continue
        if _has_authz_evidence(function, auth_aliases):
            continue
        # 判据 4：带 id 形参或路由路径形参的一律让给 IDOR
        if function.route_params:
            continue
        if any(is_id_like(name) for name in function.params):
            continue
        read = _account_read(function)
        if read is None or _has_write_sql(function):
            continue
        line, table_name, snippet = read
        route = _route_paths(function)
        steps = (
            TaintStep(
                step_index=0,
                file_path=function.file_path,
                line=function.line,
                column=0,
                symbol=route[0] if route else function.qualname,
                step_kind=TaintStepType.SOURCE,
                snippet=snippet_of(function.node),
            ),
            TaintStep(
                step_index=1,
                file_path=function.file_path,
                line=line,
                column=0,
                symbol=table_name,
                step_kind=TaintStepType.SINK,
                snippet=snippet,
            ),
        )
        findings.append(
            make_finding(
                vuln_type=VulnType.UNAUTH_ACCESS,
                file_path=function.file_path,
                line_start=line,
                line_end=line,
                symbol=table_name,
                steps=steps,
                source_kind=PATTERN_ROUTE_PARAM,
                sink_kind=UNAUTH_SINK_KIND,
                guard_blocked=False,
                detection_method=DetectionMethod.PATTERN,
                confidence=UNAUTH_ACCESS_CONFIDENCE,
            )
        )
    return tuple(findings)


# ---------------------------------------------------------------------------
# 硬编码凭据
# ---------------------------------------------------------------------------

#: 凭据味的变量名（`DB_PASSWORD` / `secret_key` / `apiKey` 都命中）。
#:
#: 名字**不带下划线前缀**：`taint.py` 处理超大文件时会直接复用这个正则与
#: `is_secret_literal`（那条路径不解析 AST，只做行级匹配）。
#: 跨模块复用的是**同一份规则**，不是「同规则的第二个副本」——
#: 复制一份的话，两边会随着迭代慢慢变得不一样。
SECRET_NAME_RE = re.compile(
    r"(?i)(?:^|_)(?:pass(?:word|wd)?|pwd|secret|token|api_?key|access_?key|secret_?key"
    r"|private_?key|signing_?key|encryption_?key|auth_?key|credential[s]?|app_?key"
    r"|client_?secret|jwt_?secret|db_?pass|smtp_?pass|master_?key)(?:$|_)"
)

#: 明显是占位符/示例的值。命中则不报 —— 这些值写进代码里是**正确做法**
#: （告诉后来者「这里要填你自己的」），报出来只会训练用户忽略这条规则。
#:
#: ⚠️ 正则的第一条**不能**写成空分支（`(?:|none|...)`）：那样 `match()`
#: 对任何字符串都成功，整条规则变成永不触发。空值由 `is_secret_literal`
#: 的长度下限单独拦，不需要在这里再表达一次。
_SECRET_PLACEHOLDERS = re.compile(
    r"(?i)^(?:none|null|changeme|change_me|placeholder|your[\-_ ]?(?:key|secret|token|password)"
    r"|xxx+|\*+|\.\.\.|<[^>]*>|\{\{.*\}\}|todo|fixme|dummy|example|test)"
)

#: 取环境变量时的默认值（`os.getenv("SECRET_KEY", "dev-secret")`）。
#: 这是**真实事故的常见形态**：生产环境变量没配好，代码默默用了开发默认值。
_ENV_GETTERS = frozenset({"os.getenv", "environ.get", "getenv", "os.environ.get"})

#: 这些后缀表明变量是**元数据常量**而不是凭据本体：
#: `SECRET_SINK_KIND = "pattern:literal_secret"` 会同时命中「名字里有 SECRET」
#: 与「值是字面量」两条，但它是规则名。自扫本仓库时正是这条误报。
#:
#: 只列**可枚举**的几个后缀，不做「名字里含有非凭据词」这类模糊判断 ——
#: 模糊判断会开始吞掉真凭据（`API_KEY_PATTERN = "sk-live-..."` 这种写法
#: 虽然少见但真实存在），而后缀白名单的误伤面可以用一句话说清。
_NON_SECRET_NAME_SUFFIXES = ("_kind", "_name", "_re", "_regex", "_pattern", "_symbol", "_rule")


def name_looks_like_secret(name: str) -> bool:
    """变量名是否像凭据。**只判名字**，值是另一条独立判据（`is_secret_literal`）。

    AST 路径与超大文件的行扫描路径都走这一处，避免两份规则慢慢漂移。
    """
    lowered = name.strip().lower()
    if lowered.endswith(_NON_SECRET_NAME_SUFFIXES):
        return False
    return SECRET_NAME_RE.search(name) is not None


def _literal_string(node: object) -> str | None:
    """取字符串字面量的值；带插值（f-string）或不是字符串时返回 None。"""
    if node.type != "string":  # type: ignore[attr-defined]
        return None
    if any(child.type == "interpolation" for child in node.named_children):  # type: ignore[attr-defined]
        return None
    text = node.text.decode("utf-8", errors="replace")  # type: ignore[attr-defined]
    for prefix in ('r"', "r'", 'b"', "b'", 'rb"', "rb'", 'u"', "u'", 'f"', "f'"):
        if text.startswith(prefix):
            text = text[len(prefix) - 1 :]
            break
    return text.strip("\"'")


def is_secret_literal(value: str) -> bool:
    """值的形态是否像真凭据（而不是占位符或一条普通文案）。"""
    if len(value) < 6:
        return False
    if len(set(value)) <= 2:  # "aaaaaa" / "111111"
        return False
    return not _SECRET_PLACEHOLDERS.match(value.strip())


def make_secret_finding(
    *,
    file_path: str,
    line: int,
    name: str,
    snippet: str,
    via_env_default: bool = False,
) -> Finding:
    """组装一条硬编码凭据 Finding。

    抽成函数是因为它有**两个调用方**：AST 版（扫描模块级赋值）与
    行扫描版（超大文件的降级路径，见 `taint._oversize_secret_findings`）。
    两处各写一遍 `make_finding(...)` 的 12 个参数，迟早会有一处漏改参数名。
    """
    steps = (
        TaintStep(0, file_path, line, 0, name, TaintStepType.SOURCE, snippet),
        TaintStep(1, file_path, line, 0, name, TaintStepType.SINK, snippet),
    )
    return make_finding(
        vuln_type=VulnType.HARDCODED_SECRET,
        file_path=file_path,
        line_start=line,
        line_end=line,
        symbol=f"{name} (env 默认值)" if via_env_default else name,
        steps=steps,
        source_kind=PATTERN_SOURCE_CODE,
        sink_kind=SECRET_SINK_KIND,
        guard_blocked=False,
        detection_method=DetectionMethod.PATTERN,
        confidence=HARDCODED_SECRET_CONFIDENCE,
    )


def _env_default_value(right: object) -> object | None:
    """`os.getenv("SECRET_KEY", "fallback")` → 第二个实参节点。"""
    if right.type != "call":  # type: ignore[attr-defined]
        return None
    inner = call_function_node(right)
    if inner is None:
        return None
    if dotted_name(inner) not in _ENV_GETTERS:
        return None
    positional = list(call_args(right))
    if len(positional) < 2:
        return None
    return positional[1]


def detect_hardcoded_secrets(
    files: dict[str, ParsedFile], table: SymbolTable
) -> tuple[Finding, ...]:
    """硬编码凭据模式规则。

    只扫**模块级赋值**（不递归进函数体）。权衡：函数体内的硬编码凭据确实存在
    （`DEFAULT_PASSWORD = "admin123"` 写在某个函数里），但函数体内的字面量赋值
    数量是模块级的几十倍，全扫会把「默认参数、临时文案、正则片段」都卷进来。
    模块级赋值是「配置」所在的位置，也是真实事故的高发位置 ——
    精度换召回的取舍在这里明显划算。

    两种形态都认：字面量直接赋值、以及 `os.getenv("X", "硬编码默认值")`。
    后者往往比前者更危险：它看起来「已经从环境变量读了」，
    只有默认值这一半是硬编码的，代码评审时最容易被放过。
    """
    findings: list[Finding] = []
    for file_path in sorted(table.module_assignments):
        for assignment in sorted(table.module_assignments[file_path], key=lambda a: a.line):
            if not name_looks_like_secret(assignment.name):
                continue
            right = assignment.node
            value_node = right
            via_env_default = False
            if _literal_string(right) is None:
                env_default = _env_default_value(right)
                if env_default is None:
                    continue
                value_node, via_env_default = env_default, True
            value = _literal_string(value_node)
            if value is None or not is_secret_literal(value):
                continue
            findings.append(
                make_secret_finding(
                    file_path=file_path,
                    line=assignment.line,
                    name=assignment.name,
                    snippet=_line_snippet(files, file_path, assignment.line) or assignment.name,
                    via_env_default=via_env_default,
                )
            )
    return tuple(findings)


def _line_snippet(files: dict[str, ParsedFile], file_path: str, line: int) -> str:
    """取源码行。`SymbolTable` 刻意不持有源码（省内存），所以片段要回文件里取。"""
    parsed = files.get(file_path)
    if parsed is None:
        return ""
    return parsed.line_text(line)


def run_pattern_rules(files: tuple[ParsedFile, ...], table: SymbolTable) -> tuple[Finding, ...]:
    """跑全部 pattern 规则，返回**已排序**的 Finding 元组。

    结果在这里就排好序（而不是交给上层）：pattern 规则的产出顺序由
    dict 遍历顺序决定，上层若忘记排序，确定性就会在这里破一个口。
    """
    by_path = {parsed.rel_path: parsed for parsed in files}
    findings = [
        *detect_idor(files, table),
        *detect_unauth_access(files, table),
        *detect_hardcoded_secrets(by_path, table),
    ]
    return tuple(sorted(findings, key=lambda f: (f.file_path, f.line_start, f.rule_id)))
