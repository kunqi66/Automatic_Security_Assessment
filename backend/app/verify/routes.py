"""从 finding 反查它自己的 HTTP 端点（B5 探针路由绑定的落地）。

## 这个模块解决什么问题

B5 的探针模板把**路由写死**了（sqli 的两条模板 `url_path` 都是 `/search`）。
于是三条 SQL 注入 finding —— 分别位于 `/search`、`/api/order/query`、
`/admin/login` —— 各自跑了一遍**同一个** `/search` 探针，然后各自"通过"了。
报告里那三条都写着「已通过动态验证」，而验证它们的是**别的端点**。

实测跑出来的样子（`poc_attempts`）：

    vuln 48  app.py:88    → GET /search?q=   ✅ 这就是它自己的端点
    vuln 49  app.py:114   → GET /search?q=   ❌ 它自己的端点是 /api/order/query
    vuln 46  admin_login.py:43 → GET /search?q= ❌ 它自己的端点是 /admin/login

**"同类漏洞在本目标上存在"与"这一行被跑通了"是两件事**，而报告把它们印成了
同一句话。这个模块负责让后者成为可能：从 finding 的污点路径反查端点。

## 锚在 source，不锚在 sink

反查的起点是污点路径里的**请求侧那一步**，不是 sink 那一步。理由是实测的：
`admin_login.py:43` 的 sink 在一个**没有路由的辅助函数**里
（`check_login()`），路由在 `app.py:301` 的 `admin_login()`。
只看 sink 所在的文件，永远找不到那个装饰器。

    [source]      app.py:304          request.form.get("username", "")   ← 锚这里
    [propagate]   app.py:306          check_login(username, password)
    [propagate]   admin_login.py:29   def check_login(...)
    [sink]        admin_login.py:43   cursor.execute("SELECT role ...")

所以顺序是：source 步 → 其它步。任一步能落到某个带路由装饰器的函数体内，
绑定就成立。

## 这个模块**不做**什么

它只回答「端点在哪、参数叫什么、载荷往哪放」。它**不判断载荷能不能打穿** ——
那是探针模板与载荷闸门的事，而后者会给出一个令人不舒服但必须承认的结论：
**路由绑定对了，有些端点依然打不穿，因为需要的载荷形态不在闸门白名单里。**
详见 `docs/探针路由绑定.md`。
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from app.analysis.parser import ParsedFile, call_args, call_keyword_args, parse_file
from app.core.logging import get_logger
from app.verify.types import InjectIn

logger = get_logger(__name__)

#: 读源码的方式：相对路径 → 源码文本。注入它而不是直接开文件，
#: 是为了让 `bind_route` **对给定的 reader 是纯函数** —— 测试可以喂内存里的字符串，
#: 不必造一个目录树。
SourceReader = Callable[[str], str]


@dataclass(frozen=True, slots=True)
class RouteBinding:
    """一个 finding 绑到的端点。**每个字段都是反查出来的事实，不是猜的。**"""

    url_path: str
    """探针要打的路由。含路径参数时，被注的那一段写作 `{payload}` 占位。"""

    methods: tuple[str, ...]
    param_name: str | None
    """参数名。**可能是 None** —— 见 `_param_and_inject`：
    污点来源只记到通道（实测 `app.py:147` 的 snippet 就是光秃秃的 `request.files`），
    这时调用方用模板声明的 `default_param` 补上。**路由是对的，补的只是字段名。**"""

    local_var: str | None
    """承接这个输入的**局部变量名**。它与 `param_name` 常常不同名，而
    `context.py` 要靠它才能在 SQL 拼接链上认出注入点是哪一个操作数 ——
    实测 `/api/order/query` 的 HTTP 参数叫 `id`、局部变量却叫 `order_id`。"""

    inject_in: InjectIn
    route_file: str
    """路由装饰器所在的文件（**可能不是 finding 所在的文件**）。"""

    route_line: int
    anchor_file: str
    """用来绑定路由的那一步污点所在文件/行 —— 出错时靠它回溯。"""

    anchor_line: int

    @property
    def is_path_injected(self) -> bool:
        return self.inject_in is InjectIn.PATH


# ---------------------------------------------------------------------------
# 装饰器解析
# ---------------------------------------------------------------------------

#: 允许作为路由装饰器的属性名。`@app.route` 与 `@app.get/@app.post` 两种风格。
#: **封闭集合**：不是路由装饰器的东西一律不当路由，宁可绑不上也不误绑。
_ROUTE_ATTRS = frozenset({"route", "get", "post", "put", "patch", "delete"})

#: `methods=` 允许的 HTTP 动词。封闭集合，同理由。
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

#: 路径参数：`<int:user_id>` / `<name>` / `<path:name>`。
_PATH_PARAM = re.compile(r"<(?:(?P<conv>\w+):)?(?P<name>\w+)>")

#: 注入路径参数时的占位符。`render_requests` 认它，见 `probe._request`。
PATH_PAYLOAD_SLOT = "{payload}"


def _unquote(text: str) -> str:
    """去掉字符串字面量的引号与常见前缀（`r"..."` / `f"..."` 很少见于路由，但便宜）。"""
    stripped = text.strip()
    for prefix in ('r"""', "r'''", '"""', "'''", 'r"', "r'", '"', "'"):
        if stripped.startswith(prefix) and stripped.endswith(
            prefix[-1] if len(prefix) > 1 else prefix
        ):
            body = stripped[len(prefix) : -len(prefix[-1])]
            return body
    return stripped


def _decorator_route(dec: Any) -> tuple[str, tuple[str, ...]] | None:
    """从一个 `decorator` 节点里取出 `(path, methods)`；不是路由装饰器就返回 None。"""
    expr = next((c for c in dec.children if c.is_named), None)
    if expr is None or expr.type != "call":
        return None
    func = expr.child_by_field_name("function")
    if func is None or func.type != "attribute":
        return None
    attr = func.child_by_field_name("attribute")
    if attr is None:
        return None
    attr_name = attr.text.decode("utf-8", errors="replace")
    if attr_name not in _ROUTE_ATTRS:
        return None

    args = call_args(expr)
    if not args or args[0].type != "string":
        return None
    path = _unquote(args[0].text.decode("utf-8", errors="replace"))

    if attr_name != "route":
        # `@app.post("/x")` 形态：动词就在装饰器名里
        return path, (attr_name.upper(),)

    methods: list[str] = []
    kw = call_keyword_args(expr).get("methods")
    if kw is not None:
        for child in kw.children:
            if child.type == "string":
                name = _unquote(child.text.decode("utf-8", errors="replace")).upper()
                if name in _HTTP_METHODS:
                    methods.append(name)
    # FastAPI 式的 `@app.route` 不带 methods 时默认 GET；Flask 同理。
    return path, tuple(methods) or ("GET",)


def _route_of_line(parsed: ParsedFile, line: int) -> tuple[str, tuple[str, ...], int] | None:
    """文件里**哪个路由处理函数的函数体**覆盖了 `line`。

    只认带路由装饰器的 `decorated_definition`：一个普通函数即使覆盖了这一行，
    它也没有端点，绑定它等于编一个出来。
    """
    for node in parsed.root.children:
        if node.type != "decorated_definition":
            continue
        fn = next((c for c in node.children if c.type == "function_definition"), None)
        if fn is None:
            continue
        start, end = fn.start_point[0] + 1, fn.end_point[0] + 1
        if not (start <= line <= end):
            continue
        for dec in node.children:
            if dec.type != "decorator":
                continue
            found = _decorator_route(dec)
            if found is not None:
                path, methods = found
                return path, methods, dec.start_point[0] + 1
    return None


# ---------------------------------------------------------------------------
# 参数与注入位置（从请求侧那一步的 snippet 读）
# ---------------------------------------------------------------------------

#: `request.<通道>.get("x")` / `request.<通道>["x"]`。
#: 通道 → 注入位置是**固定的映射**，不是启发式：`args` 只能从 query 来，
#: `form`/`json`/`files` 只能从 body 来，`headers`/`cookies` 只能从 header 来。
_SNIPPET_ACCESSOR = re.compile(
    r"""request\s*\.\s*(?P<chan>args|form|json|files|values|headers|cookies)
        \s*(?:\.\s*get\s*\(\s*|\[\s*)['"](?P<name>[^'"]+)['"]""",
    re.VERBOSE,
)

_CHANNEL_INJECT: dict[str, InjectIn] = {
    "args": InjectIn.QUERY,
    "values": InjectIn.QUERY,
    "form": InjectIn.BODY,
    "json": InjectIn.BODY,
    "files": InjectIn.BODY,
    "headers": InjectIn.HEADER,
    "cookies": InjectIn.HEADER,
}

#: 路由路径参数的合成 snippet —— 与 `analysis/taint.py` 产出的文本**必须逐字一致**。
#: 两边约定同一个字符串是有点脆，所以这里用一个专门的测试钉住它
#: （`test_routes.py::test_路径参数_snippet_与分析器一致`）。
PATH_PARAM_SNIPPET = re.compile(r"^路径模板参数\s+(?P<name>\w+)$")


def _attribute_chain(node: Any) -> list[str]:
    """`request.args.get` → `["request", "args", "get"]`；不是纯属性链就返回 []。"""
    parts: list[str] = []
    cur = node
    while cur is not None and cur.type == "attribute":
        attr = cur.child_by_field_name("attribute")
        obj = cur.child_by_field_name("object")
        if attr is None or obj is None:
            return []
        parts.append(attr.text.decode("utf-8", errors="replace"))
        cur = obj
    if cur is None or cur.type != "identifier":
        return []
    parts.append(cur.text.decode("utf-8", errors="replace"))
    parts.reverse()
    return parts


def _string_arg(node: Any) -> str | None:
    """取第一个字符串字面量：`call` 取实参，`subscript` 取下标。

    ⚠️ `call` 的实参**不是它的直接子节点** —— 它们裹在 `argument_list` 里。
    第一版直接遍历 `node.children` 找 `string`，于是在
    `request.args.get("q", "1")` 上什么也找不到，参数名全成了 None。
    这里改用分析器已有的 `call_args`，它就是把 `argument_list` 拆开的那一层。
    """
    candidates = call_args(node) if node.type == "call" else node.children
    for child in candidates:
        if child.type == "string":
            return _unquote(child.text.decode("utf-8", errors="replace"))
    return None


def _accessor_of(node: Any) -> tuple[str | None, InjectIn] | None:
    """`request.<通道>...` 的访问节点 → `(参数名|None, 注入位置)`；不是就返回 None。"""
    if node.type == "call":
        func = node.child_by_field_name("function")
        chain = _attribute_chain(func) if func is not None else []
        if len(chain) >= 3 and chain[0] == "request" and chain[1] in _CHANNEL_INJECT:
            return _string_arg(node), _CHANNEL_INJECT[chain[1]]
        return None
    if node.type == "subscript":
        value = node.child_by_field_name("value")
        chain = _attribute_chain(value) if value is not None else []
        if len(chain) == 2 and chain[0] == "request" and chain[1] in _CHANNEL_INJECT:
            return _string_arg(node), _CHANNEL_INJECT[chain[1]]
        return None
    if node.type == "attribute":
        chain = _attribute_chain(node)
        # 光秃秃的 `request.files`：**通道已知，参数名未知**
        if len(chain) == 2 and chain[0] == "request" and chain[1] in _CHANNEL_INJECT:
            return None, _CHANNEL_INJECT[chain[1]]
    return None


def _accessor_in_line(
    parsed: ParsedFile, line: int
) -> tuple[str | None, InjectIn, str | None] | None:
    """在 `line` 这一行的 AST 里找 `request.<通道>` 访问。

    返回 `(参数名|None, 注入位置, 承接它的局部变量名|None)`。

    ## 为什么不直接读污点步骤的 snippet

    因为**实测它不够**。`app.py:147` 的真实代码是 `request.files.get("file")`，
    而分析器记下来的 snippet 是光秃秃的 `request.files` —— 参数名不在里面。
    只读 snippet 的话，这条 finding 的路由绑定会整个失败（第一版就是这么失败的）。

    所以这里回到源码本身去读那一行。snippet 只当**线索**（哪一行值得看），
    不当**答案**。

    ## 为什么优先认赋值语句

    因为**局部变量名只有赋值语句里有**。`order_id = request.args.get("id", "1")`
    里的 HTTP 参数是 `id`、局部变量是 `order_id`，而 `context.py` 要在 SQL 拼接链
    上按**局部变量**认注入点 —— 少了这一步，`/api/order/query` 的上下文读不出来
    （实测第一版就停在 `unknown`）。
    """
    fallback: tuple[str | None, InjectIn, str | None] | None = None
    stack = [parsed.root]
    while stack:
        node = stack.pop()
        # 行区间不相交就整棵子树剪掉 —— 子节点必在父节点区间内
        if node.end_point[0] + 1 < line or node.start_point[0] + 1 > line:
            continue
        if node.type in ("assignment", "augmented_assignment"):
            right = node.child_by_field_name("right")
            hit = _accessor_of(right) if right is not None else None
            if hit is not None and hit[0] is not None:
                left = node.child_by_field_name("left")
                var = left.text.decode("utf-8", errors="replace") if left is not None else None
                return hit[0], hit[1], var
            # 赋值给属性/下标（`self.q = request.args[...]`）也要能认，
            # 只是拿不到一个干净的变量名
            if hit is not None and fallback is None:
                fallback = (hit[0], hit[1], None)
        else:
            hit = _accessor_of(node)
            if hit is not None and hit[0] is not None and fallback is None:
                left = node.child_by_field_name("left")
                var = left.text.decode("utf-8", errors="replace") if left is not None else None
                fallback = (hit[0], hit[1], var)
            elif hit is not None and fallback is None:
                fallback = (hit[0], hit[1], None)
        stack.extend(node.children)
    return fallback


def _param_and_inject(
    parsed: ParsedFile,
    line: int,
    snippet: str,
    symbol: str,
    placeholders: Sequence[str],
) -> tuple[str | None, InjectIn, str | None] | None:
    """定出 `(参数名, 注入位置, 局部变量名)`。**顺序即优先级，每一步都有理由。**

    1. **源码 AST**（最可信）—— 那一行上真实写着 `request.form.get("username")`；
    2. **snippet 文本** —— AST 读不到时（行号漂了、语法错误）退回正则；
    3. **路径参数** —— 分析器用合成 snippet `路径模板参数 <name>` 标注，
       且 `name` 必须**确实是路由里的占位符**，否则绑出来的 URL 是编的；
    4. **光秃秃的通道** —— 通道能确定注入位置（query/body/header），
       参数名交给模板的 `default_param`。**这是唯一一处"名字来自模板"的地方，
       而它只发生在路由已经被反查确认之后。**
    """
    picked = _accessor_in_line(parsed, line)
    if picked is not None:
        return picked

    hit = _SNIPPET_ACCESSOR.search(snippet)
    if hit:
        name = hit.group("name")
        return name, _CHANNEL_INJECT[hit.group("chan")], name

    path_hit = PATH_PARAM_SNIPPET.match(snippet.strip())
    if path_hit and path_hit.group("name") in placeholders:
        return path_hit.group("name"), InjectIn.PATH, path_hit.group("name")

    # 分析器对路径参数标的 symbol 就是占位符名
    if symbol in placeholders:
        return symbol, InjectIn.PATH, symbol

    bare = re.fullmatch(r"request\s*\.\s*(?P<chan>\w+)", snippet.strip())
    if bare and bare.group("chan") in _CHANNEL_INJECT:
        return None, _CHANNEL_INJECT[bare.group("chan")], None
    return None


def _fill_placeholders(path: str, inject_name: str | None) -> tuple[str, tuple[str, ...]]:
    """把路由里的 `<conv:name>` 换成具体值；被注入的那一个换成 `{payload}`。

    非注入占位符填什么值是**确定性的选择**：`int` 填 `1`，其余填 `asa`。
    这里刻意不"智能地"挑一个存在的资源 id —— 那需要读数据库，
    而绑定的目的是**把载荷送到正确的位置**，不是猜业务数据。
    """
    names: list[str] = []

    def _sub(match: re.Match[str]) -> str:
        name = match.group("name")
        names.append(name)
        if name == inject_name:
            return PATH_PAYLOAD_SLOT
        return "1" if match.group("conv") == "int" else "asa"

    return _PATH_PARAM.sub(_sub, path), tuple(names)


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


def _steps(finding: Any) -> list[tuple[str, int, str, str]]:
    """污点路径里可以拿来定位端点的步骤，**请求侧优先**。

    返回 `(文件, 行, symbol, snippet)`。排序键只看 `step_kind` 是不是 source ——
    不按行号排，因为行号在跨文件时没有可比性。
    """
    out: list[tuple[int, str, int, str, str]] = []
    for step in getattr(finding, "taint_path", ()) or ():
        kind = str(getattr(step, "step_kind", "") or "")
        if hasattr(kind, "value"):
            kind = str(kind.value)
        if kind in ("sanitize",):
            continue
        where = str(getattr(step, "file_path", "") or "")
        line = int(getattr(step, "line", 0) or 0)
        if not where or line <= 0:
            continue
        out.append(
            (
                0 if kind.endswith("source") else 1,
                where,
                line,
                str(getattr(step, "symbol", "") or ""),
                str(getattr(step, "snippet", "") or ""),
            )
        )
    out.sort(key=lambda item: item[0])
    return [(w, line, sym, snip) for _, w, line, sym, snip in out]


def bind_route(reader: SourceReader, finding: Any) -> RouteBinding | None:
    """反查 finding 自己的端点。**对给定的 reader 是纯函数。**

    返回 None 是**正常结果**，不是失败：`config.py:26` 的硬编码密钥根本没有端点
    （它不是任何路由处理函数里的东西），绑不上就是绑不上。
    调用方必须把 None 当作「本条无法逐点验证」处理，而不是「用默认路由凑一个」。
    """
    cache: dict[str, ParsedFile | None] = {}
    for where, line, symbol, snippet in _steps(finding):
        rel = _rel(where)
        if rel not in cache:
            cache[rel] = _parse(reader, rel)
        parsed = cache[rel]
        if parsed is None:
            continue
        found = _route_of_line(parsed, line)
        if found is None:
            continue
        path, methods, route_line = found
        _, placeholders = _fill_placeholders(path, None)
        picked = _param_and_inject(parsed, line, snippet, symbol, placeholders)
        if picked is None:
            # 端点找到了，但**载荷该往哪放完全不知道** —— 这时返回 None
            # 而不是"用第一个参数顶上"：放错参数的探针会得到 200 + 无差异，
            # 而那正是把真注入判成 rejected 的那条老路。
            logger.info(
                "已定位端点 %s（%s:%d），但无法从污点来源确定注入位置，不绑定",
                path,
                rel,
                line,
            )
            continue
        param_name, inject_in, local_var = picked
        if inject_in is InjectIn.PATH and param_name is None:
            # 路径注入必须知道往哪个占位符里填，否则 URL 拼不出来
            continue
        url_path, _ = _fill_placeholders(path, param_name if inject_in is InjectIn.PATH else None)
        return RouteBinding(
            url_path=url_path,
            methods=methods,
            param_name=param_name,
            local_var=local_var,
            inject_in=inject_in,
            route_file=rel,
            route_line=route_line,
            anchor_file=rel,
            anchor_line=line,
        )
    return None


def _rel(path: str) -> str:
    """统一成相对路径。finding 的 `file_path` 可能是相对靶场根、也可能是绝对路径，
    两种都见过 —— 交给 reader 之前先取其文件名，与 `make_fs_reader` 的约定一致。"""
    return path.replace("\\", "/").split("/")[-1]


def _parse(reader: SourceReader, rel: str) -> ParsedFile | None:
    try:
        source = reader(rel)
    except Exception as exc:  # noqa: BLE001 —— 读不到就是绑不上，不该中断整轮验证
        logger.debug("读取 %s 失败，跳过路由绑定：%s", rel, exc)
        return None
    if not source:
        return None
    try:
        return parse_file(rel, source)
    except Exception as exc:  # noqa: BLE001
        logger.debug("解析 %s 失败，跳过路由绑定：%s", rel, exc)
        return None


__all__ = ["PATH_PAYLOAD_SLOT", "RouteBinding", "SourceReader", "bind_route"]
