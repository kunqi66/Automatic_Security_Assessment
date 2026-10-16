"""符号表与调用图（设计文档 §2 的 symbols）。

三条决定成败的实现选择：

1. **qualname 带模块路径**（`app.api.order.query_order`），与设计文档 §4.3 的
   示例 `qualname="app.query_order"` 一致。不带模块的话，两个 `utils.py` 里
   同名的 `query_order` 会互相顶掉摘要 —— 这种错不会报错，只会让跨函数结论
   静默地张冠李戴。

2. **同名冲突不猜**（设计文档 §6 场景 6）：简单名（`query_order`）在项目里
   出现两次以上，就把它记进 `ambiguous_names`，解析时**返回未解析**而不是
   随便挑一个。跨函数漏报（可复核、报告里标注未展开）远好于跨函数误报
   （把 A 模块的 sink 记到 B 模块的调用点上，人工复核时几乎无法发现）。

3. **不建 import 图，只做三种解析**（见 `resolve_call` 的 docstring）。
   完整的 import 图需要处理相对导入、包 `__init__`、动态 import，
   投入产出比很差；而真实漏洞的绝大多数是「同文件内调用」与
   「from utils import f 后按名调用」，这两类不需要 import 图。
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field

from app.analysis.parser import (
    ParsedFile,
    block_statements,
    call_function_node,
    dotted_name,
    node_line,
    walk_named,
)

#: 形参默认值是这几个「注入标注函数」调用时，该形参是框架注入的请求数据
#: （FastAPI 的 `uid: str = Query(...)`）。见 sources.PARAM_SOURCE_DEFAULTS。
_PARAM_SOURCE_DEFAULTS = frozenset(
    {"Query", "Path", "Body", "Form", "Header", "Cookie", "Depends", "File"}
)

#: 路由装饰器的**末段**名。`@app.route` / `@router.get` / `@bp.post` 都命中。
_ROUTE_METHODS = frozenset({"route", "get", "post", "put", "delete", "patch", "websocket"})

#: 明确**不是**路由的装饰器末段名。
#:
#: 没有这张否定表的话，`@property` 这类装饰器一旦末段名撞上 `_ROUTE_METHODS`
#: （比如某个项目自定义了 `@app.get_config`…）就会误判。更实际的作用是：
#: 让「这个函数是不是路由」的判断能被快速否掉，避免对每个函数都去解析路径模板。
_NON_ROUTE_DECORATORS = frozenset(
    {
        "property",
        "staticmethod",
        "classmethod",
        "abstractmethod",
        "lru_cache",
        "cache",
        "wraps",
        "contextmanager",
        "fixture",
        "setter",
        "deleter",
        "overload",
        "dataclass",
        "app.errorhandler",
        "errorhandler",
        "before_request",
        "after_request",
        "teardown_appcontext",
        "middleware",
    }
)

#: 路由路径模板里的参数名，三种主流写法：Flask `<id>`、FastAPI `{id}`、Django `<int:id>`。
_ROUTE_PARAM_PATTERNS = (
    re.compile(r"<(?:[^:<>]+:)?([A-Za-z_]\w*)>"),
    re.compile(r"\{([A-Za-z_]\w*)\}"),
    re.compile(r":([A-Za-z_]\w*)"),
)


@dataclass(frozen=True, slots=True)
class FunctionDef:
    """一个函数/方法定义。`body` 与 `node` 是 tree-sitter 节点，只在本进程内使用。"""

    qualname: str
    name: str
    file_path: str
    line: int
    end_line: int
    params: tuple[str, ...]  # 位置形参名（不含 self/cls、不含 *args/**kw）
    defaults: dict[str, object]  # 形参名 → 默认值节点
    annotations: dict[str, str]  # 形参名 → 注解文本（如 "str" / "Request"）
    decorators: tuple[str, ...]  # 点分名
    decorator_nodes: tuple[object, ...]
    param_nodes: tuple[tuple[str, object], ...]  # (形参名, 标识符节点) —— 供污点入口取行号
    body: object
    node: object
    enclosing_class: str | None
    is_async: bool
    is_route: bool
    route_params: frozenset[str]  # 路由路径模板里的参数名
    has_varargs: bool
    has_kwargs: bool
    #: 形参名 → 该形参在形参列表里的下标（跨函数按位置匹配用；`self` 已剔除）
    param_index: dict[str, int] = field(default_factory=dict)

    @property
    def param_names(self) -> tuple[str, ...]:
        return self.params


@dataclass(frozen=True, slots=True)
class ClassDef:
    qualname: str
    name: str
    file_path: str
    line: int
    methods: tuple[str, ...]  # 方法名（不含类前缀）


@dataclass(frozen=True, slots=True)
class ModuleAssignment:
    """模块级赋值。用于常量表（白名单集合）与硬编码密钥检测。"""

    name: str
    node: object  # 右值节点
    line: int


@dataclass(frozen=True, slots=True)
class SymbolTable:
    functions: dict[str, FunctionDef]
    classes: dict[str, ClassDef]
    #: 简单名 → qualname 元组（长度 >1 即冲突）
    by_name: dict[str, tuple[str, ...]]
    #: 模块名 → 该模块内的 qualname 元组
    by_module: dict[str, tuple[str, ...]]
    #: 文件 → 模块级赋值
    module_assignments: dict[str, tuple[ModuleAssignment, ...]]
    #: 文件 → 导入的模块别名（`import a.b as c` 记 c，`import a.b` 记 a）
    import_aliases: dict[str, dict[str, str]]
    #: 项目里出现多次、无法唯一解析的简单名
    ambiguous_names: frozenset[str]

    def candidates(
        self, dotted: str, file_path: str, enclosing_class: str | None
    ) -> tuple[str, ...]:
        """把一次调用的点分名解析成**候选 qualname**。空元组表示「解析不到」。

        只认三种形态，其余一律不解析（宁可漏报）：

        1. `self.x` / `cls.x`（在类方法内）→ 本类的方法；
        2. 完全点分名命中 qualname（`User.get` / `module.Class.get`）；
        3. 简单名（`query_order`）在项目里**唯一**存在；
           或 `别名.名` 且别名是项目内模块（`import utils` + `utils.query_order`）。

        刻意不做：跟随 `from x import *`、跟随变量赋值得到的函数引用
        （`f = handler; f(uid)`）、跟随装饰器改写签名。
        """
        if not dotted:
            return ()

        if dotted.startswith(("self.", "cls.")) and enclosing_class:
            member = dotted.split(".", 1)[1]
            qualname = f"{enclosing_class}.{member}"
            return (qualname,) if qualname in self.functions else ()

        if dotted in self.functions:
            return (dotted,)

        name = dotted.rsplit(".", 1)[-1]
        if name in self.ambiguous_names:
            return ()

        if "." not in dotted:
            return self.by_name.get(name, ())

        # `别名.名`：只有当别名指向**项目内模块**时才解析。
        # 没有这一条，项目里恰好有个叫 `join` 的函数就会让 `os.path.join`
        # 被解析过去 —— 那会让外部库调用被当成项目内调用并产出跨函数 Finding。
        head, _, rest = dotted.partition(".")
        module = self.import_aliases.get(file_path, {}).get(head)
        if module is None or "." in rest:
            return ()
        stem = module.rsplit(".", 1)[-1]
        for qualname in self.by_module.get(stem, ()):
            if qualname.rsplit(".", 1)[-1] == name:
                return (qualname,)
        return ()


# ---------------------------------------------------------------------------
# 构建
# ---------------------------------------------------------------------------


def module_name_of(rel_path: str) -> str:
    """`app/api/order.py` → `app.api.order`；`app/api/__init__.py` → `app.api`。

    与设计文档 §4.3 的 `qualname="app.query_order"` 口径一致（`app.py` → `app`）。
    """
    parts = rel_path.split("/")
    last = parts[-1]
    if last == "__init__.py":
        parts = parts[:-1]
    else:
        parts = [*parts[:-1], last[: -len(".py")] if last.endswith(".py") else last]
    return ".".join(p for p in parts if p)


def _decorated_definition_parts(node: object) -> tuple[tuple[object, ...], object | None]:
    """拆 `decorated_definition` → (装饰器节点, 被装饰的定义)。"""
    if node.type != "decorated_definition":  # type: ignore[attr-defined]
        return (), None
    decorators: list[object] = []
    definition: object | None = None
    for child in node.named_children:  # type: ignore[attr-defined]
        if child.type == "decorator":  # type: ignore[attr-defined]
            decorators.append(child)
        else:
            definition = child
    return tuple(decorators), definition


def decorator_name(decorator_node: object) -> str:
    """`@app.route("/x")` → `app.route`；`@login_required` → `login_required`。

    `@mod.deco(args)` 这类**带调用的装饰器**要取被调函数名，而不是取整个调用文本。
    """
    for child in decorator_node.named_children:  # type: ignore[attr-defined]
        if child.type == "call":  # type: ignore[attr-defined]
            inner = call_function_node(child)
            return dotted_name(inner) if inner is not None else ""
        return dotted_name(child)
    return ""


def decorator_string_args(decorator_node: object) -> tuple[str, ...]:
    """装饰器的字符串实参（路由路径在这里）。"""
    result: list[str] = []
    for child in decorator_node.named_children:  # type: ignore[attr-defined]
        if child.type != "call":  # type: ignore[attr-defined]
            continue
        for grandchild in walk_named(child):
            if grandchild.type == "string" and not any(  # type: ignore[attr-defined]
                g.type == "interpolation"
                for g in grandchild.named_children  # type: ignore[attr-defined]
            ):
                result.append(grandchild.text.decode("utf-8", errors="replace"))  # type: ignore[attr-defined]
    return tuple(result)


def parse_route_params(path_literals: Sequence[str]) -> frozenset[str]:
    """从路由路径模板里取出参数名（`<id>` / `{uid}` / `<int:id>`）。"""
    names: set[str] = set()
    for literal in path_literals:
        for pattern in _ROUTE_PARAM_PATTERNS:
            names.update(pattern.findall(literal))
    return frozenset(names)


def is_route_decorator(decorator_node: object) -> bool:
    """判断装饰器是不是路由注册。

    判据是**两条同时成立**：末段名属于 `_ROUTE_METHODS`，
    且（有以 `/` 开头的字符串实参 **或** 完全没有实参）。

    第二条是关键：只按名字判断会把 `@app.errorhandler(404)`（末段 `errorhandler`
    不在表里，安全）与「项目自定义的 `@bp.get_config`」这类混淆。
    而要求「路径以 `/` 开头」几乎不可能被非路由装饰器满足 ——
    `@lru_cache()` / `@login_required` 都过不了这一关。
    """
    name = decorator_name(decorator_node)
    if not name or name in _NON_ROUTE_DECORATORS:
        return False
    tail = name.rsplit(".", 1)[-1]
    if tail not in _ROUTE_METHODS:
        return False
    has_call = any(child.type == "call" for child in decorator_node.named_children)  # type: ignore[attr-defined]
    if not has_call:
        return True
    return any(
        literal.strip("'\"rfbu").startswith("/")
        for literal in decorator_string_args(decorator_node)
    )


def _iter_params(
    parameters_node: object | None,
) -> Iterator[tuple[str, object, object | None, str]]:
    """遍历 `parameters` 节点 → (名字, 标识符节点, 默认值节点, 注解文本)。"""
    if parameters_node is None:
        return
    for child in parameters_node.named_children:  # type: ignore[attr-defined]
        child_type = child.type  # type: ignore[attr-defined]
        if child_type == "identifier":
            yield child.text.decode("utf-8", errors="replace"), child, None, ""  # type: ignore[attr-defined]
        elif child_type in ("default_parameter", "typed_default_parameter"):
            name_node = child.child_by_field_name("name")  # type: ignore[attr-defined]
            value_node = child.child_by_field_name("value")  # type: ignore[attr-defined]
            if name_node is not None:
                yield (
                    name_node.text.decode("utf-8", errors="replace"),  # type: ignore[attr-defined]
                    name_node,
                    value_node,
                    _annotation_text(child),
                )
        elif child_type == "typed_parameter":
            name_node = next(
                (c for c in child.named_children if c.type == "identifier"),  # type: ignore[attr-defined]
                None,
            )
            if name_node is not None:
                yield (
                    name_node.text.decode("utf-8", errors="replace"),  # type: ignore[attr-defined]
                    name_node,
                    None,
                    _annotation_text(child),
                )
        # list_splat_pattern / dictionary_splat_pattern 不进入位置形参列表：
        # `*args` 的位置映射无法静态确定，收进来只会让按位置匹配错位


def _annotation_text(node: object) -> str:
    type_node = node.child_by_field_name("type")  # type: ignore[attr-defined]
    if type_node is None:
        return ""
    return type_node.text.decode("utf-8", errors="replace")  # type: ignore[attr-defined]


def _make_function_def(
    node: object,
    *,
    file_path: str,
    qualname: str,
    enclosing_class: str | None,
    decorator_nodes: tuple[object, ...],
) -> FunctionDef:
    params_node = node.child_by_field_name("parameters")  # type: ignore[attr-defined]
    body = node.child_by_field_name("body")  # type: ignore[attr-defined]

    names: list[str] = []
    param_nodes: list[tuple[str, object]] = []
    defaults: dict[str, object] = {}
    annotations: dict[str, str] = {}
    for param_name, ident_node, default_node, annotation in _iter_params(params_node):
        if not names and param_name in ("self", "cls") and enclosing_class:
            continue  # 接收者不是实参，参与位置映射会让整条链错位一位
        names.append(param_name)
        param_nodes.append((param_name, ident_node))
        if default_node is not None:
            defaults[param_name] = default_node
        if annotation:
            annotations[param_name] = annotation

    decorators = tuple(decorator_name(d) for d in decorator_nodes)
    is_route = any(is_route_decorator(d) for d in decorator_nodes)
    route_params = parse_route_params(
        [lit for d in decorator_nodes for lit in decorator_string_args(d)]
    )

    has_varargs = (
        any(
            c.type == "list_splat_pattern"
            for c in params_node.named_children  # type: ignore[attr-defined]
        )
        if params_node is not None
        else False
    )
    has_kwargs = (
        any(
            c.type == "dictionary_splat_pattern"
            for c in params_node.named_children  # type: ignore[attr-defined]
        )
        if params_node is not None
        else False
    )

    return FunctionDef(
        qualname=qualname,
        name=qualname.rsplit(".", 1)[-1],
        file_path=file_path,
        line=node_line(node),
        end_line=int(node.end_point[0]) + 1,  # type: ignore[attr-defined]
        params=tuple(names),
        defaults=defaults,
        annotations=annotations,
        decorators=decorators,
        decorator_nodes=decorator_nodes,
        param_nodes=tuple(param_nodes),
        body=body,
        node=node,
        enclosing_class=enclosing_class,
        is_async=any(c.type == "async" for c in node.children),  # type: ignore[attr-defined]
        is_route=is_route,
        route_params=route_params,
        has_varargs=has_varargs,
        has_kwargs=has_kwargs,
        param_index={name: index for index, name in enumerate(names)},
    )


def iter_function_defs(parsed: ParsedFile) -> Iterator[FunctionDef]:
    """产出**所有**函数定义：模块级、类方法、嵌套函数。

    嵌套函数按独立符号处理（qualname `outer.inner`），闭包捕获的外层变量
    **不传播** —— 见模块末的「已知精度边界」。
    """
    module = module_name_of(parsed.rel_path)

    def _walk(block: object, prefix: str, enclosing_class: str | None) -> Iterator[FunctionDef]:
        for statement in block_statements(block):
            decorators: tuple[object, ...] = ()
            definition = statement
            if statement.type == "decorated_definition":  # type: ignore[attr-defined]
                decorators, definition = _decorated_definition_parts(statement)
                if definition is None:
                    continue
            if definition.type == "function_definition":  # type: ignore[attr-defined]
                name_node = definition.child_by_field_name("name")  # type: ignore[attr-defined]
                if name_node is None:
                    continue
                local = name_node.text.decode("utf-8", errors="replace")  # type: ignore[attr-defined]
                qualname = f"{prefix}{local}"
                function = _make_function_def(
                    definition,
                    file_path=parsed.rel_path,
                    qualname=qualname,
                    enclosing_class=enclosing_class,
                    decorator_nodes=decorators,
                )
                yield function
                yield from _walk(function.body, f"{qualname}.", enclosing_class)
            elif definition.type == "class_definition":  # type: ignore[attr-defined]
                name_node = definition.child_by_field_name("name")  # type: ignore[attr-defined]
                if name_node is None:
                    continue
                local = name_node.text.decode("utf-8", errors="replace")  # type: ignore[attr-defined]
                class_qualname = f"{prefix}{local}"
                body = definition.child_by_field_name("body")  # type: ignore[attr-defined]
                yield from _walk(body, f"{class_qualname}.", class_qualname)
            elif definition.type in ("block", "if_statement", "try_statement"):  # type: ignore[attr-defined]
                # 条件定义（`if sys.version_info: def f(): ...`）也要收，
                # 否则这类文件里的函数会整片消失
                for child in walk_named(definition):
                    if child.type == "function_definition":  # type: ignore[attr-defined]
                        name_node = child.child_by_field_name("name")  # type: ignore[attr-defined]
                        if name_node is None:
                            continue
                        local = name_node.text.decode("utf-8", errors="replace")  # type: ignore[attr-defined]
                        qualname = f"{prefix}{local}"
                        function = _make_function_def(
                            child,
                            file_path=parsed.rel_path,
                            qualname=qualname,
                            enclosing_class=enclosing_class,
                            decorator_nodes=(),
                        )
                        yield function
                        yield from _walk(function.body, f"{qualname}.", enclosing_class)

    yield from _walk(parsed.root, f"{module}.", None)


def iter_class_defs(parsed: ParsedFile) -> Iterator[ClassDef]:
    module = module_name_of(parsed.rel_path)

    def _walk(block: object, prefix: str) -> Iterator[ClassDef]:
        for statement in block_statements(block):
            definition = statement
            if statement.type == "decorated_definition":  # type: ignore[attr-defined]
                _, definition = _decorated_definition_parts(statement)
                if definition is None:
                    continue
            if definition.type != "class_definition":  # type: ignore[attr-defined]
                continue
            name_node = definition.child_by_field_name("name")  # type: ignore[attr-defined]
            if name_node is None:
                continue
            local = name_node.text.decode("utf-8", errors="replace")  # type: ignore[attr-defined]
            qualname = f"{prefix}{local}"
            body = definition.child_by_field_name("body")  # type: ignore[attr-defined]
            methods: list[str] = []
            for child in block_statements(body):
                if child.type != "function_definition":  # type: ignore[attr-defined]
                    continue
                method_name = child.child_by_field_name("name")  # type: ignore[attr-defined]
                if method_name is not None:
                    methods.append(method_name.text.decode("utf-8", errors="replace"))  # type: ignore[attr-defined]
            yield ClassDef(
                qualname=qualname,
                name=local,
                file_path=parsed.rel_path,
                line=node_line(definition),
                methods=tuple(methods),
            )
            # 类里嵌套的类
            yield from _walk(body, f"{qualname}.")

    yield from _walk(parsed.root, f"{module}.")


def collect_module_assignments(parsed: ParsedFile) -> tuple[ModuleAssignment, ...]:
    """模块级赋值（不递归进函数体）。常量表与硬编码密钥检测都靠它。"""
    found: list[ModuleAssignment] = []
    for statement in block_statements(parsed.root):
        target = statement
        if statement.type == "expression_statement":  # type: ignore[attr-defined]
            children = statement.named_children  # type: ignore[attr-defined]
            if not children:
                continue
            target = children[0]
        if target.type != "assignment":  # type: ignore[attr-defined]
            continue
        left = target.child_by_field_name("left")  # type: ignore[attr-defined]
        right = target.child_by_field_name("right")  # type: ignore[attr-defined]
        if left is None or right is None or left.type != "identifier":  # type: ignore[attr-defined]
            continue
        found.append(
            ModuleAssignment(
                name=left.text.decode("utf-8", errors="replace"),  # type: ignore[attr-defined]
                node=right,
                line=node_line(target),
            )
        )
    return tuple(found)


def collect_import_aliases(parsed: ParsedFile) -> dict[str, str]:
    """`import a.b as c` → {c: a.b}；`import a.b` → {a: a.b}。

    只服务于「`别名.函数名` 是否是项目内调用」这一个判断，不做完整 import 图。
    """
    aliases: dict[str, str] = {}
    for statement in walk_named(parsed.root):
        if statement.type != "import_statement":  # type: ignore[attr-defined]
            continue
        for child in statement.named_children:  # type: ignore[attr-defined]
            if child.type == "aliased_import":  # type: ignore[attr-defined]
                alias = child.child_by_field_name("alias")  # type: ignore[attr-defined]
                module = child.child_by_field_name("name")  # type: ignore[attr-defined]
                if alias is not None and module is not None:
                    aliases[alias.text.decode("utf-8", errors="replace")] = (  # type: ignore[attr-defined]
                        module.text.decode("utf-8", errors="replace")  # type: ignore[attr-defined]
                    )
            elif child.type == "dotted_name":  # type: ignore[attr-defined]
                text = child.text.decode("utf-8", errors="replace")  # type: ignore[attr-defined]
                aliases[text.split(".")[0]] = text
    return aliases


def build_symbol_table(files: Sequence[ParsedFile]) -> SymbolTable:
    """一次构建全项目符号表。文件顺序由调用方保证（已排序 → 结论确定）。"""
    functions: dict[str, FunctionDef] = {}
    classes: dict[str, ClassDef] = {}
    by_name: dict[str, list[str]] = {}
    by_module: dict[str, list[str]] = {}
    module_assignments: dict[str, tuple[ModuleAssignment, ...]] = {}
    import_aliases: dict[str, dict[str, str]] = {}
    ambiguous: set[str] = set()

    for parsed in files:
        module = module_name_of(parsed.rel_path)
        for function in iter_function_defs(parsed):
            if function.qualname in functions:
                # 同名 qualname 冲突（同一文件里重复定义同一函数名）：
                # 后者胜出并记 WARN —— Python 语义上也是后者覆盖前者
                ambiguous.add(function.name)
            functions[function.qualname] = function
            by_name.setdefault(function.name, []).append(function.qualname)
            by_module.setdefault(module, []).append(function.qualname)
        for klass in iter_class_defs(parsed):
            classes[klass.qualname] = klass
            by_name.setdefault(klass.name, []).append(klass.qualname)
        module_assignments[parsed.rel_path] = collect_module_assignments(parsed)
        import_aliases[parsed.rel_path] = collect_import_aliases(parsed)

    # 简单名冲突 >1 一律标歧义（设计文档 §6 场景 6：冲突函数不建摘要）
    for name, quals in by_name.items():
        if len(quals) > 1:
            ambiguous.add(name)

    return SymbolTable(
        functions=functions,
        classes=classes,
        by_name={name: tuple(quals) for name, quals in by_name.items()},
        by_module={module: tuple(quals) for module, quals in by_module.items()},
        module_assignments=module_assignments,
        import_aliases=import_aliases,
        ambiguous_names=frozenset(ambiguous),
    )


def const_table_of(table: SymbolTable, file_path: str) -> dict[str, object]:
    """取该文件的模块级常量表（名字 → 右值节点）。

    只放**看起来像常量**的赋值：字符串字面量、或者全字面量的集合/列表/元组。
    名字全大写不是必要条件（`allowed = {"a"}` 也算），但值必须是字面量 ——
    白名单守卫的可信度完全建立在这一条上。
    """
    from app.analysis.sanitizers import is_constant_value

    result: dict[str, object] = {}
    for assignment in table.module_assignments.get(file_path, ()):
        if assignment.name.startswith("_"):
            continue
        if is_constant_value(assignment.node, {}):
            result[assignment.name] = assignment.node
    return result
