"""Sink 规格表（设计文档 §2 的 sinks）—— **纯数据 + 匹配函数，零算法**。

每条规则回答三个问题：**哪个符号**、**哪个参数位危险**、**什么条件下才危险**
（`requires_shell` / `safe_loader`）。把条件写进表而不是写进 `if` 分支，
是为了让「新增一个 sink」变成一次表格编辑 —— 这也是设计文档 §2
「规格与算法分离」的全部意义。

**规则宽严的取舍说明**：`execute` / `save` 这类符号在真实代码里接收者形态太杂
（`cursor` / `conn` / `cur` / `db.session` / `upload`），只能按**末段后缀**匹配。
宽匹配的代价是潜在误报，收益是不漏；把这类宽规则的**危险参数位**收紧
（只认注入发生的那一位）比收紧符号名更有效 —— 符号名收紧会直接变成漏报。
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analysis.types import VulnType


@dataclass(frozen=True, slots=True)
class SinkSpec:
    """一条 sink 规则。

    - `dangerous_args`：危险参数位（0-based）。`(-1,)` 表示「任一实参」，
      用于接收者形态各异、危险位不固定的符号（`execute` / `os.system`）。
      关键字实参在 `(-1,)` 时**全部**计入危险位；否则按位置索引取。
    - `requires_shell`：`subprocess.*` 仅在 `shell=True` 时才构成命令注入。
      `shell=False` + 列表传参是**安全用法**（参数不经 shell 解析），
      把它报出来就是最典型的一类误报。
    - `requires_unsafe_loader`：`yaml.load` 带 `Loader=yaml.SafeLoader` 时安全。
    - `param_bindings_exempt`：SQL 类 sink 的「参数绑定位豁免」——
      `execute(sql, params)` 里 `params` 是绑定值而非 SQL 文本（见
      `sanitizers.is_parametric_sql`）。
    """

    symbol: str
    vuln_type: VulnType
    dangerous_args: tuple[int, ...] = (0,)
    requires_shell: bool = False
    requires_unsafe_loader: bool = False
    param_bindings_exempt: bool = False
    rce_class: bool = False
    exact_name: bool = False


SINKS: tuple[SinkSpec, ...] = (
    # ---------------- SQL 注入 ----------------
    # 接收者形态太多（cursor / conn / cur / db.session / session），只能后缀匹配；
    # 危险位放到「任一实参」是因为 `execute` 的重载形态各异（有的是
    # `execute(sql, params)`，有的只是 `execute(sql)`），
    # 收紧到第 0 位会漏掉 `cur.execute(sql_params_kwarg=...)` 这类写法。
    # 参数绑定位由 `param_bindings_exempt` 单独豁免 —— 那才是误报的主要来源。
    SinkSpec("execute", VulnType.SQL_INJECTION, (-1,), param_bindings_exempt=True),
    SinkSpec("executemany", VulnType.SQL_INJECTION, (-1,), param_bindings_exempt=True),
    # Django 的 `Model.objects.raw(sql)`：原始 SQL 直通
    SinkSpec("objects.raw", VulnType.SQL_INJECTION, (0,)),
    # ---------------- 命令执行 / 代码执行（PRD §7.1 ⑥ 把 eval/exec 归入此类）----------------
    SinkSpec("os.system", VulnType.COMMAND_INJECTION, (-1,), rce_class=True),
    SinkSpec("os.popen", VulnType.COMMAND_INJECTION, (-1,), rce_class=True),
    SinkSpec(
        "subprocess.run", VulnType.COMMAND_INJECTION, (0,), requires_shell=True, rce_class=True
    ),
    SinkSpec(
        "subprocess.call", VulnType.COMMAND_INJECTION, (0,), requires_shell=True, rce_class=True
    ),
    SinkSpec(
        "subprocess.check_call",
        VulnType.COMMAND_INJECTION,
        (0,),
        requires_shell=True,
        rce_class=True,
    ),
    SinkSpec(
        "subprocess.check_output",
        VulnType.COMMAND_INJECTION,
        (0,),
        requires_shell=True,
        rce_class=True,
    ),
    SinkSpec(
        "subprocess.Popen", VulnType.COMMAND_INJECTION, (0,), requires_shell=True, rce_class=True
    ),
    # eval / exec 是内置函数，用精确匹配：`x.eval()` 这种同名方法调用
    # 与代码执行无关，后缀匹配会把它算进来
    SinkSpec("eval", VulnType.COMMAND_INJECTION, (0,), rce_class=True, exact_name=True),
    SinkSpec("exec", VulnType.COMMAND_INJECTION, (0,), rce_class=True, exact_name=True),
    # ---------------- 反序列化 ----------------
    SinkSpec("pickle.loads", VulnType.DESERIALIZATION, (0,), rce_class=True),
    SinkSpec("pickle.load", VulnType.DESERIALIZATION, (0,), rce_class=True),
    SinkSpec("cPickle.loads", VulnType.DESERIALIZATION, (0,), rce_class=True),
    SinkSpec("dill.loads", VulnType.DESERIALIZATION, (0,), rce_class=True),
    SinkSpec("marshal.loads", VulnType.DESERIALIZATION, (0,), rce_class=True),
    SinkSpec("jsonpickle.decode", VulnType.DESERIALIZATION, (0,), rce_class=True),
    # `yaml.load` 的默认 Loader 在 PyYAML 5.1 之后已是 SafeLoader，
    # 但显式写 `Loader=yaml.Loader` 或旧版本仍是 RCE —— 这里只在
    # **没有** 带安全 Loader 时才算 sink（requires_unsafe_loader）
    SinkSpec(
        "yaml.load",
        VulnType.DESERIALIZATION,
        (0,),
        requires_unsafe_loader=True,
        rce_class=True,
    ),
    SinkSpec("yaml.unsafe_load", VulnType.DESERIALIZATION, (0,), rce_class=True),
    # ---------------- 路径穿越 ----------------
    # `open` 用精确匹配：`.open()` 在代码里遍地都是（文件对象、session、连接池），
    # 后缀匹配会把它们全算成路径穿越 sink。PIL / io 的形态单独列。
    SinkSpec("open", VulnType.PATH_TRAVERSAL, (0,), exact_name=True),
    SinkSpec("io.open", VulnType.PATH_TRAVERSAL, (0,)),
    SinkSpec("Image.open", VulnType.PATH_TRAVERSAL, (0,)),
    SinkSpec("send_file", VulnType.PATH_TRAVERSAL, (-1,)),
    # FastAPI 的 FileResponse：`FileResponse(BASE + name)` 是同一类任意文件读取。
    # 后端栈本身就是 FastAPI，靶场之外的「顺手扫一下自己的接口」场景必然会遇到。
    SinkSpec("FileResponse", VulnType.PATH_TRAVERSAL, (0,)),
    SinkSpec("shutil.copy", VulnType.PATH_TRAVERSAL, (-1,)),
    SinkSpec("shutil.copyfile", VulnType.PATH_TRAVERSAL, (-1,)),
    SinkSpec("shutil.copy2", VulnType.PATH_TRAVERSAL, (-1,)),
    SinkSpec("shutil.move", VulnType.PATH_TRAVERSAL, (-1,)),
    SinkSpec("os.remove", VulnType.PATH_TRAVERSAL, (-1,)),
    SinkSpec("os.unlink", VulnType.PATH_TRAVERSAL, (-1,)),
    SinkSpec("os.rmdir", VulnType.PATH_TRAVERSAL, (-1,)),
    # `os.path.join` 刻意**不是** sink：它只是拼接，落盘/读盘的那一步才是
    # 危险点。把 join 当 sink 会让每一个「用变量拼路径」的正常代码都报漏洞。
    # ---------------- 文件上传 ----------------
    # `FileStorage.save(目标路径)`；目标路径里若含 `f.filename` 就是任意写。
    # 宽匹配的兜底是：只有当**实参带污点**时才产出 Finding，
    # 无参的 `model.save()` 不会命中。
    SinkSpec("save", VulnType.FILE_UPLOAD, (-1,)),
    # ---------------- XSS ----------------
    SinkSpec("mark_safe", VulnType.XSS, (0,)),
    SinkSpec("Markup", VulnType.XSS, (0,)),
)


def _matches(dotted: str, symbol: str, *, exact: bool) -> bool:
    if exact:
        return dotted == symbol
    return dotted == symbol or dotted.endswith("." + symbol)


#: 匹配顺序：**先精确、后后缀**。`open`（精确）必须先于 `Image.open`（后缀）被
#: 检查吗？不需要 —— 精确规则只可能命中完全相等的名字，后缀规则不可能把它们
#: 抢走。但反过来，一个短符号（`execute`）会吃掉更长的名字（`conn.execute`），
#: 这是**想要的**。所以按「符号长度降序」排，更具体的规则优先，
#: 保证 `yaml.load` 不会被 `load`（假设将来加入）抢走。
_SORTED_SINKS: tuple[SinkSpec, ...] = tuple(
    sorted(SINKS, key=lambda s: (len(s.symbol), s.symbol), reverse=True)
)


def match_sink(dotted: str) -> SinkSpec | None:
    """按被调函数名匹配 sink 规则；无匹配返回 None。"""
    if not dotted:
        return None
    for spec in _SORTED_SINKS:
        if _matches(dotted, spec.symbol, exact=spec.exact_name):
            return spec
    return None


#: 需要 `shell=True` 才算注入的符号集合（读起来更直观的别名）。
SHELL_REQUIRED = frozenset(s.symbol for s in SINKS if s.requires_shell)
