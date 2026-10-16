"""漏洞原子表：`Finding → VulnAtom`（B5 设计 §4.5）。

**这张表是链的可复现性的根**：只要输入 findings 相同，原子就逐字段相同，
于是规则匹配、状态图、最终路径全部相同。表里没有一个字段来自 LLM 或启发式打分。

## `assets` 是怎么来的（这决定了 R1/R7 这类规则会不会命中）

`assets` 的取值必须**只依赖 finding 自身**，否则同一份输入会推出不同的链（L1 失效）。
所以它是「类别默认资产 ∪ 关键词命中资产」两部分：

* 类别默认：`sqli → {"users", "config"}`（SQL 注入够得着用户表与配置表）；
* 关键词命中：扫 `file_path / symbol / source_kind / sink_kind / title` 里是否出现
  `user`、`order`、`upload` 等词，命中就把对应资产加进去。

关键词表是**封闭的、字面的**（不是正则模糊匹配），所以"为什么这条链被推出来了"
永远能回答成"因为 xxx.py 的路径里出现了 `user`"。可解释性在这里比聪明重要。
"""

from __future__ import annotations

from typing import Any

from app.chain.types import Priv, VulnAtom
from app.core.logging import get_logger
from app.models.enums import VulnStatus
from app.verify.probe import canonical_vuln_type

logger = get_logger(__name__)


class _AtomTemplate:
    """类别 → 权限跃迁的静态条目（冻结的常量表，运行时只读）。"""

    __slots__ = ("assets", "gains", "produces", "requires")

    def __init__(
        self,
        *,
        requires: tuple[Priv, ...],
        gains: tuple[Priv, ...],
        assets: tuple[str, ...],
        produces: tuple[str, ...],
    ) -> None:
        self.requires = frozenset(requires)
        self.gains = frozenset(gains)
        self.assets = frozenset(assets)
        self.produces = frozenset(produces)


#: B5 设计 §4.5 的原子表，逐行照抄。**类别名 = `canonical_vuln_type` 的取值**。
CATEGORY_ATOMS: dict[str, _AtomTemplate] = {
    "sqli": _AtomTemplate(
        requires=(Priv.ANONYMOUS,),
        gains=(Priv.DB,),
        assets=("users", "config"),
        produces=("credential", "db_access"),
    ),
    "cmdi": _AtomTemplate(
        requires=(Priv.ANONYMOUS,),
        gains=(Priv.HOST,),
        assets=("shell",),
        produces=("rce",),
    ),
    "file_upload": _AtomTemplate(
        requires=(Priv.ADMIN,),
        gains=(Priv.HOST,),
        assets=("upload",),
        produces=("rce",),
    ),
    "idor": _AtomTemplate(
        requires=(Priv.USER,),
        gains=(Priv.USER,),
        assets=("users",),
        produces=("pii_bulk",),
    ),
    "unauth_access": _AtomTemplate(
        requires=(Priv.ANONYMOUS,),
        gains=(Priv.USER,),
        assets=("api",),
        produces=("data_read",),
    ),
    "info_disclosure": _AtomTemplate(
        requires=(Priv.ANONYMOUS,),
        gains=(Priv.DB, Priv.KEYS),
        assets=("config",),
        produces=("secret", "db_access"),
    ),
    "file_read": _AtomTemplate(
        requires=(Priv.ANONYMOUS,),
        gains=(Priv.KEYS,),
        assets=("files",),
        produces=("source_code", "secret"),
    ),
    "deserialization": _AtomTemplate(
        requires=(Priv.ANONYMOUS,),
        gains=(Priv.HOST,),
        assets=("deser",),
        produces=("rce",),
    ),
}

#: 关键词 → 资产。**字面子串匹配，不做词干化、不做正则**（见模块头）。
ASSET_KEYWORDS: dict[str, tuple[str, ...]] = {
    "users": ("user", "account", "member", "login", "auth", "admin", "profile"),
    "orders": ("order", "trade", "payment", "invoice"),
    "upload": ("upload", "attach", "media"),
    "files": ("file", "read", "download", "export"),
    "config": ("config", "setting", "env", "secret", "debug"),
    "api": ("api", "rest", "graphql", "endpoint"),
    "db": ("sql", "query", "db", "database", "execute", "cursor"),
    "shell": ("system", "exec", "popen", "subprocess", "shell", "eval"),
    "deser": ("pickle", "deserial", "unserial", "yaml.load", "marshal"),
}

#: 工程级资产探测：R2 要求「工程资产表含后台登录接口」。
#: 判定方式与 `ASSET_KEYWORDS` 一样是字面命中 —— 扫全部 finding 的路径与符号名。
PROJECT_ASSET_KEYWORDS: dict[str, tuple[str, ...]] = {
    "admin_login": ("login", "signin", "sign_in", "auth/login", "admin"),
    "user_table": ("user", "account", "member", "profile"),
    "upload_endpoint": ("upload", "attach", "media"),
}

#: 哪些状态的 finding 才允许进入推演。
#:
#: **只有 `verified`。** 设计 §4.4 的流程图第一行就是「verified Findings」，
#: 而 Q24 的分野（哪些环实测、哪些环推演）只有在"起点是实测的"前提下才成立：
#: 让 `potential` 进来，等于用未经证实的漏洞去论证后面的每一步，
#: 链会变成一篇"可能这样、也可能那样"的推测文 —— 那正是本系统要避免的东西。
CHAIN_ELIGIBLE_STATUSES: frozenset[VulnStatus] = frozenset({VulnStatus.VERIFIED})


def to_atom(finding: Any, *, status: VulnStatus | None = None) -> VulnAtom | None:
    """把一个 finding 转成原子。返回 `None` 表示"不进链"（类型无映射）。"""
    raw_type = str(_attr(finding, "vuln_type", "") or "")
    category = canonical_vuln_type(raw_type)
    template = CATEGORY_ATOMS.get(category)
    if template is None:
        logger.info("漏洞类型 %r 没有原子映射，不参与链推演", raw_type)
        return None

    resolved_status = status if status is not None else _status_of(finding)
    # 取不到状态字段 ⇒ **视为已验证**。理由：设计 §4.4 的输入定义就是
    # 「verified Findings」，调用方（B3）传进来的那一批本身就是验证过的；
    # 而 B4 的 `Finding` 在落库前压根没有 `status` 字段。
    # 反过来把"没有状态"默认成"未验证"，会让整条链在正常的调用姿势下恒为空 ——
    # 那是个"看起来什么都没发生"的故障，比报错难查得多。
    # B3 若要传全量 findings，builder 的 `require_verified=True` 会按 status 过滤。
    verified = True if resolved_status is None else resolved_status in CHAIN_ELIGIBLE_STATUSES
    return VulnAtom(
        vuln_id=_int_attr(finding, "vuln_id", "id"),
        vuln_code=_opt_str(_attr(finding, "code", None)),
        category=category,
        requires=template.requires,
        gains=template.gains,
        assets=template.assets | _derive_assets(finding),
        produces=template.produces,
        cvss=float(_attr(finding, "cvss_score", 0.0) or 0.0),
        verified=verified,
        file_path=str(_attr(finding, "file_path", "") or ""),
    )


def detect_project_assets(findings: Any) -> frozenset[str]:
    """从全部 finding 的路径/符号里探测工程级资产（R2 的前置条件之一）。"""
    found: set[str] = set()
    for finding in findings:
        haystack = " ".join(
            str(_attr(finding, field, "") or "").lower()
            for field in ("file_path", "symbol", "sink_kind", "title")
        )
        for asset, keywords in PROJECT_ASSET_KEYWORDS.items():
            if any(keyword in haystack for keyword in keywords):
                found.add(asset)
    return frozenset(found)


def _derive_assets(finding: Any) -> frozenset[str]:
    """扫路径/符号里的关键词，得到类别默认之外的资产。"""
    haystack = " ".join(
        str(_attr(finding, field, "") or "").lower()
        for field in ("file_path", "symbol", "source_kind", "sink_kind", "title")
    )
    assets: set[str] = set()
    for asset, keywords in ASSET_KEYWORDS.items():
        if any(keyword in haystack for keyword in keywords):
            assets.add(asset)
    return frozenset(assets)


def _status_of(finding: Any) -> VulnStatus | None:
    """取 finding 的落库状态。取不到就返回 `None`（由调用方决定放开还是收紧）。"""
    status = _attr(finding, "status", None)
    if status is None:
        return None
    if isinstance(status, VulnStatus):
        return status
    try:
        return VulnStatus(str(status))
    except ValueError:
        return None


def _attr(obj: Any, name: str, default: Any) -> Any:
    value = getattr(obj, name, None)
    return default if value is None else value


def _int_attr(obj: Any, *names: str) -> int:
    for name in names:
        value = getattr(obj, name, None)
        if isinstance(value, int):
            return value
    return 0


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
