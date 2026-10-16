"""`.env.example` 必须覆盖「生产自检会拦下的每一项」。

## 这条测试防的是什么

`Settings._check_production_secrets` 在 `DEBUG=false` 时会因为三个变量缺失
**拒绝启动**：`JWT_SECRET` / `MYSQL_PASSWORD` / `GIT_URL_ALLOWLIST`。

前两个在 `.env.example` 里有占位行，第三个**曾经没有** —— 后果是部署的人
照着 `.env.example` 填完、把 `DEBUG` 改成 `false`、然后启动失败，
报错说「GIT_URL_ALLOWLIST 为空」，而他手里那份模板里**根本没有这一行**。
他只能去翻 `config.py` 才知道这个变量存在，而那时候他已经不信任这份模板了。

**模板的意义是「照着填就能跑」**。少一行就等于模板在说谎，
而说谎的方向恰好是「你以为你配完了」。

## 为什么不去读 `.env.example` 里每个变量的值

那样会退化成「比对两份清单」的脆弱测试。这里只断言**变量名出现过**，
因为要防的是「模板没提这件事」，不是「模板里的值对不对」——
值该填什么是部署的人决定的。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.core.config import _DEV_JWT_SECRET, Settings

_ENV_EXAMPLE = Path(__file__).resolve().parent.parent / ".env.example"

#: 生产自检的三个必填项，对应 `_check_production_secrets` 里的三个 `problems.append`。
#: **这份清单与那段代码是一对** —— 那边加一条，这里就得加一条
#: （`test_生产自检的必填项与这份清单一致` 会盯着）。
_REQUIRED_IN_PRODUCTION = ("JWT_SECRET", "MYSQL_PASSWORD", "GIT_URL_ALLOWLIST")


def _declared_names() -> set[str]:
    """`.env.example` 里**未被注释掉**的变量名。"""
    text = _ENV_EXAMPLE.read_text(encoding="utf-8")
    names: set[str] = set()
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue  # 注释行里的示例不算「模板提供了这一项」
        match = re.match(r"^\s*([A-Z][A-Z0-9_]*)\s*=", line)
        if match:
            names.add(match.group(1))
    return names


def test_env_example_文件存在() -> None:
    assert _ENV_EXAMPLE.is_file(), f"找不到 {_ENV_EXAMPLE}"


@pytest.mark.parametrize("name", _REQUIRED_IN_PRODUCTION)
def test_生产必填项在_env_example_里有占位行(name: str) -> None:
    declared = _declared_names()
    assert name in declared, (
        f"`.env.example` 里没有 {name} 这一行，但生产自检要求它非空 —— "
        f"照着模板填的人会启动失败，且无从知道该加哪个变量。"
        f"（当前模板声明了 {len(declared)} 个变量）"
    )


def test_生产自检的必填项与这份清单一致() -> None:
    """把 `_check_production_secrets` 的拦截项与上面的清单对齐。

    做法：造一份「全默认值」的 Settings（`DEBUG=false`），收集它报出来的
    问题里提到的变量名，与 `_REQUIRED_IN_PRODUCTION` 比。

    这样有人往自检里加第四项时，**这条会红**，而不是等到某次部署才发现
    模板又少了一行。
    """
    with pytest.raises(ValueError) as excinfo:
        Settings(
            _env_file=None,
            debug=False,
            jwt_secret=_DEV_JWT_SECRET,
            mysql_password="",
            git_url_allowlist=[],
        )

    message = str(excinfo.value)
    missing = [n for n in _REQUIRED_IN_PRODUCTION if n not in message]
    assert not missing, (
        f"自检信息里没提到 {missing} —— 说明拦截项变了，"
        f"请同步更新 `_REQUIRED_IN_PRODUCTION`（以及 `.env.example`）。实际信息：{message}"
    )


def test_git_url_allowlist_是_JSON_数组而不是逗号分隔() -> None:
    """钉住 `list[str]` 的**唯一**正确写法。

    写成 `https://a/,https://b/` 时 pydantic-settings 会在 **import 期**
    抛 SettingsError —— 而 `.env.example` 的注释里承诺了 JSON 形式，
    注释和真实行为必须一致，否则照抄注释的人会踩坑。
    """
    import json
    import os

    key = "GIT_URL_ALLOWLIST"
    original = os.environ.get(key)
    try:
        os.environ[key] = json.dumps(["https://gitee.com/acme/"])
        assert Settings(_env_file=None, debug=True).git_url_allowlist == ["https://gitee.com/acme/"]

        os.environ[key] = "https://gitee.com/acme/,https://github.com/x/"
        with pytest.raises(Exception):  # noqa: B017 - SettingsError 不该被 import 进测试
            Settings(_env_file=None, debug=True)
    finally:
        if original is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = original
