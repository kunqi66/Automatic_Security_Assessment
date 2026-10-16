"""pytest 全局配置。

**必须在导入任何 `app.*` 之前设好环境变量**：`app.core.config` 在模块级就
`settings = get_settings()`，而生产环境自检（`_check_production_secrets`）
在 `DEBUG=false` 且没配 MySQL 口令时会直接抛异常。也就是说，这行 setdefault
如果晚于 app 的导入，整个测试套件会在收集阶段就崩掉，错误信息还与被测代码无关。
"""

from __future__ import annotations

import os

os.environ.setdefault("DEBUG", "true")
