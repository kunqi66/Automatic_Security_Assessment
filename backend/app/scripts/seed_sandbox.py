"""写入默认沙箱配置 —— 让管理页「沙箱与环境配置」有东西可配。

    uv run python -m app.scripts.seed_sandbox

## 为什么需要它

`engine._resolve_sandbox_config` 会读 `sandbox_configs` 里 `is_default` 那行，
把它注入 `AssessmentContext.sandbox_config`，再由 `poc_verify` 传给引擎。
**但没有任何代码会创建这一行** —— 迁移只 `create_table`，不种数据。

表为空不会让评估失败（读不到就回落到 `core/config.py` 的默认值，见 `engine` 的
`_resolve_sandbox_config` 与 `verify.types.SandboxConfig.from_settings`）。
但后果是：管理页永远显示「暂无沙箱配置」，管理员**无从下手**，
而「沙箱配置」这条线看起来就是坏的。

## 值为什么是这几个

**CPU 0.5 / 内存 256MB 不是随手取的** —— 这两个是 `verify/types.py` 里
`SandboxConfig` 的默认值，也就是**接通管理页之前引擎实际在用的值**。

刻意**不**采用 `models/sandbox.py` 的列默认值（`cpu_limit=1.0`、
`memory_limit_mb=1024`）：那会让「种下这一行」这个动作本身就把沙箱内存
翻 4 倍，而部署机是 2 vCPU / 7.3G **无 swap**，`poc_verify` 是要真起容器的。
一次静默的 4 倍内存变化，症状会是随机 OOM 而不是报错。

**种子的职责是让「接通前后行为一致」**：接通前用 0.5/256，接通后还是 0.5/256，
直到管理员自己动手改。要改大，是管理页上的一个显式动作，不是一个部署脚本的副作用。

其余字段（`timeout_seconds`、`base_image`）取自 `core/config.py` 的当前值，
理由相同 —— 它们本来就是引擎在用的那两个数。
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from sqlalchemy import select

from app.core.config import settings
from app.core.logging import get_logger, setup_logging
from app.models.enums import NetworkPolicy
from app.models.sandbox import SandboxConfig

logger = get_logger(__name__)

#: 默认行的名字。**唯一**（列上有 unique 约束），也是幂等的判据。
DEFAULT_NAME = "默认沙箱"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m app.scripts.seed_sandbox",
        description="写入默认沙箱配置（幂等：同名已存在则不动）",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="同名行已存在时，把它的值改回本脚本的默认值（会覆盖管理员改过的配置）",
    )
    return parser.parse_args(argv)


async def _run(args: argparse.Namespace) -> int:
    from app.db.session import AsyncSessionLocal, dispose_engine

    try:
        async with AsyncSessionLocal() as session:
            existing = await session.scalar(
                select(SandboxConfig).where(SandboxConfig.name == DEFAULT_NAME)
            )

            if existing is not None:
                if not args.force:
                    # **不静默覆盖**：管理员很可能已经在管理页上调过这些值，
                    # 一个「重跑部署脚本就把沙箱配置改回去」的行为，
                    # 症状会是某次例行操作后动态验证莫名变慢或 OOM。
                    print(
                        f"已存在：{DEFAULT_NAME!r}（id={existing.id}），未改动。"
                        f"要按脚本默认值覆盖请加 --force"
                    )
                    return 0
                existing.base_image = settings.sandbox_default_image
                existing.network_policy = NetworkPolicy.INTERNAL
                existing.timeout_seconds = settings.sandbox_exec_timeout_seconds
                existing.cpu_limit = 0.5
                existing.memory_limit_mb = 256
                existing.max_concurrency = 1
                existing.is_default = True
                action = "已按脚本默认值覆盖"
            else:
                # 别的行可能已经是默认 —— 一并清掉，理由同 `api/v1/admin.py`
                # 里那段：`is_default` 是单选，多行同时为真会让引擎挑哪一行
                # 取决于 id，是个不报错的歧义。
                for row in (
                    (await session.execute(select(SandboxConfig).where(SandboxConfig.is_default)))
                    .scalars()
                    .all()
                ):
                    row.is_default = False

                session.add(
                    SandboxConfig(
                        name=DEFAULT_NAME,
                        base_image=settings.sandbox_default_image,
                        network_policy=NetworkPolicy.INTERNAL,
                        timeout_seconds=settings.sandbox_exec_timeout_seconds,
                        # 见模块文档：取引擎现用值，不取列默认值。
                        cpu_limit=0.5,
                        memory_limit_mb=256,
                        max_concurrency=1,
                        is_default=True,
                    )
                )
                action = "已创建"

            # 一次性运维动作，不是流水线里的阶段 —— 不适用「阶段边界才提交」（T4），
            # 那条规则管的是 Agent 不许自己 commit。
            await session.commit()
    finally:
        await dispose_engine()

    print(f"{action}：{DEFAULT_NAME}")
    print(f"  镜像      {settings.sandbox_default_image}")
    print("  网络策略  internal（仅回环，禁出站 —— 不变量，引擎侧不读该字段）")
    print(f"  单探针超时 {settings.sandbox_exec_timeout_seconds}s")
    print("  CPU/内存   0.5 核 / 256MB")
    return 0


def main(argv: list[str] | None = None) -> int:
    setup_logging()
    args = _parse_args(argv)
    try:
        return asyncio.run(_run(args))
    except SystemExit as exc:
        if exc.code not in (0, None):
            print(f"错误：{exc.code}", file=sys.stderr)
        return 1 if exc.code not in (0, None) else 0


if __name__ == "__main__":
    raise SystemExit(main())
