"""B1-5 源码同步到数据面 —— **Q23 定案 = 方案 A**（总纲 §12.2）。

控制面（Windows）与数据面（阿里云 ECS）之间**没有共享磁盘**，而远端 Docker
只能挂载**远端**路径。所以「控制面的源码怎么出现在容器里」必须有一次真实搬运。
定案选的是：打包 tar 流 → SSH 推送到 `/srv/asa/tasks/{assessment_id}/src/` →
远端解包 → 由 B2 做 `ro` bind mount。

**为什么不用 `docker cp`**：`docker cp` 是拷进容器可写层，源码就变成了可写；
而只读挂载从根上阻断源码回写（总纲 §8.3 的硬约束）。搬运算一次，只读管全程。

**为什么走 SSH 流而不是 SFTP 逐文件**：源码动辄上万个文件，逐文件往返的
RTT 开销会让同步从秒级变成分钟级。一个 tar 流只有一次连接。
"""

from __future__ import annotations

import asyncio
import shlex
import subprocess
import tarfile
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger
from app.projects.errors import RemoteSyncFailedError

logger = get_logger(__name__)

SYNC_ATTEMPTS = 3
SYNC_BASE_BACKOFF_SECONDS = 2.0
SSH_CONNECT_TIMEOUT_SECONDS = 10
SYNC_TIMEOUT_SECONDS = 600


def remote_src_dir(assessment_id: int) -> str:
    """远端源码目录。

    只用 `settings.ecs_source_root` + 整数 id 拼接，**不接受任何外部字符串** ——
    这个值下面会被塞进远端 shell 命令，一旦掺进用户输入就是命令注入。
    """
    return f"{settings.ecs_source_root.rstrip('/')}/{int(assessment_id)}/src"


def _ssh_argv(remote_command: str) -> list[str]:
    """构造 ssh 调用。用 argv 列表而不是 shell 字符串 —— 不经本地 shell 解析。

    `remote_command` 是**远端**的一条 shell 命令串，由本模块构造；
    调用方传入的任何值都必须先过 `shlex.quote`。
    """
    target = settings.data_plane_ssh_target
    if not target:
        raise RemoteSyncFailedError(
            "未配置数据面（DOCKER_HOST 为空），无法同步源码到沙箱宿主",
            remediation="在 .env 中设置 DOCKER_HOST=ssh://root@<ecs-host>",
            retryable=False,
        )

    argv = [
        "ssh",
        "-o",
        "BatchMode=yes",  # 绝不交互式索要口令，否则会挂到超时
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"ConnectTimeout={SSH_CONNECT_TIMEOUT_SECONDS}",
    ]
    if settings.docker_ssh_key_path:
        argv += ["-i", settings.docker_ssh_key_path]
    return [*argv, "--", target, remote_command]


def _unpack_command(remote_dir: str) -> str:
    """建目录 → 清空 → 从 stdin 解包。

    `rm -rf` 那一节是必要的：不清的话，上一次评估留下的文件会和新源码混在一起，
    而混合后的目录树**既不等于旧版本也不等于新版本**，扫出来的漏洞定位全是错的。

    `remote_dir` 是我们自己拼的（整数 id + 配置），但仍用 `shlex.quote` 包一层 ——
    让「未来有人把某个外部值接进来」这个改动不会直接变成命令注入。
    """
    quoted = shlex.quote(remote_dir)
    return f"mkdir -p {quoted} && rm -rf {quoted}/* && tar -xf - -C {quoted}"


def _build_tar_stream(src_root: Path, handle) -> None:
    """把源码树写成一个 tar 流。

    `mode="w|"` 是**流式**（管道）写入：不 seek、不在内存里建索引，
    边遍历边写进 ssh 的 stdin。用 `w:` 会先在磁盘上生成一个完整 tar 再发送，
    对一个大仓库来说等于凭空多占一份磁盘（而 C 盘只剩 24G）。
    """
    with tarfile.open(fileobj=handle, mode="w|") as tf:
        for child in sorted(src_root.iterdir()):
            # arcname 用**相对 src_root 的名字**，而不是绝对路径：
            # 用绝对路径打包出去，远端解包会试图重建整个 C:\... 或 /home/... 层级
            tf.add(child, arcname=child.name, recursive=True)


def _sync_blocking(src_root: Path, remote_dir: str) -> None:
    argv = _ssh_argv(_unpack_command(remote_dir))
    proc = subprocess.Popen(  # noqa: S603 —— argv 全部由本模块构造，无外部字符串
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert proc.stdin is not None
        _build_tar_stream(src_root, proc.stdin)
        proc.stdin.close()

        try:
            _, stderr = proc.communicate(timeout=SYNC_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise RemoteSyncFailedError(f"同步超时（超过 {SYNC_TIMEOUT_SECONDS} 秒）") from None
    finally:
        if proc.poll() is None:  # pragma: no cover - 正常路径不会走到
            proc.kill()

    if proc.returncode != 0:
        message = (stderr or b"").decode("utf-8", errors="replace")[-500:]
        raise RemoteSyncFailedError(
            f"远端解包失败（ssh 退出码 {proc.returncode}）",
            detail={"stderr_tail": message, "remote_dir": remote_dir},
            remediation="检查 ECS 磁盘剩余空间与 /srv 目录写权限",
        )


async def sync_to_data_plane(assessment_id: int, src_root: Path) -> str:
    """同步并返回**宿主侧**路径，供 B2 做 `ro` bind mount。

    失败按 L4（可重试）处理：重试 3 次，指数退避。仍然失败就抛出去 ——
    注意**这里不吞异常**。B1 设计 §6 第 11 条要求的是「由 `ensure_ready()` 在
    评估启动时拦截」，也就是把失败表达成一个可检查的状态，
    而不是在这里假装成功。
    """
    remote_dir = remote_src_dir(assessment_id)
    # stat 也是阻塞 IO；放到线程里，与后面的打包走同一条规则
    if not await asyncio.to_thread(src_root.is_dir):
        raise RemoteSyncFailedError(
            "控制面源码目录不存在，无法同步",
            detail={"src_root": str(src_root)},
            retryable=False,
        )

    last: Exception | None = None
    for attempt in range(1, SYNC_ATTEMPTS + 1):
        try:
            await asyncio.to_thread(_sync_blocking, src_root, remote_dir)
            logger.info("源码已同步至 %s（第 %d 次尝试）", remote_dir, attempt)
            return remote_dir
        except RemoteSyncFailedError as exc:
            last = exc
            if not exc.retryable:
                raise
            if attempt < SYNC_ATTEMPTS:
                delay = SYNC_BASE_BACKOFF_SECONDS * (2 ** (attempt - 1))
                logger.warning(
                    "源码同步失败（第 %d/%d 次），%.0fs 后重试：%s",
                    attempt,
                    SYNC_ATTEMPTS,
                    delay,
                    exc.message,
                )
                await asyncio.sleep(delay)
        except FileNotFoundError as exc:
            # Windows 上 ssh 客户端不存在 / 不在 PATH
            raise RemoteSyncFailedError(
                "本机找不到 ssh 命令，无法同步源码到数据面",
                remediation="安装 OpenSSH 客户端（设置 → 应用 → 可选功能），或确认 ssh 在 PATH 中",
                retryable=False,
            ) from exc

    raise RemoteSyncFailedError(
        f"源码同步连续失败 {SYNC_ATTEMPTS} 次",
        detail={"last_error": last.message if last else None},
    )


PROBE_TIMEOUT_SECONDS = 15


async def remote_dir_exists(remote_dir: str) -> bool:
    """远端探测副本是否还在。

    **探测不通时返回 `True`（假定存在）**，而不是 `False`。这是刻意的：
    返回 `False` 的后果是每次启动评估都白传一遍源码 —— 在网络抖动时，
    这个「保守」的选择反而会放大故障。真正的错误留给后续步骤去报，
    那时拿到的是一手信息，而不是这里的猜测。

    SSH 不在 DOCKER_HOST 未配置时也返回 `True`：没有数据面就轮不到这里判断。
    """
    if not settings.data_plane_ssh_target:
        return True

    argv = _ssh_argv(f"test -d {shlex.quote(remote_dir)}")
    try:
        result = await asyncio.to_thread(
            subprocess.run, argv, capture_output=True, timeout=PROBE_TIMEOUT_SECONDS, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("远端探测失败，假定副本存在：%s", exc)
        return True
    return result.returncode == 0
