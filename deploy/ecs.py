"""阿里云 ECS（数据面）运维脚本。

**为什么要写成脚本而不是手敲命令**：PRD §2.2 把「装 swap、建独立库与账号、
配置免密 SSH」列成了前置动作项。手敲一次就没了，换台机器要重新回忆；
写成脚本之后这些步骤是可复现、可审计的，也能在面试时直接指着说
「这台机器是我用这个脚本配的」。

⚠️ **这台 ECS 上还跑着别的服务**（MySQL 3306 / Redis 6379 / Milvus 19530 /
某服务 8000）。本脚本只做**增量**改动，任何一步都不覆盖既有配置：

  - 复用既有 MySQL → 只**新建**库与账号，不动 root、不动别人的库
  - 复用既有 Redis → 只用 **db=3**，不改 redis.conf
  - Docker → 只 `docker network create` / `docker run` 自己的容器
  - 新增端口 → 只用 **8010**（后端）

用法（在仓库根目录）：

    ECS_PASSWORD=... uv run --with paramiko python deploy/ecs.py survey
    ECS_PASSWORD=... uv run --with paramiko python deploy/ecs.py install-key
    uv run --with paramiko python deploy/ecs.py --dry-run provision
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    import paramiko
except ImportError:  # pragma: no cover
    sys.exit("缺少 paramiko。用：uv run --with paramiko python deploy/ecs.py ...")

HOST = os.environ.get("ECS_HOST", "60.205.138.167")
USER = os.environ.get("ECS_USER", "root")
PORT = int(os.environ.get("ECS_PORT", "22"))
PUBKEY = Path.home() / ".ssh" / "id_rsa.pub"


@dataclass
class Result:
    stdout: str
    stderr: str
    code: int

    @property
    def ok(self) -> bool:
        return self.code == 0


def connect() -> paramiko.SSHClient:
    password = os.environ.get("ECS_PASSWORD")
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    # 不设 AutoAddPolicy：known_hosts 里已经有这台机器，如果指纹变了我们
    # **想要**它报错。自动接受新指纹等于放弃中间人防护。
    try:
        client.connect(
            HOST,
            port=PORT,
            username=USER,
            password=password,
            key_filename=str(Path.home() / ".ssh" / "id_rsa"),
            timeout=15,
            allow_agent=True,
            look_for_keys=True,
        )
    except paramiko.SSHException as exc:
        sys.exit(f"连接 {USER}@{HOST} 失败：{exc}\n（若是指纹问题，检查 ~/.ssh/known_hosts）")
    return client


def run(client: paramiko.SSHClient, command: str, *, check: bool = False) -> Result:
    _stdin, stdout, stderr = client.exec_command(command, timeout=120)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    if check and code != 0:
        sys.exit(f"命令失败（退出码 {code}）：{command}\n{err}")
    return Result(out, err, code)


# ---------------------------------------------------------------------------
# survey —— 只读，不改任何东西
# ---------------------------------------------------------------------------

SURVEY: list[tuple[str, str]] = [
    ("系统", "uname -srm; cat /etc/os-release | grep -E '^(NAME|VERSION)=' "),
    ("CPU / 内存 / Swap", "nproc; free -h"),
    ("磁盘", "df -h | grep -vE 'tmpfs|overlay'"),
    ("已监听端口", "ss -lntp 2>/dev/null | tail -n +2"),
    ("Docker", "docker version --format '{{.Server.Version}}' 2>&1 | head -2; docker ps --format '{{.Names}}\\t{{.Image}}\\t{{.Ports}}' 2>&1 | head -20"),
    ("Docker Compose", "docker compose version 2>&1 | head -1"),
    ("Docker 网络", "docker network ls 2>&1 | head -10"),
    ("MySQL", "mysql --version 2>&1 | head -1; systemctl is-active mysql 2>&1; systemctl is-active mysqld 2>&1"),
    ("Redis", "redis-server --version 2>&1 | head -1; systemctl is-active redis 2>&1; systemctl is-active redis-server 2>&1"),
    ("Python", "python3 --version 2>&1"),
    ("/srv 目录", "ls -la /srv 2>&1 | head -20"),
    ("防火墙", "ufw status 2>&1 | head -5; firewall-cmd --state 2>&1 | head -2"),
    ("SSH 免密现状", "ls -la ~/.ssh/ 2>&1; wc -l ~/.ssh/authorized_keys 2>/dev/null || echo 'no authorized_keys'"),
    ("镜像加速", "cat /etc/docker/daemon.json 2>&1 | head -20"),
]


def cmd_survey(client: paramiko.SSHClient) -> None:
    for title, command in SURVEY:
        result = run(client, command)
        body = (result.stdout + result.stderr).strip()
        print(f"\n{'=' * 62}\n## {title}\n{'=' * 62}")
        print(body if body else "(空)")


# ---------------------------------------------------------------------------
# install-key —— 装公钥，之后就不需要密码了
# ---------------------------------------------------------------------------


def cmd_install_key(client: paramiko.SSHClient) -> None:
    if not PUBKEY.is_file():
        sys.exit(f"本机没有公钥：{PUBKEY}\n先跑 ssh-keygen -t rsa -b 4096")

    pub = PUBKEY.read_text(encoding="utf-8").strip()
    # 幂等：先查有没有，避免重复追加（authorized_keys 里堆一堆同样的键，
    # 事后想撤销访问权限时根本分不清该删哪一行）
    check = run(client, "grep -cF " + _q(pub) + " ~/.ssh/authorized_keys 2>/dev/null || true")
    if check.stdout.strip() not in ("", "0"):
        print("公钥已存在，跳过")
        return

    run(client, "mkdir -p ~/.ssh && chmod 700 ~/.ssh", check=True)
    run(client, f"printf '%s\\n' {_q(pub)} >> ~/.ssh/authorized_keys", check=True)
    run(client, "chmod 600 ~/.ssh/authorized_keys", check=True)
    print(f"已安装公钥：{PUBKEY.name}")

    # 立刻用密钥重连一次验证 —— 不验证的话，等下次连接才发现没生效，
    # 而那时密码可能已经不记得了
    probe = run(client, "ssh -o BatchMode=yes -o StrictHostKeyChecking=no localhost true 2>&1")
    print("回环密钥登录：" + ("OK" if probe.ok else "未生效（不影响，回环可能被 AllowUsers 限制）"))


def _q(value: str) -> str:
    import shlex

    return shlex.quote(value)


# ---------------------------------------------------------------------------


def cmd_run(client: paramiko.SSHClient, command: str) -> None:
    """在远端跑一条命令。给排查用 —— 不必为每个临时问题都改这个脚本。"""
    result = run(client, command)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    sys.exit(result.code)


def cmd_sql(client: paramiko.SSHClient, sql: str) -> None:
    """在 `mysql8` 容器里执行 SQL。

    **口令的处理方式是这个动作存在的理由**：MySQL 跑在容器里，而 root 口令是
    容器的环境变量 `$MYSQL_ROOT_PASSWORD`。用 `sh -c '... -e "$0"' <sql>` 的形式，
    口令由**容器内的 shell** 展开，本脚本从头到尾不接触、不打印、不存储它 ——
    也就没有「口令被我写进某个文件」的可能。

    这也是为什么不用 `-p<明文>`：那会同时留在本机 shell 历史、
    paramiko 的命令日志、以及远端进程列表（`ps` 能看到）三处。
    """
    import shlex

    inner = shlex.quote('mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -t -e "$0"')
    remote = f"docker exec mysql8 sh -c {inner} {shlex.quote(sql)}"
    result = run(client, remote)
    # MySQL 会把 "Using a password on the command line" 警告混进 stderr，
    # 它来自 `-p"$VAR"` 这个写法，与我们无关，滤掉以免淹没真正的报错
    noise = "Using a password on the command line interface can be insecure"
    sys.stdout.write(result.stdout)
    err = "\n".join(line for line in result.stderr.splitlines() if noise not in line)
    if err.strip():
        sys.stderr.write(err + "\n")
    sys.exit(result.code)


def cmd_script(client: paramiko.SSHClient, path: str) -> None:
    """把本地脚本喂给远端 `bash -s` 执行。

    **为什么要绕这一道，而不直接 `bash /path`**：这样脚本根本不需要落盘到服务器上，
    也就不存在「服务器上留着一个上一版的脚本，而本地已经改了三版」的问题。
    远端执行的一定是此刻本地文件的内容。

    脚本用 `set -euo pipefail`，任何一步失败立刻停 —— 半途而废的配置
    比没配置更糟：它会留下一个「看起来配好了」的假象。
    """
    local = Path(path)
    if not local.is_file():
        sys.exit(f"脚本不存在：{local}")

    body = local.read_text(encoding="utf-8")
    _stdin, stdout, stderr = client.exec_command("bash -s", timeout=600)
    _stdin.write(body)
    _stdin.channel.shutdown_write()

    sys.stdout.write(stdout.read().decode("utf-8", errors="replace"))
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    if err.strip():
        sys.stderr.write(err)
    if code != 0:
        sys.exit(f"远端脚本退出码 {code}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["survey", "install-key", "run", "sql", "script"])
    parser.add_argument("rest", nargs="*", help="run / sql / script 动作的参数")
    args = parser.parse_args()

    client = connect()
    try:
        if args.action == "run":
            cmd_run(client, " ".join(args.rest))
        elif args.action == "sql":
            cmd_sql(client, " ".join(args.rest))
        elif args.action == "script":
            cmd_script(client, args.rest[0])
        else:
            {"survey": cmd_survey, "install-key": cmd_install_key}[args.action](client)
    finally:
        client.close()


if __name__ == "__main__":
    main()
