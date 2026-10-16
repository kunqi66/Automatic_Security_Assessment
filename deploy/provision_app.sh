#!/usr/bin/env bash
# 应用层部署：把后端装到 ECS 上并以 systemd 服务运行。
#
# **前置**：`provision_base.sh` 已经跑过（swap + /srv/asa 目录）。
# 本脚本只做应用层的事，且和基础脚本一样是**幂等**的：
# 每一步都是「不存在才创建」，重复执行结果相同。
#
# 用法（在 ECS 上，root）：
#   bash provision_app.sh /srv/asa/app
#
# 前提：`/srv/asa/app` 下已经有代码（rsync 或 git clone 过去）。
# 本脚本**不拉代码** —— 代码怎么上去是另一件事（rsync / git / scp），
# 混进来会让「部署失败」这个结论分不清是代码没上去还是脚本有问题。
set -euo pipefail

APP_ROOT="${1:-/srv/asa/app}"
BACKEND="$APP_ROOT/backend"
ASA_USER=asa

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\033[31m错误：%s\033[0m\n' "$*" >&2; exit 1; }

[ -d "$BACKEND" ] || die "$BACKEND 不存在。请先把代码放到 $APP_ROOT 再跑本脚本。"
[ -f "$BACKEND/pyproject.toml" ] || die "$BACKEND 下没有 pyproject.toml，路径不对？"

# ---------------------------------------------------------------------------
say "1/6 服务账号"
# ---------------------------------------------------------------------------
# **不用 root 跑**。这套系统的职责就是「在别人的代码上找漏洞并起容器执行探针」，
# 用一个专用账号是底线。它需要 docker 组的权限来创建探针容器 ——
# 那确实等于事实上的 root（docker 组历来如此），但至少：
#   ① 它不能改系统文件；② 审计日志里能一眼看出哪些操作来自应用。
if id "$ASA_USER" &>/dev/null; then
    echo "用户 $ASA_USER 已存在"
else
    useradd --system --create-home --shell /usr/sbin/nologin "$ASA_USER"
    echo "已创建用户 $ASA_USER"
fi

if getent group docker &>/dev/null; then
    if id -nG "$ASA_USER" | tr ' ' '\n' | grep -qx docker; then
        echo "$ASA_USER 已在 docker 组"
    else
        usermod -aG docker "$ASA_USER"
        echo "已把 $ASA_USER 加入 docker 组"
    fi
else
    die "没有 docker 组。请确认 Docker 已安装（provision_base.sh 的前置条件）。"
fi

chown -R "$ASA_USER:$ASA_USER" "$APP_ROOT"

# ---------------------------------------------------------------------------
say "2/6 uv"
# ---------------------------------------------------------------------------
# 装到 /usr/local/bin 而不是 ~/.local/bin：systemd unit 里写死了这个路径，
# 而 service 的 PATH 与登录 shell 的 PATH 不是一回事 ——
# 「我明明装了 uv，systemd 就是说找不到」就是这么来的。
if [ -x /usr/local/bin/uv ]; then
    echo "uv 已安装：$(/usr/local/bin/uv --version)"
else
    command -v curl >/dev/null || die "需要 curl"
    curl -LsSf https://astral.sh/uv/install.sh | \
        env UV_INSTALL_DIR=/usr/local/bin sh
    echo "已安装 uv：$(/usr/local/bin/uv --version)"
fi

# ---------------------------------------------------------------------------
say "3/6 依赖同步"
# ---------------------------------------------------------------------------
# 以 asa 身份同步，避免 root 建的 .venv 后面 asa 写不进去。
# **不带 dev extra**：服务器上不需要 pytest / ruff。
sudo -u "$ASA_USER" env HOME="$(getent passwd "$ASA_USER" | cut -d: -f6)" \
    /usr/local/bin/uv sync --project "$BACKEND" --frozen
echo "依赖已同步"

# ---------------------------------------------------------------------------
say "4/6 .env"
# ---------------------------------------------------------------------------
if [ -f "$BACKEND/.env" ]; then
    echo ".env 已存在，**不覆盖**（里面有密钥）"
    echo "如需变更请手工编辑：$BACKEND/.env"
else
    cp "$BACKEND/.env.example" "$BACKEND/.env"
    chown "$ASA_USER:$ASA_USER" "$BACKEND/.env"
    chmod 600 "$BACKEND/.env"
    echo "已从 .env.example 生成 .env（权限 600）"
    echo
    echo "⚠️  下一步必须手工填写 .env，至少这几项："
    echo "      MYSQL_PASSWORD   MySQL 专用账号密码"
    echo "      REDIS_PASSWORD   Redis 密码（若已设）"
    echo "      JWT_SECRET       随机串，见下方生成命令"
    echo "      DEEPSEEK_API_KEY DeepSeek 密钥（不填则全程降级为模板，功能可用）"
    echo
    echo "    JWT_SECRET 生成："
    echo "      python3 -c 'import secrets;print(secrets.token_urlsafe(48))'"
    echo
    echo "  填完后**重新跑一次本脚本**，或直接 start 服务。"
fi
chmod 600 "$BACKEND/.env" 2>/dev/null || true

# ---------------------------------------------------------------------------
say "5/6 数据库迁移"
# ---------------------------------------------------------------------------
# 以 asa 身份跑 alembic：迁移会写 alembic_version 表，
# 用 root 跑会让那张表的属主变成 root，之后 asa 就改不动了。
if [ -f "$BACKEND/alembic.ini" ]; then
    sudo -u "$ASA_USER" env HOME="$(getent passwd "$ASA_USER" | cut -d: -f6)" \
        /usr/local/bin/uv run --no-sync --project "$BACKEND" \
        alembic -c "$BACKEND/alembic.ini" upgrade head
    echo "迁移已应用"
else
    echo "跳过：没有 alembic.ini"
fi

# ---------------------------------------------------------------------------
say "6/6 systemd"
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for unit in asa-api asa-worker; do
    src="$SCRIPT_DIR/$unit.service"
    [ -f "$src" ] || die "找不到 $src"
    # 路径参数化：unit 里写的是 /srv/asa/app，换了目录就替换掉。
    # 用 `|` 作分隔符，因为路径里有 `/`。
    sed "s|/srv/asa/app|$APP_ROOT|g" "$src" > "/etc/systemd/system/$unit.service"
    echo "已安装 /etc/systemd/system/$unit.service"
done

systemctl daemon-reload
systemctl enable asa-api.service asa-worker.service >/dev/null
echo "已设为开机自启"

cat <<EOF

部署完成。接下来：

  systemctl start asa-api asa-worker
  systemctl status asa-api asa-worker --no-pager
  journalctl -u asa-api -u asa-worker -f

验证（本机）：
  curl -s localhost:8010/api/v1/health

⚠️  API **只监听 127.0.0.1:8010**，公网访问不了。
    这是刻意的：这套系统一旦暴露在公网，任何人都能用它扫你的内网。
    对外提供服务的正确做法是前面放一层 Nginx（同源反代 /api），
    并在 Nginx 上做登录校验与速率限制 —— 而不是把 8010 开出去。
    详见 vibecoding_doc/ECS安全现状.md 与 PRD §12 风险 8。
EOF
