#!/usr/bin/env bash
# 阿里云 ECS 数据面基础配置（PRD §2.2 的前置动作项）。
#
# 设计约束：**这台机器上还跑着别的服务**（MySQL / Redis / Milvus / Attu）。
# 脚本里的每一步都是「不存在才创建」，不覆盖任何既有配置，也不重启任何容器。
# 重复执行的结果与执行一次相同 —— 因为运维脚本总有一天会被重跑，
# 而「重跑一次就把环境搞坏」的脚本，出事时恰恰是最不敢用的那个。
set -euo pipefail

SWAPFILE=/swapfile
SWAP_SIZE=2G
ASA_ROOT=/srv/asa

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
say "1/3 swap"
# ---------------------------------------------------------------------------
# 2 vCPU / 7.3G，跑着 Milvus，而 swap = 0。没有 swap 意味着任何一次内存尖峰
# 都由内核直接选一个进程 OOM kill —— 在 Milvus 和 MySQL 之间选谁，不由我们决定。
if swapon --show=NAME --noheadings | grep -qx "$SWAPFILE"; then
    echo "swap 已启用，跳过"
else
    if [ -f "$SWAPFILE" ]; then
        echo "$SWAPFILE 已存在但未启用，复用"
    else
        # fallocate 比 dd 快得多，但**在部分文件系统上是稀疏文件**，
        # 那样内核可能拒绝 swapon。回退到 dd 保证是真的分配了块。
        fallocate -l "$SWAP_SIZE" "$SWAPFILE" 2>/dev/null || \
            dd if=/dev/zero of="$SWAPFILE" bs=1M count=2048 status=none
    fi
    chmod 600 "$SWAPFILE"
    mkswap "$SWAPFILE" >/dev/null
    swapon "$SWAPFILE"
    echo "已启用 $SWAP_SIZE swap"
fi

# 开机自动挂载。**先 grep 再追加**，否则每跑一次脚本 fstab 就多一行，
# 最后 swapon -a 会因为重复条目而报错。
if ! grep -qE "^\s*$SWAPFILE\s" /etc/fstab; then
    printf '%s none swap sw 0 0\n' "$SWAPFILE" >> /etc/fstab
    echo "已写入 /etc/fstab"
else
    echo "/etc/fstab 已有条目，跳过"
fi

# swappiness 默认 60，对一台跑着 Milvus + MySQL 的机器太激进：它会在还有
# 空闲内存时就把热页换出去，换来的是查询延迟的随机尖刺。10 表示
# 「只在真的快没内存时才用 swap」—— 它在这里的定位是**保命**，不是扩容。
SYSCTL_FILE=/etc/sysctl.d/99-asa-swap.conf
if [ ! -f "$SYSCTL_FILE" ]; then
    printf 'vm.swappiness=10\nvm.vfs_cache_pressure=50\n' > "$SYSCTL_FILE"
    sysctl -p "$SYSCTL_FILE" >/dev/null
    echo "已设置 vm.swappiness=10"
else
    echo "$SYSCTL_FILE 已存在，跳过"
fi

# ---------------------------------------------------------------------------
say "2/3 /srv/asa 目录"
# ---------------------------------------------------------------------------
# 三个子目录的分工（总纲 §7.4 的三个路径空间之一：数据面 POSIX 绝对路径）：
#   tasks/   —— B1 推送上来的源码，{assessment_id}/src，由 B2 只读挂载进容器
#   reports/ —— B6 生成的报告文件
# 权限 750：源码里可能有客户的私有代码，不给 other 任何位。
install -d -m 750 "$ASA_ROOT" "$ASA_ROOT/tasks" "$ASA_ROOT/reports"
ls -ld "$ASA_ROOT" "$ASA_ROOT/tasks" "$ASA_ROOT/reports"

# ---------------------------------------------------------------------------
say "3/3 汇总"
# ---------------------------------------------------------------------------
free -h
echo
df -h / | tail -1
echo
echo "Docker: $(docker version --format '{{.Server.Version}}')"
echo "容器："
docker ps --format '  {{.Names}}\t{{.Status}}'
