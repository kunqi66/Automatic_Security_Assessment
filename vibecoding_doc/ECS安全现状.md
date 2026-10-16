# ECS（60.205.138.167）安全现状

> 记录日期：2026-10-16　　记录人：本次开发会话
> 起因：为部署本系统的数据面而勘察该机器时，发现历史入侵痕迹。
>
> **本文只做记录，不代表已经修复。** 按使用者 2026-10-16 的决定，
> 除新增 swap 与新建本系统的库/账号外，**未对既有服务做任何改动**。

---

## 1. 结论摘要

这台机器在 **2026-10-01 19:16** 遭到过自动化的 MySQL 勒索攻击，攻击者留下的
勒索库至今仍在。**当前最紧急的敞口不是那次攻击本身，而是两个仍然对全网开放的端口**：

| 优先级 | 事项 | 现状 |
|---|---|---|
| 🔴 P0 | Milvus `19530` 与 Attu `8000` 对**整个互联网**开放，Milvus 默认无认证 | 未修复 |
| 🔴 P0 | MySQL `root@'%'` 账号仍然存在，任意主机可尝试登录 | 未修复 |
| 🟠 P1 | Redis `requirepass` 为空（无认证） | 未修复（端口已被安全组挡住，暂不暴露） |
| 🟠 P1 | 勒索库 `RECOVER_YOUR_DATA` 未被清理 | 未修复（刻意保留为证据） |
| 🟡 P2 | 被入侵过的 MySQL 实例上存放本系统的数据 | 已用专用账号 + 专用库 + 隧道隔离，但仍同住一个实例 |

---

## 2. 入侵证据

### 2.1 勒索信

`RECOVER_YOUR_DATA` 库（单表，与库同名），内容：

```
All your data was backed up by us. You must pay 0.0101 bitcoin to
bc1qt6kstjjdatqnxd3ksdcfv0jnhdjzndcnkx8zla or in 48 hours, your data
will be publicly disclosed and deleted.
(for more information visit https://cuq.in/844) After payment send mail to
ak+28xmi@onionmail.org and we will provide a link for you to download your
data. Your DATAID is: 28XMI
```

这是自动化 MySQL 勒索工具的标准投放物。特征：单一同名表、
固定格式的英文勒索信、比特币地址、`onionmail.org` 邮箱、短域名跳转。

### 2.2 时间线

| 时间 | 事件 | 证据 |
|---|---|---|
| 2026-09-20 10:42 | MySQL 容器初始化（`mysql8`，卷 `mysql8_data`） | 数据目录文件时间 |
| **2026-10-01 19:16** | **勒索库被创建，同时 binlog 被重置** | `RECOVER_YOUR_DATA/` 目录 mtime；`binlog.index` mtime 且只剩 1 条记录 |
| 2026-10-05 11:03 | `commerce`、`customer_service` 被重新创建 | 目录 mtime + binlog 里的 `CREATE DATABASE` |
| 2026-10-15 10:29 | `rag_kb` 仍在正常写入 | 目录 mtime |
| 2026-10-16 | 本次勘察 | —— |

**binlog 在同一分钟被重置，是这次记录里最值得注意的一点。** 它是典型的
反取证动作（`RESET MASTER` 或 `PURGE BINARY LOGS`），后果是**入侵前后的
SQL 语句没有任何留档** —— 攻击者具体删了什么、导出过什么，从 binlog 已经查不出来了。

### 2.3 数据现状（截至勘察时）

| 库 | 大小 | 表数 | 判断 |
|---|---|---|---|
| `rag_kb` | 14.2 MB | 20 | 完好，10-15 仍在写 |
| `commerce` | 0.3 MB | 8 | 攻击后重建（10-05） |
| `customer_service` | ~0 MB | 1 | 攻击后重建（10-05），**只有 1 张表，建议确认是否完整** |
| `RECOVER_YOUR_DATA` | ~0 MB | 1 | 勒索信，**非业务数据** |

> ⚠️ 无法从现有证据判断数据是否曾被**导出**。勒索信声称"已备份"，但这是
> 模板话术，不能当作事实，也不能当作虚张声势。**保守假设：曾暴露过的数据
> 都应视为已泄露。**

---

## 3. 攻击面勘察（2026-10-16 从公网实测）

```
3306   closed/filtered      ← 安全组已挡住 ✅
6379   closed/filtered      ← 安全组已挡住 ✅
19530  OPEN                 ← Milvus，全公网可达 ⚠️
8000   OPEN                 ← Attu（Milvus 控制台），全公网可达 ⚠️
22     open                 ← SSH
```

**注意 3306 现在是关的，但入侵发生在 10-01。** 无法确定当时是否开放 ——
安全组的历史变更记录需要到阿里云控制台查。这一点很重要：
如果 3306 从未开放过，那么攻击者是从别的路径拿到 MySQL 凭据的，
**那条路径可能还开着**（比如 Milvus 或别的服务）。**建议去控制台核对安全组变更历史。**

### 3.1 账号

```sql
root     @ '%'          ← 任意主机可登录，是这次入侵最可能的入口
root     @ 'localhost'
ai_user  @ '%'          ← 同样绑定通配主机
```

### 3.2 Redis

`requirepass` 为空 —— 即**无认证**。当前 6379 被安全组挡住，所以不直接暴露；
但一旦哪天为了图方便开放端口，这台 Redis 就是完全裸奔的。

---

## 4. 本次为部署本系统所做的改动（全部为增量，未覆盖既有配置）

| 改动 | 内容 | 影响面 |
|---|---|---|
| swap | 新增 `/swapfile` 2GB，写入 `/etc/fstab`，`vm.swappiness=10` | 无（原本为 0） |
| 目录 | 新建 `/srv/asa/{tasks,reports}`，权限 750 | 无 |
| 数据库 | 新建 `security_assessment`（utf8mb4/unicode_ci） | 无 |
| 数据库账号 | 新建 `asa_user@'172.17.0.%'`，**仅授予 `security_assessment.*`** | 无 |
| 表结构 | 迁移建 15 张业务表 + `alembic_version` | 无 |

**没有做的事**（按使用者决定）：未改 root 口令、未删任何账号、未清理勒索库、
未改 sshd 配置、未动安全组、未重启任何容器。

### 4.1 本系统的连接方式

3306/6379 不对公网开放，控制面（Windows）经 **SSH 隧道**访问：

```
Windows  127.0.0.1:13306  ──ssh──>  ECS 127.0.0.1:3306  ──>  mysql8 容器
Windows  127.0.0.1:16379  ──ssh──>  ECS 127.0.0.1:6379  ──>  redis 容器
```

隧道工具：`deploy/tunnel.py`。这样做的好处是**不需要在安全组上再开任何端口**，
且链路加密 —— 本系统要存客户源码片段、漏洞详情和补丁，明文公网连接不可接受。

---

## 5. 建议的处置（按优先级，均需使用者确认后再动手）

### P0 — 建议尽快

1. **关闭安全组的 19530 与 8000**（或限制到固定源 IP）。
   这是当前唯一对全网开放的高价值服务。若确实需要远程访问 Milvus，
   走 SSH 隧道，参考 `deploy/tunnel.py` 的写法。
2. **给 Milvus 开启认证**，或确认它是否真的需要对外。
3. **处理 `root@'%'`**：
   ```sql
   -- 先确认没有服务在用远程 root 连接，再执行
   DROP USER 'root'@'%';
   ALTER USER 'root'@'localhost' IDENTIFIED BY '<新口令>';
   ```
   同时检查 `ai_user@'%'` 是否也需要收窄到具体主机。
4. **核对阿里云安全组的历史变更记录**，确认 10-01 前后 3306 是否开放过。
   这决定了「攻击者是怎么进来的」这个问题的答案。

### P1 — 建议本月内

5. **清理勒索库**（确认已不需要作为证据后）：`DROP DATABASE RECOVER_YOUR_DATA;`
6. **给 Redis 设 `requirepass`**，并同步更新所有使用方（db 0 有 260 个键，
   db 1 有 6 个，改之前要先找出是谁在用）。
7. **确认 `customer_service` 库只有 1 张表是正常的**，还是攻击的后果。
8. **全量备份 + 离线留存**：现在所有数据只有一份，且所在实例有被入侵史。

### P2 — 长期

9. 把 MySQL/Redis 的数据目录纳入定期备份，备份文件不与实例同机存放。
10. 给所有对外的服务端口建立清单与复查机制 —— 这次发现 19530/8000 敞开，
    说明"哪些端口对外"这件事目前没有人在看。
11. **重新考虑这台机器的定位**：它同时承载着曾遭入侵的 MySQL、无认证的 Redis、
    对全网开放的 Milvus，以及本系统的数据面。建议至少把 Milvus 与本系统的
    沙箱容器做网络隔离（本系统的沙箱本来就设计在 `internal` 无出网网络里）。

---

## 6. 附：本次勘察用到的命令

全部为只读查询，脚本见 `deploy/ecs.py`（`survey` / `sql` / `run` 三个动作）。

```bash
# 勘察
ECS_PASSWORD=... uv run --with paramiko python deploy/ecs.py survey

# 只读 SQL（口令由容器内 shell 展开，本机不接触）
ECS_PASSWORD=... uv run --with paramiko python deploy/ecs.py sql "show databases;"

# 公网端口实测
for p in 3306 6379 19530 8000; do
  timeout 6 bash -c "cat < /dev/null > /dev/tcp/60.205.138.167/$p" && echo "$p OPEN"
done
```
