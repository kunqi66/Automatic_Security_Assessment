"""全局配置 —— 环境相关取值的唯一来源。

**为什么所有配置都必须走这里**：如果允许各处 `os.getenv`，那么「系统有哪些配置项、
默认值是什么、生产环境必须给什么」就没有单一答案，缺失的密钥会在某个冷门分支上
才暴露。集中到 Settings 之后，「生产环境配置不全 = 启动即失败」可以用一个
model_validator 表达，而不是靠人记得。

对应 PRD §8.3「密钥走环境变量」。
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from urllib.parse import quote_plus

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# 开发态默认密钥。生产环境若仍是这个值，启动会被 model_validator 拦下。
# noqa 的理由：这是**故意**写死的，因为「有默认值」本身才是被检测的对象 ——
# 生产自检拿它做比较，一致就拒绝启动。改成随机生成反而会让自检永远通过。
_DEV_JWT_SECRET = "dev-only-secret-change-me"  # noqa: S105


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---------- 应用 ----------
    app_name: str = "自动化安全评估系统"
    debug: bool = False
    api_prefix: str = "/api/v1"

    # ---------- MySQL ----------
    mysql_host: str = "127.0.0.1"
    mysql_port: int = 3306
    mysql_user: str = "asa"
    mysql_password: str = ""
    mysql_database: str = "security_assessment"
    #: 连接池大小。**默认值由 SSH 隧道的通道上限决定，不是由数据库决定的。**
    #:
    #: 数据库在 ECS 上，本机经 `deploy/tunnel.py` 的 SSH 隧道访问
    #: （`127.0.0.1:13306` → `60.205.138.167:3306`）。而 ECS 的 sshd
    #: `MaxSessions` 默认 **10，且按"通道"计而不是按"客户端"计** ——
    #: 每条经隧道的 MySQL 连接占一条通道，**API 与 worker 共享这 10 条**。
    #:
    #: 取 5 时一个进程的上限是 `pool_size(5) + max_overflow(5) = 10`，
    #: 一个进程就能吃满全部通道；两个进程一起跑必然超限，症状是 sshd 关掉通道、
    #: 本机侧留下 `CLOSE_WAIT` 的死 socket —— 而 `pool_pre_ping` **救不了它**：
    #: 半开的通道上读操作是**挂住**而不是报错，于是每个请求先卡十几秒再 500。
    #: 这是实测踩到的（`health` 返回 500 且耗时 19s，同时新建连接一切正常）。
    #:
    #: 取 2 ⇒ 每进程上限 4 条，两个进程共 8 条，给隧道自身的 SSH 连接留出余量。
    #: 2 vCPU 上并发度本来就恒为 1，池子再大也只是占着通道不用。
    mysql_pool_size: int = Field(default=2, ge=1, le=20)
    mysql_echo: bool = False
    #: 覆盖 DSN 的逃生口，只给 Alembic 用：没有可用 MySQL 时，可指向一个临时库
    #: 生成**方言无关**的首版迁移（迁移文件里是 op.create_table 之类的抽象操作，
    #: 真正执行时才由 MySQL 方言渲染 DDL）。生产留空。
    database_url_override: str = ""

    # ---------- Redis ----------
    redis_host: str = "127.0.0.1"
    redis_port: int = 6379
    redis_password: str = ""
    redis_db: int = Field(default=3, ge=0, le=15)

    #: 套接字读超时（秒）。**必须显式设置，不能靠 redis-py 的默认值。**
    #:
    #: ⚠️ redis-py 8.x 的 `DEFAULT_SOCKET_TIMEOUT` 是 **5 秒**
    #: （`redis/_defaults.py`），而不是旧版本的 `None`。老代码里
    #: 「不设 socket_timeout = 永不超时」这个心智模型**已经不成立**了。
    #: 不显式给值的后果：任何阻塞超过 5 秒的 Redis 命令都会抛
    #: `TimeoutError: Timeout reading from ...`。
    #:
    #: 本系统唯一的长时间阻塞命令是 worker 的 `XREADGROUP ... BLOCK`
    #: （见 `worker_poll_block_ms`），所以这两个值必须一起看 ——
    #: 下面的 `_check_block_under_socket_timeout` 会强制它们的关系。
    redis_socket_timeout_seconds: float = Field(default=20.0, gt=0)

    #: worker 阻塞读队列的时长。空闲时每这么多毫秒空转一次。
    #:
    #: **必须严格小于 `redis_socket_timeout_seconds`**：`BLOCK 5000` 让
    #: Redis 沉默 5 秒才回一个空数组，而套接字超时也是 5 秒时两者会赛跑 ——
    #: 实测结果是套接字先输，worker 每 5 秒报一次
    #: 「读取任务队列失败」并把超时当故障，而 Redis 那边一切正常。
    #: 取 2 秒：新任务最多等 2 秒被取走，同时离 20 秒的超时线很远。
    worker_poll_block_ms: int = Field(default=2000, ge=100, le=60_000)

    # ---------- JWT ----------
    jwt_secret: str = _DEV_JWT_SECRET
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = Field(default=480, ge=5)

    # ---------- LLM ----------
    # API Key 不入库（PRD §6 llm_configs）：只从环境读，避免随数据库备份泄露
    deepseek_api_key: str = ""
    llm_base_url: str = "https://api.deepseek.com/v1"
    llm_model: str = "deepseek-chat"
    llm_timeout_seconds: int = Field(default=15, ge=1)
    llm_max_retries: int = Field(default=1, ge=0, le=3)

    # ---------- 沙箱（远程 Docker over SSH，PRD §7.2）----------
    docker_host: str = ""
    docker_ssh_key_path: str = ""
    # Q23 定案：源码 tar 流落到 ECS 的这个根目录下，按 assessment_id 分目录
    ecs_source_root: str = "/srv/asa/tasks"
    sandbox_default_image: str = "asa/sandbox-base:latest"
    sandbox_exec_timeout_seconds: int = Field(default=30, ge=1)
    sandbox_container_ttl_seconds: int = Field(default=1800, ge=60)

    # ---------- 接入源约束 ----------
    #: Git 地址白名单。**空列表 = 不限制，仅限本地开发**（PRD §12 风险 8 第 ② 条：
    #: 公网演示时必须只允许扫内置靶场）。留空在生产环境是危险的，
    #: 所以在下面 `_check_production_secrets` 里会一并拦截。
    git_url_allowlist: list[str] = []

    # ---------- 归档解包上限 ----------
    #: 压缩炸弹防护：解压后总字节上限与条目数上限。
    #: 两者都要有 —— 只看体积的话，「十万个 1 字节文件」照样能拖垮文件系统。
    archive_max_total_bytes: int = Field(default=500 * 1024 * 1024, ge=1024 * 1024)
    archive_max_entries: int = Field(default=50_000, ge=100)

    # ---------- 控制面源码工作区（总纲 §7.4）----------
    workspace_root: Path = Path("D:/myself_complete_code/.asa/workspaces")
    #: 报告落盘根目录。与 `workspace_root` 分开是刻意的：报告的保留策略
    #: （按需清理旧报告）与源码工作区（项目删了就清）完全不同，
    #: 混在一棵树下会让「清源码」顺手把报告也删了。
    report_root: Path = Path("D:/myself_complete_code/.asa/reports")

    # ---------- 分析引擎约束 ----------
    # 单漏洞探针上限与单探针超时共同把最坏耗时锁在 10 分钟量级（总纲 §8.1）
    max_probes_per_vuln: int = Field(default=20, ge=1, le=100)
    # 单文件大小上限：超过就不解析，避免一个巨型生成文件拖垮整轮扫描
    max_source_file_bytes: int = Field(default=2 * 1024 * 1024, ge=1024 * 100)

    # 静态扫描的规模闸。B4 自己也有同名的默认值（`analysis.taint.DEFAULT_*`），
    # 但那是**模块内部的兜底**，不是配置 —— 与 `max_source_file_bytes` 的区别在
    # 「谁来决定」：B4 是纯函数、不许读全局配置，所以由 `code_audit` 从这里取了
    # 显式传进去。改这三项**不需要动 B4 的代码**，这是它们进配置的意义。
    #
    # 超限的后果是**截断而不是失败**：`AnalysisResult.truncated=True`，
    # 报告里会注明「本轮只扫了前 N 个文件」。
    analysis_max_files: int = Field(default=2000, ge=1)
    #: 整轮扫描的墙钟上限（秒）。2 vCPU 上按 2000 文件量级估的；
    #: 它是**总闸**，单个文件没有独立超时（tree-sitter 的 C 层调用无法安全中断，
    #: 加线程看门狗反而会把非确定性引进 L1）。
    analysis_max_seconds: float = Field(default=60.0, gt=0)
    #: 单文件解析上限。与 `max_source_file_bytes` 守的是**两个不同的边界**
    #: （那个管 workspace 读文件，这个管分析引擎入口），但**默认值必须一致**：
    #: 若引擎入口比 workspace 更严，一个 2.05 MB 的文件会先被读出来、
    #: 再被引擎静默跳过 —— 产生一条「读得到却分析不了」的 SkipRecord，
    #: 而排查的人会从文件读取权限开始查，方向完全错。
    #: 要收紧就同时收紧两个，不要只动这一个。
    analysis_max_file_bytes: int = Field(default=2 * 1024 * 1024, ge=1024)

    # ---------- 编排引擎（B3）----------
    # 并发度恒为 1（总纲 D12）：2 vCPU + Milvus 常驻，并发只会撞 OOM。
    # 消费者名做成配置而不是常量，是为了将来扩容时不必改代码 —— 但本期就一个。
    task_queue_name: str = "task:queue"
    task_queue_dead_name: str = "task:queue:dead"
    task_consumer_group: str = "asa-workers"
    task_consumer_name: str = "worker-1"
    #: 消费重试上限。超了进死信 —— 总纲 §8.1 定的是 3 次。
    task_max_retries: int = Field(default=3, ge=1, le=10)
    #: 重试退避基数，指数增长：1s / 2s / 4s（B3 设计 §8 待定项 5）
    task_retry_backoff_seconds: float = Field(default=1.0, gt=0)

    #: 日志流的长度上限（`XTRIM MAXLEN ~`）。~ 是近似裁剪，Redis 按节点粒度删，
    #: 比精确 MAXLEN 快得多，代价是实际长度可能略超一点 —— 这里不需要精确。
    log_stream_maxlen: int = Field(default=5000, ge=100)
    #: 阶段结束时写进 `assessment_stages.log_excerpt` 的摘要长度。
    #: 只留尾巴：失败原因几乎总在最后几行，而全量日志落表在 19G 磁盘上是纯负担。
    log_excerpt_max_lines: int = Field(default=100, ge=10)
    log_excerpt_max_bytes: int = Field(default=8 * 1024, ge=512)

    #: 上下文快照的体积上限。`result_ref` 是 JSON 列，超了会撑爆行（B3 设计 §8 待定项 3）
    context_payload_max_bytes: int = Field(default=256 * 1024, ge=4096)

    #: 资源指标采样间隔与保留天数（B3 设计 §8 待定项 7）
    metrics_sample_interval_seconds: float = Field(default=5.0, ge=0.5)
    metrics_retention_days: int = Field(default=30, ge=1)

    #: 单个评估的整体超时。**这是兜底而非主控**：正常靠单探针 30s × 上限 20 收敛，
    #: 但一个卡死的 Agent 不该让 worker 永久占着（并发度恒为 1，占住就是全线停摆）。
    assessment_timeout_seconds: int = Field(default=3600, ge=60)

    # ---------- worker 生命周期 ----------
    #: 收到停止信号后等当前任务做完的上限。
    #: 取 120s 的理由：要容下最慢的单个阶段（`poc_verify` 的探针上限是
    #: 20 × 30s = 10 分钟，但那是整个阶段；单条消息的等待窗口按
    #: 「人还愿意等 docker stop 多久」来定，超过就交给下次启动恢复）。
    worker_shutdown_grace_seconds: float = Field(default=120.0, gt=0)

    # ---------- HTTP ----------
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # ------------------------------------------------------------------
    # 派生属性
    # ------------------------------------------------------------------

    @property
    def mysql_dsn(self) -> str:
        """SQLAlchemy async DSN。口令做 URL 编码 —— 含 @ / : 的口令不编码必然解析错。"""
        return (
            f"mysql+aiomysql://{quote_plus(self.mysql_user)}:{quote_plus(self.mysql_password)}"
            f"@{self.mysql_host}:{self.mysql_port}/{self.mysql_database}?charset=utf8mb4"
        )

    @property
    def effective_dsn(self) -> str:
        return self.database_url_override or self.mysql_dsn

    @property
    def data_plane_ssh_target(self) -> str | None:
        """从 `docker_host` 里解出 ECS 的 `user@host`，供源码同步复用。

        **刻意不新增一组 ECS 主机配置**：`docker_host` 已经描述了一次数据面地址
        （`ssh://root@host:port`）。再写一份 `ecs_host` 的后果是两者会漂移 ——
        容器建在 A 机器上、源码推到 B 机器上，而挂载失败时的报错只会说「路径不存在」。
        地址只有一个来源。

        返回 None 表示未配置数据面（源码同步将跳过，见 §8.2 降级矩阵）。
        """
        raw = self.docker_host.strip()
        if not raw:
            return None
        # 支持 ssh://user@host:port 与 user@host:port 两种写法
        body = raw.removeprefix("ssh://")
        return body or None

    @property
    def redis_dsn(self) -> str:
        auth = f":{quote_plus(self.redis_password)}@" if self.redis_password else ""
        return f"redis://{auth}{self.redis_host}:{self.redis_port}/{self.redis_db}"

    @property
    def llm_available(self) -> bool:
        """没有 key 不算错误 —— 系统按 PRD §7.6 L4 降级为模板生成，结论不受影响。"""
        return bool(self.deepseek_api_key)

    # ------------------------------------------------------------------
    # 生产环境自检
    # ------------------------------------------------------------------

    @model_validator(mode="after")
    def _check_block_under_socket_timeout(self) -> Settings:
        """阻塞时长必须严格小于套接字超时。

        **这条与 DEBUG 无关，任何时候都要成立** —— 所以它单独一个 validator，
        不放进只对生产生效的 `_check_production_secrets`。

        改成警告是不行的：这个组合出错时的症状是「worker 在启动日志里刷
        `Timeout reading from`」，而排查的人会去查网络、查隧道、查 Redis 负载，
        不会想到是两个配置项的数值撞在了一起。**启动即失败**才能把方向拨正。
        """
        block_seconds = self.worker_poll_block_ms / 1000
        if self.redis_socket_timeout_seconds <= block_seconds:
            raise ValueError(
                f"REDIS_SOCKET_TIMEOUT_SECONDS（{self.redis_socket_timeout_seconds}）"
                f"必须大于 WORKER_POLL_BLOCK_MS（{self.worker_poll_block_ms}ms = "
                f"{block_seconds}s）：阻塞读会让套接字静默这么久，两者相等或反过来的话，"
                f"套接字会先超时，worker 把正常的空轮询当成故障。"
            )
        return self

    @model_validator(mode="after")
    def _check_production_secrets(self) -> Settings:
        """生产环境（DEBUG=false）下密钥缺失即启动失败。

        **刻意如此，不要降级成 warning**：带着空密钥或默认密钥跑起来，
        表现是「越权能过 / 数据能被解」，而这两种故障都不会在启动时自己叫出来。
        """
        if self.debug:
            return self

        problems: list[str] = []
        if not self.jwt_secret or self.jwt_secret == _DEV_JWT_SECRET:
            problems.append("JWT_SECRET 未设置或仍是开发默认值")
        if not self.mysql_password:
            problems.append("MYSQL_PASSWORD 为空")
        if not self.git_url_allowlist:
            # PRD §12 风险 8：公网可达时若不限制可扫仓库，本系统就成了
            # 「任意仓库克隆 + 自动攻击」的跳板。开发态无妨，生产必须显式给出。
            problems.append("GIT_URL_ALLOWLIST 为空（生产环境必须限定可扫描的仓库）")

        if problems:
            joined = "；".join(problems)
            raise ValueError(f"生产环境配置不完整，拒绝启动：{joined}（本地开发请设 DEBUG=true）")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """进程内单例。FastAPI 依赖注入与 Alembic 都从这里取，保证同一份配置。"""
    return Settings()


settings = get_settings()
