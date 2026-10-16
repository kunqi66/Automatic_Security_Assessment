"""验证闭环的执行编排与**状态裁决**（B5 设计 §3.1 / §4.1）。

## 两种调用形状，一个实现

- 契约 4 定的是 `verify_finding(finding, sandbox, handle) -> VerificationResult`
  —— 单个 Finding 的入口，B3 的 `PocVerifyAgent` 逐条调用，自己掌握循环与进度。
- 设计 §3.1 写的是 `PocVerifier.verify_findings(findings, ctx, on_progress)`
  —— 批量入口，内含「串行、并发度恒为 1」的纪律与阶段级降级判断。

两个都保留：**批量入口是单个入口的循环 + 聚合**，没有第二份验证逻辑。

## 并发度恒为 1（设计 §7 B5-D6）

不是"暂时先串行"：并发展开会让 `poc_attempts` 的写入出现竞态（设计 §8 待定项 12），
而 2 vCPU 的机器上并行跑几个容器只会让每个都更慢。串行是这个部署形态下的正确答案。

## 降级：绝不把基础设施问题升级成结论问题

沙箱不可达 ⇒ 该 Finding `skipped`（不是 `rejected`，更不是"没有漏洞"）；
环境部署失败 ⇒ `ENV_DEPLOY_FAILED`，仍是 `unverified`。
**只要「验证动作没做成」，静态分析的成果就原样保留**（设计 §6 的分级原则）。
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from app.core.logging import get_logger
from app.models.enums import VulnStatus
from app.sandbox.ports import ContainerSpec, ExecResult, Sandbox
from app.verify import fingerprints
from app.verify.guard import HarmlessGuard
from app.verify.probe import (
    bootstrap_command,
    build_probes,
    canonical_vuln_type,
    mission_env,
)
from app.verify.types import (
    PocAttempt,
    Probe,
    ProbePlan,
    ProbeResponse,
    SandboxConfig,
    SkipReason,
    Verdict,
    VerificationResult,
    VerifyOutcome,
    WorkspaceHandleLike,
)

logger = get_logger(__name__)

#: 沙箱不可达时的重试次数（设计 §6：`create()` 3 次重试后仍失败即判定 daemon 不可达）。
#:
#: 重试的是**整组任务**：`run_once` 没有"只重试后半段"的能力，而且真的断连时
#: 重试整组也没有额外代价 —— 重试成功的情况下那一组本来就要重跑。
SANDBOX_RETRY_ATTEMPTS = 3

#: 连续多少个 Finding 的环境部署失败，就判定为 daemon 级问题（设计 §6）。
CONSECUTIVE_FAILURE_LIMIT = 3

#: CVSS 上调增量表（B5 自带，设计 §7 B5-D11）。
#:
#: **它不是一套新的评分算法，只是一句「这条已经被证实可以利用了」的量化表达。**
#: 分级刻意粗：精确到小数点后两位的调整会给人一种"算过"的错觉，而这里的输入
#: （base score + 已验证这一事实）支撑不起那种精度。
#:
#: 设计 §5.1 还要求同步修正 `cvss_vector` 的 AV/PR 分量 —— **本实现不做**，
#: 理由见报告：重算某一两个分量而不重算整个向量，会产出一个自相矛盾的向量
#: （AV 改了 CVSS 3.1 的权重却没改），而错误向量比不变向量更误导人。
CVSS_UPLIFT: dict[str, float] = {
    "sqli": 2.3,  # 7.5 → 9.8（PRD §7.1 ⑧ 的例子）
    "cmdi": 2.8,
    "deserialization": 2.6,
    "file_upload": 2.5,
    "file_read": 1.8,
    "info_disclosure": 1.7,
    "idor": 1.5,
    "unauth_access": 1.2,
}
#: 表外类型的兜底上调节。不设 0 —— 「已验证」这件事本身就该抬高分数，
#: 而 0 会让一个确认可利用的漏洞与一个静态怀疑的漏洞看起来一样重。
DEFAULT_CVSS_UPLIFT = 1.0


class SandboxUnreachable(Exception):
    """沙箱整体不可达（SSH 断 / daemon 挂）。

    **刻意不继承 `AppError` 也不向外抛** —— 它是本模块内部的信号，用来把
    "这一条验证不了"与"整个阶段该跳过"分开。设计 §6 要求的是**阶段标 skipped
    且后续阶段继续**，所以它必须在下游被消费掉，而不是穿透到 B3。
    """


class _EnvDeployFailed(Exception):
    """最小化环境没起来（靶场进程崩了 / 端口不监听）。**只影响这一个 Finding。**"""


ProgressCallback = Callable[[VerificationResult], Awaitable[None]]


# ---------------------------------------------------------------------------
# 门面
# ---------------------------------------------------------------------------


class PocVerifier:
    """无害化验证的门面（B5 设计 §3.1）。**无状态**，可反复构造。"""

    def __init__(
        self,
        sandbox: Sandbox,
        cfg: SandboxConfig | None = None,
        *,
        guard: HarmlessGuard | None = None,
    ) -> None:
        self.sandbox = sandbox
        self.cfg = cfg or SandboxConfig.from_settings()
        self.guard = guard or HarmlessGuard(max_probes=self.cfg.max_probes_per_vuln)

    # ------------------------------------------------------------------
    # 单 Finding
    # ------------------------------------------------------------------

    async def verify_finding(
        self,
        finding: Any,
        handle: WorkspaceHandleLike,
        *,
        on_progress: ProgressCallback | None = None,
    ) -> VerificationResult:
        """验证单个 Finding。**任何单点失败都就地降级，不向外抛。**"""
        started = time.monotonic()
        vuln_id = _vuln_id(finding)
        cvss_before = float(getattr(finding, "cvss_score", 0.0) or 0.0)

        # `handle.src_root` 是控制面上的源码根 —— 路由反查读的就是它。
        # 拿不到就传 None，探针退回模板的固定路由（**不抛异常**：
        # 绑定是增益，不是前置条件）。
        src_root = getattr(handle, "src_root", None)
        plan = build_probes(
            finding,
            vuln_id=vuln_id,
            max_probes=self.cfg.max_probes_per_vuln,
            src_root=src_root,
        )
        logger.info(
            "开始验证漏洞 %s（%s）：计划 %d 条探针，裁剪 %d 条",
            vuln_id,
            getattr(finding, "vuln_type", "?"),
            len(plan.probes),
            len(plan.skipped),
        )

        result = await self._run_plan(finding, handle, plan=plan, cvss_before=cvss_before)
        result.elapsed_ms = int((time.monotonic() - started) * 1000)

        if on_progress is not None:
            # 回调失败**不影响结论**：进度条是表达层，而结论是可复现的证据层。
            try:
                await on_progress(result)
            except Exception:  # noqa: BLE001 - 进度广播的任何异常都不该改变验证结论
                logger.warning("验证进度回调失败（已忽略，不影响结论）", exc_info=True)
        return result

    # ------------------------------------------------------------------
    # 批量
    # ------------------------------------------------------------------

    async def verify_findings(
        self,
        findings: Sequence[Any],
        ctx: Any = None,
        on_progress: ProgressCallback | None = None,
        *,
        handle: WorkspaceHandleLike,
    ) -> VerifyOutcome:
        """串行验证一批 Finding 并聚合（设计 §3.1）。

        `handle` 是 B1 的工作区句柄（**必须显式传**）：设计 §3.1 的签名里它藏在
        `ctx` 后面，但 B3 已落地的 `AssessmentContext` 里并没有工作区句柄 ——
        把它显式化成参数，比让 B5 去猜 ctx 的字段更不容易错位。
        """
        started = time.monotonic()
        outcome = VerifyOutcome()
        consecutive_env_failures = 0

        for finding in findings:
            result = await self.verify_finding(finding, handle, on_progress=on_progress)
            outcome.results.append(result)
            outcome.probe_count += len(result.attempts)
            outcome.executed_count += result.executed_probe_count

            # 两套口径分别累计：`verdict` 回答「验证动作做成了没有」（阶段降级用它），
            # `status` 回答「漏洞状态该落什么」（报告与前端用它）。混在一起会让
            # 「3 个未验证」有两种读法 —— 而这两种读法对应完全不同的下一步动作。
            if result.verdict is Verdict.VERIFIED:
                outcome.verified_count += 1
            elif result.verdict is Verdict.SKIPPED:
                outcome.skipped_count += 1
            else:
                outcome.unverified_count += 1

            if result.status is VulnStatus.REJECTED:
                outcome.rejected_count += 1
            elif result.status is VulnStatus.POTENTIAL:
                outcome.potential_count += 1

            if result.skip_reason is SkipReason.SANDBOX_UNREACHABLE:
                # 设计 §4.1 硬规则 3：沙箱不可达是**阶段级事件**，不是单条的不幸。
                # 立即停止剩余 Finding，把 sandbox_reachable=False 交回 B3。
                outcome.sandbox_reachable = False
                remaining = len(findings) - len(outcome.results)
                if remaining:
                    logger.warning(
                        "沙箱不可达，跳过剩余 %d 个漏洞的验证（阶段将标 skipped，静态成果保留）",
                        remaining,
                    )
                break

            env_failed = result.unverified_reason is not None and "ENV_DEPLOY_FAILED" in (
                result.unverified_reason or ""
            )
            consecutive_env_failures = consecutive_env_failures + 1 if env_failed else 0
            if consecutive_env_failures >= CONSECUTIVE_FAILURE_LIMIT:
                # 设计 §6：连续 3 个部署失败视为 daemon 级问题，升级为全局跳过。
                # 「靶场恰好坏了三次」与「镜像/网络坏了」在这里被有意归为后者 ——
                # 前者的代价是多跳过一个 Finding，后者的代价是烧完整个阶段超时。
                logger.warning(
                    "连续 %d 个漏洞的环境部署失败，判定为沙箱级问题，停止剩余验证",
                    consecutive_env_failures,
                )
                outcome.sandbox_reachable = False
                break

        outcome.elapsed_ms = int((time.monotonic() - started) * 1000)
        return outcome

    # ------------------------------------------------------------------
    # 内部：一个 Finding 的完整闭环
    # ------------------------------------------------------------------

    async def _run_plan(
        self,
        finding: Any,
        handle: WorkspaceHandleLike,
        *,
        plan: ProbePlan,
        cvss_before: float,
    ) -> VerificationResult:
        vuln_id = _vuln_id(finding)
        canon = canonical_vuln_type(str(getattr(finding, "vuln_type", "")))
        attempts: list[PocAttempt] = []

        if not plan.probes:
            quota_only = bool(plan.skipped) and all(
                s.reason_code.value == "PROBE_QUOTA_EXCEEDED" for s in plan.skipped
            )
            reason = plan.skipped[0].reason if plan.skipped else "无可用探针"
            return VerificationResult(
                vuln_id=vuln_id,
                # 探针在构造期就被额度吃光 ⇒ 验证动作根本没发生 ⇒ skipped。
                # 与「跑过了但没确认」必须分开，否则报告里分不清
                # 「我们没测」和「我们测了，没测出来」。
                verdict=Verdict.SKIPPED if quota_only else Verdict.UNVERIFIED,
                status=VulnStatus.POTENTIAL,
                cvss_before=cvss_before,
                cvss_after=cvss_before,
                unverified_reason=reason,
                skip_reason=SkipReason.PROBE_QUOTA_EXCEEDED if quota_only else None,
                skipped_probe_count=len(plan.skipped),
            )

        # ---- 闸门 ① 行为 / ② 载荷 / ③ 网络：三道都是零成本的纯文本检查 ----
        fireable: list[Probe] = []
        for index, probe in enumerate(plan.probes):
            verdict = self.guard.check(probe, probe_index=index)
            if not verdict.passed:
                attempts.append(_blocked_attempt(probe, verdict))
                continue
            network = self.guard.check_network(probe, allowed_hosts=self.cfg.allowed_hosts)
            if not network.passed:
                attempts.append(_blocked_attempt(probe, network))
                continue
            fireable.append(probe)
        blocked_count = len(plan.probes) - len(fireable)

        if not fireable:
            # 全部被闸门拦下 —— 按设计 §4.1 表：判 `potential`，**不是** rejected。
            # 闸门拦的是"这次探测不合规"，与"这个漏洞不存在"无关。
            reasons = {a.reason_code.value for a in attempts if a.reason_code}
            return VerificationResult(
                vuln_id=vuln_id,
                verdict=Verdict.UNVERIFIED,
                status=VulnStatus.POTENTIAL,
                attempts=attempts,
                cvss_before=cvss_before,
                cvss_after=cvss_before,
                unverified_reason=(
                    "全部探针在无害化闸门处被拒（" + "、".join(sorted(reasons)) + "），"
                    "未向目标发出任何请求"
                ),
                skipped_probe_count=len(plan.skipped) + len(plan.probes),
            )

        # ---- 执行：一次容器跑完本 Finding 的全部探针 ----
        try:
            exec_result = await self._run_container(handle, fireable)
            bootstrap, evidence = fingerprints.parse_mission_output(exec_result.stdout)
            if bootstrap is None or not bootstrap.get("ready"):
                raise _EnvDeployFailed(str((bootstrap or {}).get("error") or "靶场未就绪"))
        except SandboxUnreachable:
            # 不抛给调用方 —— 由 VerifyOutcome.sandbox_reachable 交给 B3 决定阶段降级
            return VerificationResult(
                vuln_id=vuln_id,
                verdict=Verdict.SKIPPED,
                status=VulnStatus.POTENTIAL,
                attempts=attempts,
                cvss_before=cvss_before,
                cvss_after=cvss_before,
                unverified_reason="沙箱不可达，本漏洞未能验证（阶段将标 skipped，静态结论保留）",
                skip_reason=SkipReason.SANDBOX_UNREACHABLE,
                skipped_probe_count=len(plan.skipped) + len(fireable),
            )
        except _EnvDeployFailed as exc:
            return VerificationResult(
                vuln_id=vuln_id,
                verdict=Verdict.UNVERIFIED,
                status=VulnStatus.POTENTIAL,
                attempts=attempts,
                cvss_before=cvss_before,
                cvss_after=cvss_before,
                unverified_reason=(
                    f"ENV_DEPLOY_FAILED：最小化环境未就绪（{exc}）。"
                    f"依赖已预置进镜像，运行期不安装依赖 —— 缺依赖即镜像问题"
                ),
                skipped_probe_count=len(plan.skipped) + len(fireable),
            )

        # ---- 闸门 ④ 特征：判定 ----
        matched: tuple[Probe, ProbeResponse] | None = None
        executed = 0
        negatives: list[Probe] = []
        inconclusive = 0
        for probe in fireable:
            response = fingerprints.responses_to_probe_response(probe, evidence.get(probe.probe_id))
            if response.executed:
                executed += 1
            match = fingerprints.evaluate(probe, response)
            attempts.append(_attempt(probe, response, match))
            if match.matched:
                if matched is None:
                    matched = (probe, response)
                continue
            negative = fingerprints.can_conclude_absence(probe, response, match)
            if negative.conclusive:
                negatives.append(probe)
            else:
                # 没有否证力的探针**不参与证伪表决**（既不算"同意证伪"，也不算
                # "反对证伪"）：它们既没有对照组也不读固定内容，没命中时纯粹是
                # "没看到痕迹"。把它们当成反对票，会让 `rejected` 在整个系统里
                # 几乎不可达；当成赞成票，又会让一次没覆盖到注入点的探测有权否定
                # 一条静态发现。两种都错，所以它们只被计数、不进表决。
                inconclusive += 1

        # 未执行的探针三种来源都要算进来：构造期超额裁剪的（plan.skipped）、
        # 闸门拦下的（blocked）、以及发出去了但容器没回证据的（fireable - executed）。
        # 少算任何一类，报告里的覆盖率都会偏高 —— 而偏高的覆盖率是最危险的一种谎。
        skipped_total = len(plan.skipped) + blocked_count + len(fireable) - executed
        if matched is not None and not matched[0].bound_to_finding:
            # 命中了，但**打在模板的固定路由上，不是这条 finding 自己的端点**。
            #
            # 这条证据是真的，但它证明的是「该类漏洞在本目标上存在」，
            # 不是「你看到的那一行被跑通了」。靶场实测：15 条 finding 里
            # 有 10 条的"验证"发生在别的端点上（`config.py:26` 的硬编码密钥
            # 靠读 `/.env` "通过"了）。把它们记成 `verified`，报告里就会
            # 出现一句读起来像"这行代码被证明有问题"、实际不是的话。
            #
            # 所以落 `potential`：**静态结论不动**（那条 finding 仍然成立），
            # 只是动态证据不足以支撑"逐点确认"。这是"没测到这一条"，
            # 与 `rejected` 的"测了、不存在"是两件事。
            probe, _ = matched
            return VerificationResult(
                vuln_id=vuln_id,
                verdict=Verdict.UNVERIFIED,
                status=VulnStatus.POTENTIAL,
                matched_probe_id=probe.probe_id,
                attempts=attempts,
                cvss_before=cvss_before,
                cvss_after=cvss_before,
                unverified_reason=(
                    "动态探针命中了，但打在**该类漏洞的标准形态路由**上"
                    f"（{probe.method} {probe.url_path}），不是本条 finding 自己的端点"
                    "—— 未能从源码反查出本条的端点（该行不在任何路由处理函数内，"
                    "或污点来源读不出参数名）。该命中证明「这一类漏洞在本目标上存在」，"
                    "不足以证明「本行所在的端点已被打通」，故维持 potential"
                ),
                executed_probe_count=executed,
                skipped_probe_count=skipped_total,
            )

        if matched is not None:
            probe, response = matched
            delta = CVSS_UPLIFT.get(canon, DEFAULT_CVSS_UPLIFT)
            return VerificationResult(
                vuln_id=vuln_id,
                verdict=Verdict.VERIFIED,
                status=VulnStatus.VERIFIED,
                matched_probe_id=probe.probe_id,
                attempts=attempts,
                cvss_before=cvss_before,
                cvss_after=min(10.0, round(cvss_before + delta, 1)),
                unverified_reason=None,
                executed_probe_count=executed,
                skipped_probe_count=skipped_total,
            )

        # 未命中：rejected 还是 potential？—— **默认 potential，理由写在这里**
        #
        # `rejected` 意味着「静态分析误报了」—— 这是本系统能下的**最重的结论**，
        # 所以入口只有一个：至少要有一条**具备否证力**的探针（对照组稳定 / 读的是
        # 本来就存在的固定内容 / 访问被明确拒绝）给出否定结论；这样的探针一条都没有，
        # 就永远只说 potential。设计 §7 B5-D3 的取舍：宁可多出 potential 让人复核，
        # 也不制造假阴性 ——「没验证出来」不等于「不存在」。
        rejected = bool(negatives)
        if rejected:
            return VerificationResult(
                vuln_id=vuln_id,
                verdict=Verdict.UNVERIFIED,
                status=VulnStatus.REJECTED,
                attempts=attempts,
                cvss_before=cvss_before,
                cvss_after=cvss_before,
                unverified_reason=(
                    f"动态验证未复现：{len(negatives)} 条有否证力的探针均给出否定结论"
                    f"（对照组稳定 / 固定内容读不到 / 访问被拒绝），静态判断被证伪"
                    f"（原 CVSS 保持不变）"
                    + (
                        f"；另有 {inconclusive} 条探针未命中但无否证力，未参与判定"
                        if inconclusive
                        else ""
                    )
                ),
                executed_probe_count=executed,
                skipped_probe_count=skipped_total,
            )

        return VerificationResult(
            vuln_id=vuln_id,
            verdict=Verdict.UNVERIFIED,
            status=VulnStatus.POTENTIAL,
            attempts=attempts,
            cvss_before=cvss_before,
            cvss_after=cvss_before,
            unverified_reason=(
                f"探针已执行（{executed} 条）但未观察到命中特征；"
                f"无害化探针只读，存在覆盖盲区，故维持 potential 而非否定"
                + (f"（{inconclusive} 条未命中且无否证力）" if inconclusive else "")
                + (f"；另有 {skipped_total} 条探针未执行" if skipped_total else "")
            ),
            executed_probe_count=executed,
            skipped_probe_count=skipped_total,
        )

    # ------------------------------------------------------------------
    # 内部：沙箱调用
    # ------------------------------------------------------------------

    async def _run_container(
        self, handle: WorkspaceHandleLike, probes: Sequence[Probe]
    ) -> ExecResult:
        """把一组探针投进沙箱跑一次。**重试耗尽 → `SandboxUnreachable`。**"""
        spec = self._build_spec(handle, probes)
        last_exc: Exception | None = None
        for attempt in range(1, SANDBOX_RETRY_ATTEMPTS + 1):
            try:
                return await self.sandbox.run_once(spec)
            except Exception as exc:  # noqa: BLE001 - 契约把 infra 故障定义为异常
                last_exc = exc
                logger.warning(
                    "沙箱执行失败（第 %d/%d 次尝试）：%s: %s",
                    attempt,
                    SANDBOX_RETRY_ATTEMPTS,
                    type(exc).__name__,
                    exc,
                )
                if attempt < SANDBOX_RETRY_ATTEMPTS:
                    # 退避一下再重试：SSH 瞬断的恢复通常就在几百毫秒内，
                    # 立刻重试往往撞在同一时刻的同一个故障上。
                    await asyncio.sleep(0.5 * attempt)
        raise SandboxUnreachable(str(last_exc))

    def _build_spec(self, handle: WorkspaceHandleLike, probes: Sequence[Probe]) -> ContainerSpec:
        """组装 `ContainerSpec`（契约 1）。

        隔离参数**全部走安全侧且不做成配置项**：无出网、只读根、源码只读挂载。
        把它们做成可配置，就等于给了「某次运行放宽了隔离」一个合法的表达方式，
        而本系统没有任何一种场景需要那个。
        """
        return ContainerSpec(
            image=self.cfg.preset_image,
            command=bootstrap_command(),
            # B1 给的**数据面宿主路径**：bind mount 由远端 daemon 解析（契约 1）
            source_mount=handle.mount_host_path,
            workdir=self.cfg.workdir,
            env=mission_env(probes),
            cpu_limit=self.cfg.cpu_limit,
            memory_limit_mb=self.cfg.memory_limit_mb,
            timeout_seconds=self._group_budget(probes),
            network_disabled=True,
            read_only_root=True,
        )

    def _group_budget(self, probes: Sequence[Probe]) -> int:
        """整组容器的时长预算 = 部署 + Σ(每条请求的超时) + 余量。

        按**每条请求**而不是每条探针累加：布尔盲注与时间盲注各要发 2–3 条请求，
        按探针数算会把它们在最坏情况下的预算算少一半 —— 而"预算算少了"的表现是
        「好好的探针被容器超时杀掉」，那是要花很久才能定位的一类问题。
        """
        from app.verify.probe import render_requests  # 局部导入：避免模块级循环依赖

        request_budget = sum(len(render_requests(p)) * p.timeout_s for p in probes)
        natural = self.cfg.port_ready_timeout_s + request_budget + 15
        return max(30, min(natural, self.cfg.container_timeout_s))


# ---------------------------------------------------------------------------
# 契约 4 的函数式入口
# ---------------------------------------------------------------------------


async def verify_finding(
    finding: Any,
    sandbox: Sandbox,
    handle: WorkspaceHandleLike,
    *,
    cfg: SandboxConfig | None = None,
    on_progress: ProgressCallback | None = None,
) -> VerificationResult:
    """契约 4 的入口：`verify.verify_finding(finding, sandbox, handle)`。

    函数式包装只是为了对齐契约里的调用形状；实现只有 `PocVerifier` 一份 ——
    两套验证逻辑迟早会漂移出两个结论，那正是契约存在的意义所在。
    """
    verifier = PocVerifier(sandbox=sandbox, cfg=cfg)
    return await verifier.verify_finding(finding, handle, on_progress=on_progress)


async def verify_findings(
    findings: Sequence[Any],
    sandbox: Sandbox,
    handle: WorkspaceHandleLike,
    ctx: Any = None,
    on_progress: ProgressCallback | None = None,
    *,
    cfg: SandboxConfig | None = None,
) -> VerifyOutcome:
    """批量入口（设计 §3.1 的 `verify_findings`），供 B3 的 `PocVerifyAgent` 调用。"""
    verifier = PocVerifier(sandbox=sandbox, cfg=cfg)
    return await verifier.verify_findings(findings, ctx, on_progress, handle=handle)


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------


def _vuln_id(finding: Any) -> int:
    """取漏洞主键。

    **两种来源都要能吃**：B4 的 `Finding` 没有 `vuln_id`（`code` 由 B3 生成），
    而 B3 上下文里的 `FindingRef` 有 `vuln_id` 却没有污点路径。取不到就退 0 ——
    `poc_attempts.vulnerability_id` 是外键，落库前 B3 必然已经知道真实 id。
    """
    for attr in ("vuln_id", "id", "vulnerability_id"):
        value = getattr(finding, attr, None)
        if isinstance(value, int):
            return value
    return 0


def _blocked_attempt(probe: Probe, verdict: Any) -> PocAttempt:
    """被闸门拦下的探针也要留一条记录（设计 §4.1 硬规则 1）。"""
    return PocAttempt(
        vulnerability_id=probe.vuln_id,
        probe_id=probe.probe_id,
        payload=probe.payload,
        technique=probe.technique.value,
        request_raw="",  # 没有发出任何请求 —— 这正是这条记录的意义
        response_raw="",
        expected_pattern=probe.expected_pattern,
        matched=False,
        elapsed_ms=0,
        http_status=None,
        harmless_guard_passed=False,
        failure_reason=verdict.reason,
        failed_gate=verdict.failed_gate,
        reason_code=verdict.reason_code,
    )


def _attempt(probe: Probe, response: ProbeResponse, match: Any) -> PocAttempt:
    """把一次真实的探测落成证据记录（↔ `poc_attempts`）。"""
    return PocAttempt(
        vulnerability_id=probe.vuln_id,
        probe_id=probe.probe_id,
        payload=probe.payload,
        technique=probe.technique.value,
        request_raw=response.request_raw,
        response_raw=response.response_raw,
        expected_pattern=probe.expected_pattern,
        matched=match.matched,
        elapsed_ms=response.elapsed_ms,
        http_status=response.http_status,
        # 走到这里的探针都过了闸门 —— 这是"它被允许发出"的记录
        harmless_guard_passed=True,
        # 命中时不写失败原因；未命中时写清「为什么没命中」——
        # 这一列是人工复核唯一的抓手，`matched=False` 加一句原因，
        # 比十个布尔值都有用。
        failure_reason=None if match.matched else _attempt_reason(response, match),
        failed_gate=None,  # 过了闸门的探针没有失败闸门
        reason_code=None,
    )


def _attempt_reason(response: ProbeResponse, match: Any) -> str:
    """未命中时的中文原因（进 `poc_attempts.failure_reason`）。"""
    if not response.executed:
        return "探针未在容器中执行完毕（容器超时或被杀），本次探测未取得结论"
    if response.error:
        return f"容器内请求未成功：{response.error}"
    return match.reason


def cvss_after_verification(vuln_type: str, cvss_before: float) -> float:
    """验证通过后的评分（设计 §5.1）。**只有 verified 才调用它。**"""
    delta = CVSS_UPLIFT.get(canonical_vuln_type(vuln_type), DEFAULT_CVSS_UPLIFT)
    return min(10.0, round(float(cvss_before or 0.0) + delta, 1))


def default_config(**overrides: Any) -> SandboxConfig:
    """从全局配置推导 B5 的沙箱参数（见 `SandboxConfig` 的注释）。

    `SandboxConfig.from_settings()` 是唯一读全局配置的地方 —— 验证逻辑本身不碰
    `settings`，这样测试里换一份配置就能换掉镜像/超时，不需要改环境变量。
    """
    return SandboxConfig.from_settings(**overrides)
