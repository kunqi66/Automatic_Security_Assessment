"""端到端跑一遍：建项目 → 传源码 → 起评估 → 盯五个阶段。

    uv run python tools/e2e.py ecommerce
    uv run python tools/e2e.py usercenter

**只打 API，不 import app** —— 这样它验证的就是**真正部署起来的那条路径**，
而不是某个内部函数。「跑得通」如果只证明"函数能被调用"，那它什么都没证明。

放在 `tools/` 而不是后端根目录：它不是产品代码，不会被 `app/` 引用。
之前它以 `_` 前缀躺在 `backend/` 根下，与「后端根目录只有包和配置」这个约定冲突，
而且 `_` 前缀只表达了"临时"，没表达"这是什么"。
"""

from __future__ import annotations

import io
import pathlib
import sys
import time
import zipfile

import httpx

API = "http://127.0.0.1:8010/api/v1"

#: 锚在 `__file__` 而**不是 cwd** —— 脚本移到 `tools/` 之后，
#: 原来那种 `pathlib.Path("../ranges")` 的相对写法会静默指向
#: `backend/ranges`（不存在），然后报"目录是空的"而不是"路径错了"。
#: 布局依赖写死成常量并立刻断言，挪错位置时**在导入期就炸**。
_LAYOUT = "tools/ 的上一级是 backend/，再上一级是仓库根（含 ranges/ 与 .asa/）"
ROOT = pathlib.Path(__file__).resolve().parents[2]
RANGES = ROOT / "ranges"
DEMO = RANGES / (sys.argv[1] if len(sys.argv) > 1 else "ecommerce")
PW_FILE = ROOT / ".asa" / "engineer-password.txt"

if not RANGES.is_dir():  # pragma: no cover - 只在挪错位置时触发
    raise SystemExit(f"找不到 {RANGES}（{_LAYOUT}）")

#: 用**安全工程师**而不是 admin：需求 2.5.2 把 `assessment:create` 给了
#: 安全工程师，admin 只有沙箱/LLM/审计三项 —— 拿 admin 建档会 403，
#: 而那个 403 是**正确行为**，不是 bug（`api/deps.py::ROLE_PERMISSIONS`）。
USERNAME = "engineer"


def make_zip() -> bytes:
    """把靶场打成 zip。

    顶层目录名刻意不放进归档：解包器要处理的是「一堆文件」，
    而不是「一个目录」—— 多一层前缀会让 manifest 的相对路径全都带上它。
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(DEMO.rglob("*")):
            if f.is_file():
                zf.write(f, f.relative_to(DEMO).as_posix())
    return buf.getvalue()


def main() -> int:
    if not PW_FILE.is_file():
        print(f"缺 {PW_FILE} —— 先跑 app/scripts/create_user.py")
        return 1

    with httpx.Client(base_url=API, timeout=60) as c:
        # ---- 1. 登录 ----
        r = c.post(
            "/auth/login",
            json={
                "username": USERNAME,
                # 口令只从文件读进内存，**不打印**
                "password": PW_FILE.read_text(encoding="utf-8").strip(),
            },
        )
        if r.status_code != 200:
            print(f"登录失败 {r.status_code}: {r.text[:300]}")
            return 1
        token = r.json().get("access_token") or r.json().get("data", {}).get("access_token")
        c.headers["Authorization"] = f"Bearer {token}"
        print(f"[1/5] 登录成功，JWT 长度 {len(token)}")

        # ---- 2. 建项目 ----
        r = c.post(
            "/projects",
            json={
                "name": f"{DEMO.name} {time.strftime('%H%M%S')}",
                "description": f"靶场 {DEMO.name}（PRD §10）",
                "source_type": "upload",
            },
        )
        if r.status_code not in (200, 201):
            print(f"建项目失败 {r.status_code}: {r.text[:400]}")
            return 1
        proj = r.json()
        pid = proj.get("id") or proj.get("data", {}).get("id")
        print(f"[2/5] 项目 id={pid}")

        # ---- 3. 传源码 ----
        blob = make_zip()
        r = c.post(f"/projects/{pid}/upload", files={"file": ("demo.zip", blob, "application/zip")})
        if r.status_code not in (200, 201):
            print(f"上传失败 {r.status_code}: {r.text[:400]}")
            return 1
        print(f"[3/5] 上传 {len(blob)} 字节，返回：{str(r.json())[:200]}")

        # ---- 4. 起评估 ----
        r = c.post(f"/projects/{pid}/assessments")
        if r.status_code not in (200, 201, 202):
            print(f"起评估失败 {r.status_code}: {r.text[:400]}")
            return 1
        body = r.json()
        aid = body.get("id") or body.get("data", {}).get("id")
        state = body.get("status") or body.get("data", {}).get("status")
        print(f"[4/5] 评估 id={aid}，状态={state}")

        # ---- 5. 盯阶段 ----
        print("[5/5] 盯阶段（最多 8 分钟）……")
        deadline = time.monotonic() + 480
        seen: list[str] = []
        while time.monotonic() < deadline:
            time.sleep(4)
            r = c.get(f"/assessments/{aid}")
            if r.status_code != 200:
                print(f"  查询失败 {r.status_code}: {r.text[:200]}")
                continue
            d = r.json()
            st = d.get("status")
            stages = d.get("stages") or []
            line = " ".join(f"{s.get('stage')}={s.get('status')}" for s in stages)
            if line != (seen[-1] if seen else None):
                print(f"  [{time.strftime('%H:%M:%S')}] 总状态={st} | {line}")
                seen.append(line)
            if st in ("completed", "failed", "stopped"):
                print(f"\n最终状态：{st}")
                print(f"  失败原因：{d.get('error_message') or '—'}")
                break
        else:
            print("\n超时：8 分钟内没跑完")
            return 1

        # ---- 收尾：看看真出了什么 ----
        r = c.get(f"/assessments/{aid}/vulnerabilities")
        vulns: list[dict] = []
        if r.status_code == 200:
            body = r.json()
            vulns = body if isinstance(body, list) else body.get("items") or body.get("data") or []
        by_status: dict[str, int] = {}
        print(f"\n漏洞 {len(vulns)} 条：")
        for v in vulns:
            status = str(v.get("status"))
            by_status[status] = by_status.get(status, 0) + 1
            print(
                f"   [{status:<9}] {str(v.get('vuln_type')):<20} "
                f"{v.get('file_path')}:{v.get('line_start')}  "
                f"严重度={v.get('severity')} 置信={v.get('confidence')}"
            )
        print(f"\n   状态分布：{by_status}")

        r = c.get(f"/assessments/{aid}/chains")
        chains: list[dict] = []
        if r.status_code == 200:
            body = r.json()
            chains = body if isinstance(body, list) else body.get("items") or body.get("data") or []
        # ⚠️ 这个端点返回的是**链上的节点**，不是链本身。
        # 早先这里写「利用链 {len} 条」，跑出来一个 28 —— 而 `attack_chains`
        # 表里其实只有 5 行。把节点数当链数会让人以为"串出了 28 条攻击路径"，
        # 是个只会往大了错的标签。链数要查表。
        print(f"\n利用链节点 {len(chains)} 个（链数见 attack_chains 表）：")
        for ch in chains:
            print(
                f"   - [{ch.get('rule_id') or '?'}] {ch.get('label') or ch.get('title')}"
                f"  严重度={ch.get('severity')}"
                f" 推演={ch.get('outcome_inferred')}"
            )
        return 0


if __name__ == "__main__":
    sys.exit(main())
