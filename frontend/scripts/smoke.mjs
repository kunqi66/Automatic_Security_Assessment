/**
 * 前端冒烟测试：用 CDP 驱动无头浏览器走一遍登录后的四个页面，
 * 抓每页的实际可见文本与控制台异常，确认「没有白屏」。
 *
 * 为什么需要它：类型检查通过、打包成功，都**不能**证明页面渲染得出来。
 * 一个运行期异常（比如图表配置写错）就会让整页白屏，而这只在真实浏览器里才暴露。
 *
 * 用法：
 *   npm run smoke                    # 需先 npm run dev
 *   npm run smoke -- http://localhost:5173
 *   CHROME_PATH=/path/to/chrome npm run smoke
 */
import { spawn } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'

const APP = process.argv[2] ?? 'http://localhost:5173'
const PORT = 9223

// 登录信息与 `backend/tools/e2e.py` 取同一处，口令只读进内存、**不打印**。
const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..', '..')
const PW_FILE = join(ROOT, '.asa', 'engineer-password.txt')
//: admin 只在第 6 项用得上：`/settings` 的读写都要 `sandbox:manage`，engineer 没有。
const ADMIN_PW_FILE = join(ROOT, '.asa', 'admin-password.txt')
const USERNAME = 'engineer'

const CANDIDATES = [
  process.env.CHROME_PATH,
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
].filter(Boolean)

const PAGES = [
  ['概览大盘', '/'],
  ['评估工作台', '/workbench?assessmentId=101'],
  ['报告中心', '/reports'],
  ['沙箱与环境配置', '/settings'],
]

const browser = CANDIDATES.find((p) => existsSync(p))
if (!browser) {
  console.error('未找到浏览器。请用 CHROME_PATH 环境变量指定 Chrome/Edge 可执行文件路径。')
  process.exit(1)
}

// 先确认 dev server 在跑，否则报错会更难懂
try {
  await fetch(APP, { signal: AbortSignal.timeout(3000) })
} catch {
  console.error(`连不上 ${APP} —— 请先在另一个终端运行 npm run dev`)
  process.exit(1)
}

const proc = spawn(
  browser,
  [
    '--headless=new',
    '--disable-gpu',
    '--no-sandbox',
    '--no-first-run',
    '--disable-extensions',
    `--remote-debugging-port=${PORT}`,
    `--user-data-dir=${join(tmpdir(), 'asa-smoke-profile')}`,
    'about:blank',
  ],
  { stdio: 'ignore' },
)

const cleanup = () => {
  try {
    proc.kill()
  } catch {
    /* 已退出 */
  }
}
process.on('exit', cleanup)

// --- 连接 CDP ---------------------------------------------------------------

let wsUrl = null
for (let i = 0; i < 60 && !wsUrl; i++) {
  try {
    const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json()
    wsUrl = list.find((t) => t.type === 'page')?.webSocketDebuggerUrl ?? null
  } catch {
    /* 浏览器还没起来 */
  }
  if (!wsUrl) await sleep(250)
}
if (!wsUrl) {
  console.error('无法连接浏览器 DevTools')
  process.exit(1)
}

const ws = new WebSocket(wsUrl)
await new Promise((resolve, reject) => {
  ws.onopen = resolve
  ws.onerror = reject
})

let seq = 0
const pending = new Map()
let exceptions = []
let consoleErrors = []

ws.onmessage = (ev) => {
  const msg = JSON.parse(ev.data)
  if (msg.id && pending.has(msg.id)) {
    pending.get(msg.id)(msg)
    pending.delete(msg.id)
    return
  }
  if (msg.method === 'Runtime.exceptionThrown') {
    const d = msg.params.exceptionDetails
    exceptions.push(d.exception?.description ?? d.text)
  }
  if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
    consoleErrors.push(msg.params.args.map((a) => a.value ?? a.description ?? '').join(' '))
  }
}

const send = (method, params = {}) =>
  new Promise((resolve) => {
    const id = ++seq
    pending.set(id, resolve)
    ws.send(JSON.stringify({ id, method, params }))
  })

const evaluate = async (expression) => {
  const r = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })
  return r.result?.result?.value
}

await send('Runtime.enable')
await send('Page.enable')

// --- 登录 → 逐页巡检 --------------------------------------------------------
// **必须真登录。** 原先这里直接塞了一个 `'mock-jwt-token'`，注释写的是
// 「mock 模式下任意非空 token 都能通过 /auth/me」—— 那话在当时是对的，
// 但 `VITE_USE_MOCK` 一旦关掉（现在默认关），伪造的 token 会被真实后端 401，
// 应用随即退回登录页，于是**四个页面全部"白屏"**，而这是个假警报：
// 页面没坏，是巡检自己没进去。所以这里改成向真实后端换一个真 token。
async function obtainToken() {
  if (!existsSync(PW_FILE)) {
    console.log(`⚠️  未找到 ${PW_FILE}，退回 mock token（仅 VITE_USE_MOCK=true 时有效）`)
    return 'mock-jwt-token'
  }
  const res = await fetch(`${APP}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: USERNAME, password: readFileSync(PW_FILE, 'utf8').trim() }),
    signal: AbortSignal.timeout(15_000),
  })
  if (!res.ok) {
    console.error(`登录失败 HTTP ${res.status} —— 检查后端是否在跑、以及 ${PW_FILE}`)
    process.exit(1)
  }
  // 登录成功直接返回资源 JSON（`{access_token, token_type, user}`）——
  // 本项目**刻意不用** `{code, message, data}` 信封（见 `schemas/common.py`）。
  // 这里两种形状都认只是防御性写法，与 `e2e.py` 的取法保持一致。
  // 只打印长度，不打印内容。
  const body = await res.json()
  const token = body?.access_token ?? body?.data?.access_token
  if (!token) {
    console.error('登录返回 200 但没有 access_token —— 响应结构变了')
    process.exit(1)
  }
  console.log(`已登录 ${USERNAME}（JWT 长度 ${token.length}）`)
  return token
}

await send('Page.navigate', { url: `${APP}/login` })
await sleep(2500)
const token = await obtainToken()
await evaluate(`localStorage.setItem('asa_token', ${JSON.stringify(token)})`)

console.log(`\n目标：${APP}\n`)
console.log('页面'.padEnd(20) + '可见字符'.padEnd(12) + '结果')
console.log('-'.repeat(64))

let failed = false
for (const [name, path] of PAGES) {
  exceptions = []
  consoleErrors = []
  await send('Page.navigate', { url: `${APP}${path}` })
  await sleep(4500)

  const text = (await evaluate('document.body.innerText')) ?? ''
  const chars = text.replace(/\s/g, '').length
  const rootChildren = await evaluate(`document.getElementById('root')?.children.length ?? 0`)

  const blank = chars < 40 || rootChildren === 0
  const bad = blank || exceptions.length > 0
  if (bad) failed = true

  console.log(
    name.padEnd(18) + String(chars).padEnd(14) + (bad ? (blank ? '✗ 疑似白屏' : '✗ 有异常') : '✓'),
  )
  if (blank) console.log('    #root 子节点数 =', rootChildren)
  for (const e of exceptions) console.log('    [exception]', String(e).split('\n')[0])
  for (const e of consoleErrors) console.log('    [console.error]', String(e).slice(0, 300))
}

console.log('-'.repeat(64))

// --- 第 5 项：报告中心要能**真的打开一份报告** ------------------------------
//
// 上面那四项只证明页面没白屏，**证明不了报告打得开** —— 而这正是踩过的坑：
// 报告中心的预览区曾经渲染的是 `sampleReport.tsx` 里的固定示例（靶场一的正文），
// 于是点开靶场二的报告会看到**另一个靶场的内容**；导出也只弹一句服务端路径。
// 这两处的共同点是：列表页一切正常、页面字符数也很正常，所以四项巡检全绿。
//
// 所以这里必须**点进去**：选中第一行 → 等预览区出正文 → 断言它不是示例。
console.log('\n报告预览（点开第一行看正文是否真的加载）')
console.log('-'.repeat(64))
exceptions = []
consoleErrors = []
await send('Page.navigate', { url: `${APP}/reports` })
await sleep(4500)
const rowCount = await evaluate(`document.querySelectorAll('.ant-table-tbody tr.ant-table-row').length`)
if (rowCount === 0) {
  console.log('✗ 报告列表为空 —— 没有可打开的报告，这一项无法验证（不算通过）')
  failed = true
} else {
  await evaluate(`document.querySelector('.ant-table-tbody tr.ant-table-row')?.click()`)
  await sleep(5000)
  // 取预览区正文：Markdown 模式渲染进 .asa-report-md；HTML 模式进 iframe。
  // 空沙箱下 iframe 内容读不出来（这正是我们想要的安全属性），所以只统计 srcdoc 长度。
  const preview = (await evaluate(`document.querySelector('.asa-report-md')?.innerText ?? ''`)) ?? ''
  const iframeLen = await evaluate(
    `[...document.querySelectorAll('iframe')].map(f=>(f.srcdoc||'').length).reduce((a,b)=>Math.max(a,b),0)`,
  )
  // 判据：正文里出现「评估报告」这类真实标题结构，且**不能**残留示例标记。
  // 注意判据用「示例」而不是某个具体靶场名 —— 具体名字会随评估对象变。
  const hasSample = preview.includes('示例')
  const ok = preview.length > 200 && !hasSample
  if (!ok) failed = true
  console.log(
    `预览正文字符数`.padEnd(18) +
      String(preview.length).padEnd(14) +
      (ok ? '✓' : hasSample ? '✗ 仍在渲染固定示例' : '✗ 正文没加载出来'),
  )
  console.log('    iframe srcdoc 长度 =', iframeLen)
  for (const e of exceptions) console.log('    [exception]', String(e).split('\n')[0])
  for (const e of consoleErrors) console.log('    [console.error]', String(e).slice(0, 300))
}

console.log('-'.repeat(64))

// --- 第 6 项：沙箱配置页要**真的能配** --------------------------------------
//
// 上面对 `/settings` 只数了可见字符 —— 而这一页在接通之前**一直是绿的**：
// 表格恒空（后端返回裸数组、前端按 `Page<T>` 读 `data.items`，永远是 undefined），
// 「配置」按钮根本不存在，字符数照样有 397。
//
// 这正是第 5 项那段注释说的同一件事：**字符数只能证明没白屏，证明不了这一页
// 能干它该干的事。** 所以这里以 admin 身份再进一次，断言那行配置真的渲染出来了、
// 且「配置」按钮在。engineer 做不到 —— 它没有 `sandbox:manage`，
// 走的是「无权限」提示那条分支。
console.log('\n沙箱配置页（以 admin 身份，engineer 没有该权限）')
console.log('-'.repeat(64))
exceptions = []
consoleErrors = []

/** 换一个真 token。取法与 `obtainToken` 一致，只是换账号，且不做 mock 回退。 */
async function loginAs(username, pwFile) {
  if (!existsSync(pwFile)) return null
  try {
    const res = await fetch(`${APP}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password: readFileSync(pwFile, 'utf8').trim() }),
      signal: AbortSignal.timeout(15_000),
    })
    if (!res.ok) return null
    return (await res.json())?.access_token ?? null
  } catch {
    return null
  }
}

const adminToken = await loginAs('admin', ADMIN_PW_FILE)
if (!adminToken) {
  console.log('✗ 拿不到 admin token —— 跳过即视为失败（这一项无法验证）')
  failed = true
} else {
  await evaluate(`localStorage.setItem('asa_token', ${JSON.stringify(adminToken)})`)
  await send('Page.navigate', { url: `${APP}/settings` })
  await sleep(5000)

  const rows = await evaluate(
    `document.querySelectorAll('.ant-table-tbody tr.ant-table-row').length`,
  )
  const rowText = (await evaluate(
    `[...document.querySelectorAll('.ant-table-tbody tr.ant-table-row')].map(r=>r.innerText.replace(/\\s+/g,' ')).join(' | ')`,
  )) ?? ''
  const hasEditBtn = await evaluate(
    `[...document.querySelectorAll('button')].some(b => b.innerText.includes('配置'))`,
  )

  // 判据三条，缺一不可：有行、行里有「默认」标记、有可点的「配置」按钮。
  // 只断言「字符数 > N」是不够的 —— 空白表格加一段说明文字也能凑够字符数。
  const ok = rows > 0 && rowText.includes('默认') && hasEditBtn === true
  if (!ok) failed = true
  console.log(
    '沙箱配置行数'.padEnd(18) + String(rows).padEnd(14) + (rows > 0 ? '✓' : '✗ 表格为空'),
  )
  console.log(
    '「配置」按钮'.padEnd(17) + (hasEditBtn ? '存在' : '缺失').padEnd(14) +
      (hasEditBtn ? '✓' : '✗ 按钮不存在，这一页只能看不能配'),
  )
  if (rowText) console.log(`   行内容：${rowText.slice(0, 160)}`)
  for (const e of exceptions) console.log('    [exception]', String(e).split('\n')[0])
  for (const e of consoleErrors) console.log('    [console.error]', String(e).slice(0, 300))
}

console.log('-'.repeat(64))
console.log(
  failed
    ? '存在失败项'
    : '四个页面全部正常渲染，报告预览加载真实正文，沙箱配置页可读可配，无控制台异常\n',
)

ws.close()
process.exit(failed ? 1 : 0)
