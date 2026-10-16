/**
 * 端到端验证：「新建评估」入口是否真的能从界面上走通。
 *
 * 跑法：先确保 隧道 / 后端 8010 / worker / Vite 5173 都在，然后
 *   node scripts/_e2e_new_assessment.mjs
 * 16 项全绿退出码 0。
 *
 * 它**会产生副作用**（建一个项目、起一次评估），所以没进 `package.json` 的脚本表，只手动跑。
 * 耗时取决于队列：worker 单消费者、顺序取任务，实测一次完整评估约 191 秒，
 * 前面若有任务在跑，本脚本会在「等 worker 取走」那一步一起等（上限 420 秒）。
 *
 * ## 两个踩过的坑，都写进了对应的代码段
 * 1. `become()` 必须**先导航到应用的源**再写 localStorage（见该函数的注释）；
 * 2. tooltip 必须用 CDP 真实鼠标移动验证，合成事件测不出来（见第 3 节的注释）。
 * 两处都是**假阴性**——报红的地方产品是好的，坏的是测试。
 */
import { spawn } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'

const APP = 'http://localhost:5173'
const API = 'http://127.0.0.1:8010'
const PORT = 9224
const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..', '..')
const ZIP = join(ROOT, '.asa', 'ecommerce.zip')

const browser = [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
].find((p) => existsSync(p))

const proc = spawn(
  browser,
  [
    '--headless=new',
    '--disable-gpu',
    '--no-sandbox',
    '--no-first-run',
    `--remote-debugging-port=${PORT}`,
    `--user-data-dir=${join(tmpdir(), 'asa-e2e-profile')}`,
    'about:blank',
  ],
  { stdio: 'ignore' },
)
process.on('exit', () => {
  try {
    proc.kill()
  } catch {
    /* 已退出 */
  }
})

let wsUrl = null
for (let i = 0; i < 60 && !wsUrl; i++) {
  try {
    const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json()
    wsUrl = list.find((t) => t.type === 'page')?.webSocketDebuggerUrl ?? null
  } catch {
    /* 还没起来 */
  }
  if (!wsUrl) await sleep(250)
}

const ws = new WebSocket(wsUrl)
await new Promise((res, rej) => {
  ws.onopen = res
  ws.onerror = rej
})

let seq = 0
const pending = new Map()
const exceptions = []
ws.onmessage = (ev) => {
  const m = JSON.parse(ev.data)
  if (m.id && pending.has(m.id)) {
    pending.get(m.id)(m)
    pending.delete(m.id)
    return
  }
  if (m.method === 'Runtime.exceptionThrown') {
    exceptions.push(m.params.exceptionDetails.exception?.description ?? m.params.exceptionDetails.text)
  }
}
const send = (method, params = {}) =>
  new Promise((resolve) => {
    const id = ++seq
    pending.set(id, resolve)
    ws.send(JSON.stringify({ id, method, params }))
  })
const evaluate = async (e) =>
  (await send('Runtime.evaluate', { expression: e, returnByValue: true, awaitPromise: true }))
    .result?.result?.value

await send('Runtime.enable')
await send('Page.enable')
await send('DOM.enable')

const results = []
const check = (name, ok, detail = '') => {
  results.push(ok)
  console.log(`${ok ? '✓' : '✗'} ${name}${detail ? '  —— ' + detail : ''}`)
}

async function login(username, pwFile) {
  const res = await fetch(`${API}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password: readFileSync(pwFile, 'utf8').trim() }),
  })
  return (await res.json()).access_token
}

/**
 * 换身份：**先落到应用自己的源上**，再写 token，最后整页导航。
 *
 * 🔴 第一步不能省。浏览器起在 `about:blank`，那是个不透明源，
 * `localStorage` 压根访问不了 —— 会在 `Runtime.evaluate` 里抛 SecurityError。
 * 而那个异常**不会**走 `Runtime.exceptionThrown`（它走 evaluate 自己的
 * `exceptionDetails`），于是被静默吞掉，表现为「token 好像设了、其实没有」。
 *
 * 症状极具误导性：应用没 token → `user` 为 null → `can()` 恒 false →
 * 工程师的「新建评估」按钮也是灰的，看起来像**权限表配错了**。
 */
async function become(token, path = '/') {
  await send('Page.navigate', { url: `${APP}/login` })
  await sleep(2000)
  const stored = await evaluate(
    `(() => { localStorage.setItem('asa_token', ${JSON.stringify(token)}); return localStorage.getItem('asa_token')?.length ?? 0 })()`,
  )
  if (!stored) throw new Error('token 没能写进 localStorage —— 检查当前页面的源')
  await send('Page.navigate', { url: `${APP}${path}` })
  await sleep(5000)
}

/** 页面自己看到的身份。用来区分「后端权限不对」和「前端没拿到身份」。 */
const whoAmI = () =>
  evaluate(
    `(() => {
       const raw = localStorage.getItem('asa_token');
       return { href: location.pathname, hasToken: !!raw, body: document.body.innerText.slice(0, 60) };
     })()`,
  )

/** 按可见文字点按钮。 */
const clickByText = (text, tag = 'button') =>
  evaluate(
    `(() => {
       const el = [...document.querySelectorAll('${tag}')].find(b => b.innerText.trim() === ${JSON.stringify(text)});
       if (!el) return false;
       el.click();
       return true;
     })()`,
  )

// ===========================================================================
console.log('\n=== 1. 工程师身份：按钮应当**可用** ===')
console.log('-'.repeat(60))

const engToken = await login('engineer', join(ROOT, '.asa', 'engineer-password.txt'))
await become(engToken, '/')
console.log('   页面看到的身份：', JSON.stringify(await whoAmI()))

const btn = await evaluate(
  `(() => {
     const b = [...document.querySelectorAll('button')].find(x => x.innerText.trim() === '新建评估');
     return b ? { found: true, disabled: b.disabled } : { found: false };
   })()`,
)
check('「新建评估」按钮存在', btn?.found === true)
check('工程师身份下按钮**可点**', btn?.disabled === false, `disabled=${btn?.disabled}`)

// ===========================================================================
console.log('\n=== 2. 走完「新项目 + 上传源码包 + 启动」 ===')
console.log('-'.repeat(60))

await clickByText('新建评估')
await sleep(1200)

const modalOpen = await evaluate(
  `!!document.querySelector('.ant-modal-content')?.innerText.includes('新建评估')`,
)
check('弹窗打开', modalOpen === true)

// 项目名
await evaluate(
  `(() => {
     const i = document.querySelector('input[placeholder="例如：订单服务"]');
     if (!i) return false;
     const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
     setter.call(i, '端到端验证 · 电商靶场');
     i.dispatchEvent(new Event('input', { bubbles: true }));
     return true;
   })()`,
)

// 直接塞文件进 antd Upload 的隐藏 input。
// DOM.setFileInputFiles 在 Chrome 里会真的派发 change 事件，rc-upload 接得住。
const doc = await send('DOM.getDocument', { depth: -1 })
const fileNode = await send('DOM.querySelector', {
  nodeId: doc.result.root.nodeId,
  selector: 'input[type=file]',
})
check('找到文件输入框', !!fileNode.result?.nodeId)
if (fileNode.result?.nodeId) {
  await send('DOM.setFileInputFiles', { files: [ZIP], nodeId: fileNode.result.nodeId })
  await sleep(800)
}
const picked = await evaluate(
  `document.querySelector('.ant-modal-content')?.innerText.includes('ecommerce.zip') === true`,
)
check('文件已被表单接收（弹窗里出现文件名）', picked === true)

const clickedOk = await clickByText('启动评估')
check('点到「启动评估」', clickedOk === true)

// 克隆/上传/启动都是同步请求，给它足够时间；成功后组件会 navigate 到工作台
let landed = null
for (let i = 0; i < 40; i++) {
  await sleep(1500)
  landed = await evaluate(`location.pathname + location.search`)
  if (landed?.includes('/workbench')) break
}
check('提交后跳到工作台', landed?.includes('/workbench') === true, landed ?? '(未跳转)')

const assessmentId = Number(new URLSearchParams((landed ?? '').split('?')[1] ?? '').get('assessmentId'))
check('URL 带上了 assessmentId', Number.isInteger(assessmentId) && assessmentId > 0, `id=${assessmentId}`)

// 后端确认：这条评估真的存在，且属于刚建的项目
if (assessmentId) {
  const r = await fetch(`${API}/api/v1/assessments/${assessmentId}`, {
    headers: { Authorization: `Bearer ${engToken}` },
  })
  const a = await r.json()
  check('后端确认评估存在', r.status === 200, `${a?.project_name} / ${a?.status}`)
  check('落库时项目名正确', a?.project_name === '端到端验证 · 电商靶场', a?.project_name)

  // 等它跑起来。
  //
  // ⚠️ 这里验的是「**队列 → worker 的交接**」，不是「跑得快不快」。
  // worker 是**单消费者、顺序取任务**，所以只要上一轮验证留下的评估还在跑
  // （实测一次完整评估约 191 秒），这一条就会一直停在 `created`。
  // 那**不是**故障 —— 用 60 秒的预算去判它会得到假阳性（本脚本首跑就踩了）。
  // 预算按「排一个满编任务」给足，并在等待时把排队情况打出来，
  // 这样看到 `created` 的人能立刻分辨是「在排队」还是「worker 挂了」。
  const budgetS = 420
  let last = null
  let waited = 0
  for (let i = 0; i < budgetS / 3; i++) {
    const s = await (
      await fetch(`${API}/api/v1/assessments/${assessmentId}`, {
        headers: { Authorization: `Bearer ${engToken}` },
      })
    ).json()
    last = s
    if (s.status !== 'created') break
    if (i % 10 === 0) {
      const q = await (
        await fetch(`${API}/api/v1/assessments?page_size=20`, {
          headers: { Authorization: `Bearer ${engToken}` },
        })
      ).json()
      const ahead = (q.items ?? []).filter(
        (a) => a.status === 'running' && a.id !== assessmentId,
      ).length
      console.log(`   … 等待中 ${waited}s：status=created，前面还有 ${ahead} 个在跑`)
    }
    await sleep(3000)
    waited += 3
  }
  check(
    '评估离开了 created（worker 真的取走了）',
    last?.status !== 'created',
    `status=${last?.status}${last?.status === 'created' ? `，等了 ${waited}s 仍在排队` : `，耗时约 ${waited}s`}`,
  )

  // 界面上也该看得到进度条与阶段名
  const wbText = (await evaluate(`document.body.innerText`)) ?? ''
  check('工作台渲染出阶段名', wbText.includes('环境侦察') || wbText.includes('静态审计'))
}

// ===========================================================================
console.log('\n=== 3. 管理员身份：同一个按钮应当**禁用并说明原因** ===')
console.log('-'.repeat(60))

const admToken = await login('admin', join(ROOT, '.asa', 'admin-password.txt'))
await become(admToken, '/')

const admBtn = await evaluate(
  `(() => {
     const b = [...document.querySelectorAll('button')].find(x => x.innerText.trim() === '新建评估');
     return b ? { found: true, disabled: b.disabled } : { found: false };
   })()`,
)
check('管理员也**看得到**入口（不是藏起来）', admBtn?.found === true)
check('管理员身份下按钮**禁用**', admBtn?.disabled === true, `disabled=${admBtn?.disabled}`)

// 悬浮拿 tooltip 文案。
//
// ⚠️ 必须用 CDP 的**真实鼠标移动**，不能用 `dispatchEvent(new MouseEvent('mouseover'))`。
// rc-trigger（antd Tooltip 的底层）听的是 React 合成出来的 enter 事件，而 React 的
// `onMouseEnter` 是**从一对 `mouseout`/`mouseover` 推导**出来的 —— 手工派发只有一个
// `mouseover`、没有配对的前半个，React 就不会合成 enter，tooltip 永远不弹。
//
// 这个假阴性极具误导性：它会让你以为「antd 的 Tooltip 在 disabled 按钮上不工作」，
// 于是去加一个 `<span>` 包一层（网上到处是这个偏方）—— 而实际上产品是好的，
// 坏的是测试。**用假事件测交互，测的是浏览器怎么看待假事件，不是产品。**
const btnBox = await evaluate(
  `(() => {
     const b = [...document.querySelectorAll('button')].find(x => x.innerText.trim() === '新建评估');
     if (!b) return null;
     const r = b.getBoundingClientRect();
     return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
   })()`,
)
if (btnBox) {
  // 先从别处移进来，再落到按钮上 —— 单次 move 落在原地不会产生 enter
  await send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: 5, y: 5, buttons: 0 })
  await send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: btnBox.x, y: btnBox.y, buttons: 0 })
}
await sleep(1800)
const tip = (await evaluate(`document.querySelector('.ant-tooltip-inner')?.innerText ?? ''`)) ?? ''
check('tooltip 说明缺哪个权限', tip.includes('系统管理员') && tip.includes('安全工程师'), tip || '(没弹出)')

// ===========================================================================
console.log('\n=== 4. 控制台 ===')
console.log('-'.repeat(60))
check('无未捕获异常', exceptions.length === 0, exceptions.slice(0, 2).join(' | '))

const failed = results.filter((r) => !r).length
console.log(`\n${results.length - failed}/${results.length} 项通过`)
ws.close()
process.exit(failed ? 1 : 0)
