# 通用图元片段

配套 `SKILL.md`。全部是**可复制粘贴**的 `execute` snippet 片段，改数据即可用。

约定：辅助函数写成本次 snippet 内的 `function`（**不跨调用保留**）；
跨调用要用的 id 一律用**节点 id 字符串**或全局变量。

---

## 1. 屏幕骨架

```js
function navOv(i){return {[navItemIds[i]]:{fill:"$brand"},[navLabelIds[i]]:{fill:"#FFFFFF"},[navIconIds[i]]:{fill:"#FFFFFF"}}}
const sid=Insert(document,{type:"frame",name:"页面名",x:1520,y:1000,width:1440,height:900,layout:"horizontal",fill:"$bg-page",clip:true,placeholder:true})
Insert(sid,{type:"ref",ref:sidebarCmp,name:"NavSidebar",width:240,height:"fill_container",descendants:navOv(1)})
const main=Insert(sid,{type:"frame",name:"Main",width:"fill_container",height:"fill_container",layout:"vertical",fill:"$bg-page"})
const top=Insert(main,{type:"frame",name:"Topbar",width:"fill_container",height:60,padding:[0,20],gap:12,alignItems:"center",fill:"$bg-card",stroke:"$border",strokeWidth:{bottom:1}})
Insert(top,{type:"text",name:"PageTitle",content:"页面名",fontFamily:"$font",fontSize:15,fontWeight:"600",fill:"$text-primary"})
Insert(top,{type:"frame",name:"TopSpacer",width:"fill_container",height:1})   // 撑开，把右侧按钮推到边上
const body=Insert(main,{type:"frame",name:"Body",width:"fill_container",height:"fill_container",layout:"vertical",gap:16,padding:[16,20],clip:true})
// ... 页面内容插入 body
Update(sid,{placeholder:false})   // 全部画完再解锁
TakeScreenshot([sid])
```

---

## 2. 表格卡片

```js
const COLS=[["标题","fill_container"],["分类",110],["状态",100],["操作",120]]
function mkCells(row){
  const cells=[]
  for(let i=0;i<COLS.length;i=i+1){
    cells.push(Insert(row,{type:"frame",name:"Cell/"+COLS[i][0],width:COLS[i][1],height:"fill_container",alignItems:"center",layout:"horizontal"}))
  }
  return cells
}
const card=Insert(body,{type:"frame",name:"TableCard",width:"fill_container",height:"fill_container",layout:"vertical",fill:"$bg-card",cornerRadius:10,stroke:"$border",strokeWidth:1,clip:true})
const hr=Insert(card,{type:"frame",name:"HeaderRow",width:"fill_container",height:40,padding:[0,16],fill:"$bg-subtle",stroke:"$border",strokeWidth:{bottom:1}})
const hcs=mkCells(hr)
for(let i=0;i<hcs.length;i=i+1){Insert(hcs[i],{type:"text",name:"Th",content:COLS[i][0],fontFamily:"$font",fontSize:11.5,fontWeight:"600",fill:"$text-secondary",textGrowth:"fixed-width",width:"fill_container"})}
const ROWS=[["差旅报销标准.pdf","财务制度","启用"],["员工手册.txt","通用制度","停用"]]
for(let ri=0;ri<ROWS.length;ri=ri+1){
  const d=ROWS[ri]
  const r=Insert(card,{type:"frame",name:"Row/"+d[0],width:"fill_container",height:52,padding:[0,16],stroke:"$border-soft",strokeWidth:{bottom:1}})
  const cs=mkCells(r)
  Insert(cs[0],{type:"text",name:"Name",content:d[0],fontFamily:"$font",fontSize:12.5,fontWeight:"500",fill:"$text-primary",textGrowth:"fixed-width",width:"fill_container"})
  Insert(cs[1],{type:"text",name:"Cat",content:d[1],fontFamily:"$font",fontSize:12.5,fill:"$text-secondary",textGrowth:"fixed-width",width:"fill_container"})
  pill(cs[2],d[2],d[2]==="启用")
  const act=Insert(cs[3],{type:"frame",name:"Actions",width:"fill_container",gap:11,alignItems:"center"})
  Insert(act,{type:"text",name:"ActEdit",content:"编辑",fontFamily:"$font",fontSize:12,fill:"$brand"})
  Insert(act,{type:"text",name:"ActMore",content:"停用",fontFamily:"$font",fontSize:12,fill:"$text-muted"})
}
```

> **宽度分配**：`fill_container` 列吃掉剩余宽度。先算固定列之和，剩余才给弹性列，
> 否则窄屏下文字会挤成一列一个字的竖排。

---

## 3. 状态胶囊 / 角色胶囊

```js
function pill(parent,text,on){
  const p=Insert(parent,{type:"frame",name:"Pill",padding:[3,9],cornerRadius:5,fill:on?"$success-soft":"$border-soft"})
  Insert(p,{type:"text",name:"PillText",content:text,fontFamily:"$font",fontSize:11.5,fontWeight:"500",fill:on?"$success":"$text-muted"})
}
```

其他配色的软底/实色对：`$brand-softer`+`$brand` · `$warning-soft`+`#8A5A12` ·
`$danger-soft`+`$danger` · `$border-soft`+`$text-muted`。

---

## 4. 权限范围单元格（globe / shield）

```js
function scopeCell(parent,text,isGlobal){
  const c=Insert(parent,{type:"frame",name:"ScopeCell",width:"fill_container",gap:6,alignItems:"center"})
  Insert(c,{type:"icon",name:"ScopeIcon",library:"lucide",icon:isGlobal?"globe":"building-2",width:13,height:13,fill:isGlobal?"$brand":"$text-muted"})
  Insert(c,{type:"text",name:"ScopeText",content:text,fontFamily:"$font",fontSize:12,fill:isGlobal?"$brand":"$text-secondary",textGrowth:"fixed-width",width:"fill_container"})
}
```

---

## 5. KPI 卡片行

```js
const row=Insert(body,{type:"frame",name:"KpiRow",width:"fill_container",gap:14})
const KPIS=[["访问次数 PV","12,480","+12.4%","eye","$brand","$brand-soft"],
            ["独立人数 UV","326","+4.1%","users","$brand","$brand-soft"],
            ["平均响应时长","1.4s","-0.3s","timer","$warning","$warning-soft"]]
for(let i=0;i<KPIS.length;i=i+1){
  const k=KPIS[i]
  const c=Insert(row,{type:"frame",name:"Kpi/"+k[0],width:"fill_container",layout:"vertical",gap:9,padding:[13,14],cornerRadius:9,fill:"$bg-card",stroke:"$border",strokeWidth:1})
  const tr=Insert(c,{type:"frame",name:"KpiTop",width:"fill_container",gap:8,alignItems:"center"})
  Insert(tr,{type:"text",name:"KpiLabel",content:k[0],fontFamily:"$font",fontSize:11.5,fill:"$text-secondary",textGrowth:"fixed-width",width:"fill_container"})
  const ib=Insert(tr,{type:"frame",name:"KpiIconBox",width:22,height:22,cornerRadius:6,fill:k[5],layout:"horizontal",justifyContent:"center",alignItems:"center"})
  Insert(ib,{type:"icon",name:"KpiIcon",library:"lucide",icon:k[3],width:13,height:13,fill:k[4]})
  Insert(c,{type:"text",name:"KpiValue",content:k[1],fontFamily:"$font",fontSize:22,fontWeight:"600",fill:"$text-primary",textGrowth:"fixed-width",width:"fill_container"})
  const dr=Insert(c,{type:"frame",name:"KpiDelta",gap:4,alignItems:"center"})
  Insert(dr,{type:"icon",name:"DeltaIcon",library:"lucide",icon:k[2].charAt(0)==="-"?  "trending-down":"trending-up",width:12,height:12,fill:"$success"})
  Insert(dr,{type:"text",name:"DeltaText",content:k[2]+" 环比",fontFamily:"$font",fontSize:11,fill:"$text-muted"})
}
```

---

## 6. 柱状图（父水平 + 列垂直底对齐）

**不要用绝对定位**。柱高写死像素，靠 `justifyContent:"end"` 压到底部。

```js
const chart=Insert(card,{type:"frame",name:"BarChart",width:"fill_container",height:"fill_container",gap:12})
const DATA=[["10-08",74,52],["10-09",96,64],["10-10",82,58]]
for(let i=0;i<DATA.length;i=i+1){
  const d=DATA[i]
  const col=Insert(chart,{type:"frame",name:"Col/"+d[0],width:"fill_container",height:"fill_container",layout:"vertical",justifyContent:"end",gap:7,alignItems:"center"})
  const bars=Insert(col,{type:"frame",name:"Bars",width:"fill_container",height:150,gap:5,alignItems:"end"})
  Insert(bars,{type:"frame",name:"BarA",width:"fill_container",height:d[1],cornerRadius:[3,3,0,0],fill:"$brand"})
  Insert(bars,{type:"frame",name:"BarB",width:"fill_container",height:d[2],cornerRadius:[3,3,0,0],fill:"$brand-soft"})
  Insert(col,{type:"text",name:"DayLabel",content:d[0],fontFamily:"$font",fontSize:10.5,fill:"$text-muted"})
}
```

---

## 7. 环形图（多段弧，叠在 layout:"none" 的栈里）

角度：`startAngle` 从右侧起**逆时针**，`sweepAngle` 是本段占比 × 360。

```js
const stack=Insert(wrap,{type:"frame",name:"DonutStack",width:132,height:132,layout:"none"})
Insert(stack,{type:"ellipse",name:"Arc/A",x:0,y:0,width:132,height:132,fill:"$brand",  innerRadius:0.68,startAngle:0,  sweepAngle:209})
Insert(stack,{type:"ellipse",name:"Arc/B",x:0,y:0,width:132,height:132,fill:"$success",innerRadius:0.68,startAngle:209,sweepAngle:122})
Insert(stack,{type:"ellipse",name:"Arc/C",x:0,y:0,width:132,height:132,fill:"$warning",innerRadius:0.68,startAngle:331,sweepAngle:29})
// 圆心文字：layout:"none" 里用 x/y 定位
Insert(stack,{type:"text",name:"CenterValue",x:0,y:48,width:132,textAlign:"center",textGrowth:"fixed-width",content:"58%",fontFamily:"$font",fontSize:20,fontWeight:"600",fill:"$text-primary"})
Insert(stack,{type:"text",name:"CenterLabel",x:0,y:74,width:132,textAlign:"center",textGrowth:"fixed-width",content:"检索生成占比",fontFamily:"$font",fontSize:10,fill:"$text-muted"})
```

---

## 8. 榜单卡片（TOP N）

```js
function rankRow(card,idx,name,value){
  const r=Insert(card,{type:"frame",name:"Rank"+idx,width:"fill_container",height:40,padding:[0,14],gap:10,alignItems:"center",stroke:"$border-soft",strokeWidth:{bottom:1}})
  const top3=idx<=3
  const b=Insert(r,{type:"frame",name:"RankBadge",width:20,height:20,cornerRadius:5,fill:top3?"$brand-soft":"$border-soft",layout:"horizontal",justifyContent:"center",alignItems:"center"})
  Insert(b,{type:"text",name:"RankNum",content:""+idx,fontFamily:"$font",fontSize:11,fontWeight:"600",fill:top3?"$brand":"$text-muted"})
  Insert(r,{type:"text",name:"RankName",content:name,fontFamily:"$font",fontSize:12.5,fill:"$text-primary",textGrowth:"fixed-width",width:"fill_container"})
  Insert(r,{type:"text",name:"RankValue",content:value,fontFamily:"$font",fontSize:12.5,fontWeight:"600",fill:"$brand"})
}
```

---

## 9. 下划线式 Tab 栏

**Tab 必须给固定宽度**（父级 fit_content + 子级 fill_container 会循环依赖）。

```js
const TABS=[["FAQ 候选审核",4,148],["已发布 FAQ",18,132]]
const bar=Insert(body,{type:"frame",name:"TabBar",width:"fill_container",gap:6,stroke:"$border",strokeWidth:{bottom:1}})
for(let i=0;i<TABS.length;i=i+1){
  const tb=TABS[i]
  const act=i===0
  const t=Insert(bar,{type:"frame",name:"Tab/"+tb[0],width:tb[2],padding:[12,0,10],gap:7,alignItems:"center",strokeWidth:{bottom:2},stroke:act?"$brand":"#00000000"})
  Insert(t,{type:"text",name:"TabLabel",content:tb[0],fontFamily:"$font",fontSize:13.5,fontWeight:act?"600":"400",fill:act?"$brand":"$text-secondary"})
  const bd=Insert(t,{type:"frame",name:"TabBadge",padding:[1,7],cornerRadius:9,fill:act?"$brand":"$border-soft"})
  Insert(bd,{type:"text",name:"TabCount",content:""+tb[1],fontFamily:"$font",fontSize:11,fontWeight:"500",fill:act?"#FFFFFF":"$text-muted"})
}
```

---

## 10. 分段控件（Segmented）

```js
const seg=Insert(body,{type:"frame",name:"SubTabs",padding:3,gap:2,cornerRadius:9,fill:"$bg-card",stroke:"$border",strokeWidth:1})
const SEGS=["部门管理","用户管理","角色权限","模型配置"]
for(let i=0;i<SEGS.length;i=i+1){
  const on=i===1
  const it=Insert(seg,{type:"frame",name:"Seg/"+SEGS[i],padding:[6,14],cornerRadius:7,fill:on?"$brand":"#00000000"})
  Insert(it,{type:"text",name:"SegLabel",content:SEGS[i],fontFamily:"$font",fontSize:12.5,fontWeight:on?"500":"400",fill:on?"#FFFFFF":"$text-secondary"})
}
```

---

## 11. 表单输入框 / 按钮

```js
function field(parent,label,icon,value,ph){
  const g=Insert(parent,{type:"frame",name:"Field/"+label,width:"fill_container",layout:"vertical",gap:7})
  Insert(g,{type:"text",name:"Label",content:label,fontFamily:"$font",fontSize:12,fontWeight:"500",fill:"$text-secondary"})
  const box=Insert(g,{type:"frame",name:"Input",width:"fill_container",height:42,gap:9,padding:[0,12],cornerRadius:8,fill:ph?"$bg-card":"$bg-subtle",stroke:"$border",strokeWidth:1,alignItems:"center"})
  Insert(box,{type:"icon",name:"InputIcon",library:"lucide",icon:icon,width:15,height:15,fill:"$text-muted"})
  Insert(box,{type:"text",name:"InputText",content:value,fontFamily:"$font",fontSize:13.5,fill:ph?"$text-placeholder":"$text-primary",textGrowth:"fixed-width",width:"fill_container"})
  return g
}

function btnPrimary(parent,label,icon,w){
  const b=Insert(parent,{type:"frame",name:"Btn/"+label,width:w,height:34,padding:[0,14],gap:7,cornerRadius:8,fill:"$brand",justifyContent:"center",alignItems:"center"})
  Insert(b,{type:"icon",name:"BtnIcon",library:"lucide",icon:icon,width:15,height:15,fill:"#FFFFFF"})
  Insert(b,{type:"text",name:"BtnLabel",content:label,fontFamily:"$font",fontSize:13,fill:"#FFFFFF"})
}

function btnGhost(parent,label,icon){
  const b=Insert(parent,{type:"frame",name:"Btn/"+label,height:34,padding:[0,14],gap:7,cornerRadius:8,fill:"$bg-card",stroke:"$border",strokeWidth:1,alignItems:"center"})
  Insert(b,{type:"icon",name:"BtnIcon",library:"lucide",icon:icon,width:15,height:15,fill:"$text-secondary"})
  Insert(b,{type:"text",name:"BtnLabel",content:label,fontFamily:"$font",fontSize:13,fill:"$text-secondary"})
}
```

---

## 12. 提示条（info / warning）

```js
function note(parent,icon,text,bg,fg){
  const n=Insert(parent,{type:"frame",name:"NoteBox",width:"fill_container",gap:8,padding:[10,12],cornerRadius:8,fill:bg,alignItems:"start"})
  Insert(n,{type:"icon",name:"NoteIcon",library:"lucide",icon:icon,width:14,height:14,fill:fg})
  Insert(n,{type:"text",name:"NoteText",content:text,fontFamily:"$font",fontSize:11.5,fill:fg,textGrowth:"fixed-width",width:"fill_container",lineHeight:1.6})
}
// note(body,"info","授权部门自动覆盖其子孙部门","$brand-softer","$brand")
// note(body,"triangle-alert","8.2% 的提问超过 2s","$warning-soft","#8A5A12")
```
