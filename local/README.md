# 本地活动站（改前端 JS 看效果）

把「融合！山团团！」活动的前端搬到本地跑，用来**改 JS / 改接口响应看效果**。

线上资源是公开只读的 CDN，改不了服务端那一份；这里的改动**只影响你自己**。

两条路，按需选：

- **本地镜像**（`fetch.py` + `serve.py`）：下载整套前端到本地托管，用你自己的浏览器打开。见下面。
- **路由拦截**（`intercept.py`）：不下载，用 Playwright 起一个受控浏览器直接改官方请求/响应。见后文。

## 目录

```
local/
  fetch.py       镜像下载 + 打补丁（可重复执行）
  serve.py       静态托管 + /act-server 反向代理 + 接口响应改写
  patch_score.py 改计分 / 上限 / 合成逻辑 / 出块等级（可重复执行 / 可还原）
  _verify_patch.py  校验补丁：六处值 + 与 .orig 的字节级比对（调试用）
  intercept.py   路由拦截版：不下载镜像，直接改官方 CDN 的请求/响应
  manifest.json  下载清单与 sha256（fetch.py 生成）
  site/          镜像产物（fetch.py 生成，可随时删掉重下）
```

## 用法

```bash
cd output/local
python fetch.py          # 下载并打补丁，约 1 分钟
python serve.py          # 默认 127.0.0.1:8765，会直接打印可打开的完整地址
```

`serve.py` 启动后会把带 token 的完整 URL 打印出来，直接粘进浏览器即可。
（token 取自 `output/.u8_token`；没有的话自己把 `u8_token=...` 拼到地址后面。）

> 注意：**同一端口只能有一个 `serve.py`**。重复启动时 Windows 允许两个进程同时 bind
> （`SO_REUSEADDR`），结果是新进程收不到连接、你看到的还是旧进程的页面 ——
> 改了参数却「没生效」多半是这个原因。启动前先确认 8765 只有一个监听：
> `netstat -ano | findstr 8765`

## 打了哪三处补丁

不补的话页面根本跑不起来，`fetch.py` 每次都会重打一遍：

| # | 位置 | 原值 | 改成 | 为什么 |
|---|------|------|------|--------|
| 1 | `index.js` 的 `r.p`（webpack publicPath） | `https://web.hycdn.cn/.../orbipom-merge-XaVa5Tz/` | `/` | 不改的话 chunk / css / 图片仍然回 CDN 拉，本地改 JS 没意义 |
| 2 | `821.js` 的 axios `baseURL` | `https://ef-webview.hypergryph.com/act-server/orbipom-merge` | `/act-server/orbipom-merge` | 页面在 127.0.0.1 上直连官方域名属于跨域 + 第三方 cookie，浏览器会拦；改成相对路径交给 `serve.py` 代理 |
| 3 | `index.html` 入口脚本前 | — | 注入 WVSDK 垫片 | 浏览器里没有 `window.WVSDK`，页面会判定自己不在游戏内，直接显示「网络异常」 |

补丁 1、2 是纯文本替换；补丁 3 注入的是一段小脚本：

```js
window.WVSDK = { ENV:{}, callback:{}, API:{}, platform:"Qt", invoke(){...}, invokeWithReturnValue(){...} }
```

`platform:"Qt"` 就是游戏客户端的真实取值，页面据此认为自己在游戏里，从而走
`PureLayout` 分支去读 URL 里的 `u8_token`。

## 实测结果

无头 Edge（`--headless=new --dump-dom`）打开 `http://127.0.0.1:8765/`：

| 配置 | `#root` 里的 `aria-label` |
|------|--------------------------|
| 垫片 + `u8_token`（`+`→`%2B`），**URL 不带 `hg_iframe`** | ✅ `最高分: 2026` / `排行榜` / `任务奖励` / `活动规则` / `重开一局 / 结算本局` / `得分` / `战技栏` / `2 COMBO` / `融合图鉴` |
| 不带 `u8_token` | `参数错误`（`params_error`，与代码预期一致） |

**本地站不需要 `hg_iframe=1`。** 线上版本要靠它把 `platform` 抬成 `Web`；
这里垫片已经把 `platform` 直接设成 `"Qt"`，比 `hg_iframe` 更贴近真实客户端环境。
两个一起加反而会去初始化 iframe 的 postMessage 桥（缺 `hg_parent_origin`），没必要。

## 改分数 / 分数上限（`patch_score.py`）

本地站跑起来后，改分数就是改 `site/821.67c1cf.js`。这个脚本把要改的地方都找好了：

```bash
python patch_score.py          # 得分 ×100，上限全抬高，关看门狗，1+1=最高级，只出 1 级
python patch_score.py --scale 1000
python patch_score.py --keep-spawn       # 保留原出块区间（1~5 随机）
python patch_score.py --spawn-level 2    # 固定出 2 级
python patch_score.py --restore   # 从 .orig 还原成原始文件
```

它改**六处**，全部是文件里唯一匹配的常量：

| # | 位置 | 原值 | 改成 | 说明 |
|---|------|------|------|------|
| 1 | `eS=[…]` 得分表 | `[1,3,6,10,15,21,28,36,45,55,66]` | 各项 ×`--scale`（默认 100） | 每级合成得分，index `i` 对应等级 `i+1`；原值 = 三角形数 `L(L-1)/2`。**唯一的得分来源** —— `addScore` 只有定义没有调用点，实际加分全在 `onMerge` 里走 `eM(level).score` |
| 2 | `ey.maxScore` | `99999` | `--cap`（默认 `9999999`） | `onMerge` / `addScore` 里的 `Math.min(ey.maxScore, …)` 夹取上限。只是**保险丝**，不是单局长度 |
| 3 | `r.score<1500&&e.score>=1500` | `1500` | `--run-cap`（默认 `99999999`） | **真正的单局分数上限**：分数跨过 1500 的那一瞬自动结算。1500 同时也是 `highScore` 奖励任务的目标值 |
| 4 | 10 秒看门狗 `"playing"===r&&n>i&&0===e&&t()` | — | `!1`（默认关掉） | 每 10 秒检查一次，只要「当前分 > 历史最高分」就自动结算。不关掉的话，抬了得分后一局只撑 10 秒就结束 |
| 5 | `processMerges()` 的新等级 `h=d?ek:r.level+1` | `h=d?ek:r.level+1` | `h=d\|\|1===r.level?ek:r.level+1` | **改合成逻辑本身**：两只**最小（1 级）**撞在一起直接变**最高级**（`ek` = 等级总数，实测 11）。`d` 仍是 false，所以照常走 `spawn` 分支，真的会生成一只 11 级 |
| 6 | `ey` 里的出块区间 `spawnLevelMin:1,spawnLevelMax:5` | `1,5` | `--spawn-level`（默认 `1,1`） | **第 5 条的配套**。`nextSpawnLevel()` 在 `[min,max]` 里随机取；不钉死的话出一只 3 级还得再等一只 3 级，第 5 条等于白改。钉成 1 之后 `r=t-e+1=1`，永远出 1 级 |

> **只改 `maxScore` 是不够的。** 抬高得分后一局还是会在 1500 或 10 秒处被自动结算，
> 得同时改 3、4 两处。详见技术分析报告 §8.6。
>
> **第 5 条必须和第 6 条一起改。** 合成逻辑改成「1+1=最高级」之后，
> 如果出块还按 1~5 级随机，玩家拿到一只 3 级就得再等一只 3 级才能合 ——
> 看着像没改。所以 `patch_score.py` / `mitm.py` / `intercept.py` 三个入口
> 默认都把出块钉在最小级；要单独关掉用 `--keep-spawn`。
> 第 6 条只动 `ey` 里那两个数字字面量，`lT` 里那行 `spawnLevelMin:ey.spawnLevelMin,…`
> （devtools 面板的基线快照，写的是 `ey.xxx` 而不是数字）**不会被误改**。

脚本的几条安全设计：

- **唯一性守卫**：每处都要求匹配且仅匹配 1 次，数量不对就报错退出，不会静默改错位置。
- **先备份再改**：第一次运行会把原始文件存成 `821.67c1cf.js.orig`，之后**所有补丁都从 `.orig` 出发** ——
  所以可重复执行（幂等），也不会叠着改花。`--restore` 直接还原。
- **`--start N`** 是调试用：直接给起始分，可以立刻看到分数与自动结算的效果（注意它本身就会触发结算）。
- **写文件带 `newline=""`**：不加的话 Windows 文本模式会把每个 `\n` 写成 `\r\n`，
  「除补丁外逐字节一致」就不成立了（实测被坑过，文件凭空多出一个 `\r`）。

实测输出（默认参数）：

```
  得分表    [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 66]
         ->  [100, 300, 600, 1000, 1500, 2100, 2800, 3600, 4500, 5500, 6600]
  硬上限    99999 -> 9999999
  结算阈值  1500 -> 99999999
  10s看门狗 已关闭
  合成逻辑  开（1+1=ek=最高级）
  出块等级  spawnLevelMin:1,spawnLevelMax:5 -> 固定 1 级
```

改完 `node --check 821.67c1cf.js` 语法通过，刷新页面正常进游戏。

### 校验补丁（`_verify_patch.py`）

改完想知道「是不是只改了那六处、别的地方一个字节都没动」，跑：

```bash
python _verify_patch.py
```

它会做两件事：把六处的当前值打出来；再把规则**重新作用到 `.orig` 上**，
跟 `site/` 里那份做**字节级**比对。完全一致才算通过 ——
这条能抓住「正则匹配多了 / 文件被顺手改坏」这类看不见的问题。实测输出：

```
### 补丁后 site  388530 字节  CR=0 LF=1
    得分表 eS     100,300,600,1000,1500,2100,2800,3600,4500,5500 OK
    maxScore   9999999                                        OK
    结算阈值       99999999                                       OK
    10s看门狗     !1                                             OK
    合成逻辑       ||1===r.level                                  OK
    出块区间       1|1                                            OK

### 字节级复核：把规则重新作用到 .orig 上，结果与 site 文件**完全一致**
    → 确认只改了那六处，其余一个字节都没动（388530 字节）
```

> ⚠️ **只影响本地这一份客户端。** 服务端 `/api/save/score` 对 `score` 另有上限
> （实测 99999，见技术分析报告 §4.2），所以本地刷到 100 万，提交上去也不会按 100 万记账。

## 首页那个「最高分」不是 `maxScore`

这是最容易踩的一个坑，先说清楚：

| 名字 | 是什么 | 在哪显示 | 谁能改 |
|------|--------|----------|--------|
| **`maxScore`**（`ey.maxScore`） | 前端配置里的**夹取上限**，只出现在 `Math.min(ey.maxScore, …)` 里 | **界面上根本不显示** | 改 JS（`patch_score.py`）✅ |
| **最高分**（首页那个数字） | 服务端 `/api/save/profile` 下发的**历史最高分** `data.highScore` | 首页标题栏 | 改 JS **没用**，得改接口响应 |

所以「改了 `maxScore` 但首页最高分没变」是**正常现象** —— 这俩压根不是一个东西。

而且服务端自己就把分数夹在 **99999**：

```
POST /api/save/score  ->  HTTP 200  {'code': 0, 'data': {'best': 99999, 'isNewBest': False}, 'msg': ''}
```

哪怕客户端算出更大的分数，服务端也只记 99999，下一次 `/api/save/profile` 返回的 `highScore` 仍是 99999。

### 换个方法：在代理层改写响应

`serve.py` 加了一个 `--fake-high-score`，直接把服务端响应里的 `highScore` / `best` 替换掉：

```bash
python serve.py                        # 默认 --fake-high-score 9999999
python serve.py --fake-high-score 0    # 关掉，恢复服务端原值
python serve.py --fake-high-score 12345678
```

只碰 `/api/save/profile` 与 `/api/save/score` 两个接口里的这两个字段，排行榜等其它接口不动。
命中时会打一行 `[改写] ... -> 9999999`，启动时也会打印当前值。

**实测**（无头 Edge 打开 `http://127.0.0.1:8765/`）：

| 配置 | 首页 `aria-label` |
|------|-------------------|
| `--fake-high-score 9999999` | `最高分: 9999999` ✅ |
| `--fake-high-score 0` | `最高分: 99999`（服务端原值） |

> ⚠️ **只影响本地站。** 真实游戏客户端加载的是官方 CDN 的 JS，走的是官方接口，
> 这里怎么改都不会影响它 —— 而且服务端本来就夹 99999，客户端显示再大也不会被记账。

## 另一条路：路由拦截（`intercept.py`）

上面那套是「下载镜像 → 本地托管」。如果不想下 8.3 MB、也不想担心 CDN 更新后
chunk 文件名变了导致映射过期，用 `intercept.py`：**直接打官方 CDN，在请求层改写**。

```bash
python intercept.py                             # 有头，改最高分 + 改计分 + 1+1=最高级
python intercept.py --headless --shot out.png   # 无头跑一次看结果
python intercept.py --high-score 0              # 只改计分，最高分走服务端原值
python intercept.py --scale 1000                # 得分放大 1000 倍
python intercept.py --no-mega-merge             # 保留原合成逻辑（1+1=2）
python intercept.py --no-js-patch               # 只拦接口
```

需要 `pip install playwright`（**不用**再下浏览器，脚本用系统已装的 Edge）。

两种方式对比：

| | 本地镜像（`fetch.py` + `serve.py`） | 路由拦截（`intercept.py`） |
|--|-----------------------------------|---------------------------|
| 准备 | 下载 462 文件 / 8.3 MB | 不用下载 |
| CDN 更新 | chunk 带 hash，映射会过期 | 按**内容**判断，不用改 |
| publicPath / baseURL | 都要改写 | 原样不动 |
| 接口 | 走自建反向代理 | 请求原样发出，只改响应 |
| 浏览器 | 你自己那个 | **必须是脚本拉起的**（Playwright 控制） |

拦截两处：

1. **JS** —— 命中活动目录下的 `.js` 就 `route.fetch()` 取原文，在内存里按同样的六处规则改完再
   `route.fulfill()` 交回浏览器。判断依据是**内容里有没有 `maxScore:`**，不是文件名，
   所以 CDN 换版本也不用维护 chunk 映射。规则从 `patch_score.py` 导入，不另写一份。
2. **接口** —— `/api/save/profile`、`/api/save/score` 的响应，正则替换 `highScore` / `best`。

平台检测用 `add_init_script()` 注入同一段 WVSDK 垫片，不需要 `hg_iframe`。

**实测**（`--headless --shot`）：

```
  [JS]   821.67c1cf.js  -> 得分表 ×100、maxScore->9999999、结算阈值->99999999、关掉10s看门狗
  [接口] save/profile  highScore/best -> 9999999
aria-labels: ['返回', '最高分: 9999999', '排行榜', '任务奖励', '活动规则', ...]
```

> ⚠️ **只能作用于脚本启动的浏览器。** 你平时双击打开的那个浏览器、以及游戏客户端里的 WebView
> 都不受它影响 —— 所以「在游戏里看，数字没变」是必然结果，不是补丁失效。

## 代理做了什么

`serve.py` 把 `/act-server/*` 原样转发到 `https://ef-webview.hypergryph.com/act-server/*`，
请求头里的 `Origin` / `Referer` 改写成官方来源（避免上游校验拒绝）。

`Set-Cookie` 必须改写，否则浏览器会直接丢弃：

- 去掉 `Domain=` → 变成 `127.0.0.1` 的 host-only cookie
- 去掉 `Secure` → 允许 `http://127.0.0.1`
- `SameSite=None` → `SameSite=Lax`（不配 `Secure` 时 `None` 会被拒）

## 注意

- **CDN 更新后要重跑 `fetch.py`**：文件名带 hash（`index.3d8293.js`、`821.67c1cf.js`），
  版本一变这里的 `CHUNKS` 映射和入口名就过期了。当前版本 `v1d5-synthesize-tuantuan-web@1.1.2`。
  重跑前把 `site/` 删掉，或加 `--force`。
- **分享功能会失效**：垫片不是真 SDK，`share` / `openGameScheme` 这类需要原生桥的调用会走空实现。
  游戏主体、奖励、排行榜不受影响。
- **这是绕过官方「仅限游戏内打开」限制的做法**，属非常规用法，仅建议用于本地调试与学习。
- **上游有限流**：短时间内重复打开会被拒，页面显示「网络出小差了，请稍后重试~」（`network_issue`）。
  等十几秒再来即可，别对 `/act-server/*` 做高频压测。
- **改 JS 的正确姿势**：直接编辑 `site/` 下的文件（比如 `821.67c1cf.js`），刷新页面即生效。
  改计分与上限可以直接用 `patch_score.py`（见上节）。
  但注意 `fetch.py` 会覆盖 `index.html` / 入口 JS / 全部 chunk / CSS —— 想保留改动就先把
  `fetch.py` 里对应的 `write(..., True)` 改成 `False`，或者改完自己留个备份。
