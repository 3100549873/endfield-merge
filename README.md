# 融合！山团团！工具集（`orbipom-merge`）

《明日方舟：终末地》WebView 活动「融合！山团团！」的两件事：

| 能力 | 脚本 |
| --- | --- |
| **修改分数** | `cli.py` |
| **一键获取奖励**（刷满五个任务 + 全部领取） | `claim_all.py` |

**单文件，零第三方依赖**，Python ≥ 3.6 即可运行。

---

## 快速开始

```bash
git clone https://github.com/3100549873/endfield-merge.git
cd endfield-merge

python claim_all.py              # 一键拿满全部奖励
python cli.py --score 12345      # 只改分数
```

首次运行需要活动链接（只需粘一次，之后走缓存）：

```
[-] 需要 u8_token —— 它是提交进度的唯一凭证。
    u8_token / 活动链接 (留空则只生成密文，不提交): https://.../?u8_token=XXXX&server=1
[+] 已缓存到 .u8_token（server=1）
```

> **其实基本不用手粘。** 只要你在游戏里点开过一次这个活动页，工具就能从
> 本机游戏日志 / CEF 缓存里自己找到 `u8_token` —— 见
> [u8_token 从哪来](#u8_token-从哪来不需要抓包)。

### 常用命令

| 命令 | 作用 |
| --- | --- |
| **`python claim_all.py`** | **一键获取全部奖励：刷满五个任务 + 一键领取** |
| `python claim_all.py --dry-run` | 只看还差多少，不发写请求 |
| `python claim_all.py --selftest` | 离线自检（28 项），不联网 |
| **`python cli.py --score N`** | **修改分数（认人 → 建会话 → 加密 → 提交）** |
| `python cli.py reward` | 只读查看奖励任务进度与领取状态 |
| `python cli.py claim` | 领取全部可领的奖励（服务端幂等） |
| `python cli.py where` | 排查 token 来源与 token→角色对照表 |
| `python cli.py selftest` | 跑官方加解密测试向量 |
| `python cli.py reset` | 清缓存，切换游戏角色时用 |
| `python tools/netdiag.py` | 网络诊断：直连 / 走代理两条路分开测 |

两个脚本**必须放在同一目录** —— `claim_all.py` 直接复用 `cli.py` 的
加解密 / 会话 / token 认人，缓存文件也共用，可以交替跑，不用重复粘 token。

---

## 修改分数

```bash
python cli.py --score 12345          # 全流程
python cli.py encrypt 1500           # 只生成密文，不提交
python cli.py decrypt <d>            # 解一个已有的 d
python cli.py key                    # 打印推导出的 AES-128 密钥
```

```
[>] 目标角色: 角色A (roleId=10000000000, uid=100000000)
[>] 加密完成  {"score":12345}
    d = <base64(iv ‖ AES-GCM(score))>
[>] 提交分数 ...
    HTTP 200  {"code":0,"data":{"best":12345,"isNewBest":true},"msg":""}
```

提交分两步，缺一不可：先 `POST /api/role/login` 换会话 cookie，再
`POST /api/save/score`。跳过第一步直接提交会 `401 UN_LOGIN`。

响应给的是 **`best`（历史最高）**，不是本次提交值 —— 服务端**只升不降**。
完整契约（密文结构、密钥推导、校验边界）见
[技术分析报告.md §2–§4](技术分析报告.md)。

---

## 一键获取奖励（`claim_all.py`）

```bash
python claim_all.py              # 刷满 + 一键领取
python claim_all.py --dry-run    # 只看还差多少，不发写请求
python claim_all.py --selftest   # 离线自检，不联网
```

就这三个开关。分数固定 1500（任务要求值），写请求间隔固定 1 秒，不需要调。

五个任务与端点：

| 任务 | 目标 | 端点 | 请求体 |
| --- | --- | --- | --- |
| `merge` | 合成 20 次 | `POST /api/save/merge` | `{"level": 2~11}` |
| `skill` | 战技 3 **种** | `POST /api/save/skill` | `{"skillId": "clear\|wind\|shake\|swap"}` |
| `highScore` | 最高分 1500 | `POST /api/save/score` | `{"d": "<AES-GCM base64>"}` |
| `share` | 分享 1 次 | `POST /api/reward/share` | 无 |
| `goldenAdmin` | 合成黄金管理员 1 次 | **没有端点** | — |
| （领取） | — | `POST /api/reward/claim-all` | 无 |

三个容易踩的点，脚本都已经处理：

1. **`goldenAdmin` 没有独立接口。** 它是 `save/merge` 响应里 `unlockedMax >= 11`
   推导出来的（前端 `updateTaskProgress("goldenAdmin", +(unlockedMax >= ek))`，`ek = 11`）。
   所以脚本保证合成序列里**一定出现 `level: 11`** —— 哪怕次数已经刷满 20 次、
   只要 `unlockedMax` 还没到 11，也会补发一次 11 级。只刷次数是点不亮这个任务的。

   > 真机实测过：某账号 `merge` 已经 `20/20` 但 `unlockedMax` 只有 **9**，
   > `goldenAdmin` 就是不亮。补一次 `{"level": 11}` 立刻点亮。

2. **`skillUseTotal` 统计的是「种类数」不是「次数」。** 所以要发 `clear` / `wind` / `shake`
   三个**不同**的 skillId；同一个发三次只会得到 1。

3. **`claim-all` 在「没有可领」时不是返回空 `results`，而是报错**
   `{"code":1300,"msg":"NO_REWARD_TO_CLAIM"}`。脚本把它当正常情况，不当失败。

另外它是**增量**的：先读 `/api/reward` 和 `/api/save/profile`，只补差额。
已经满的账号跑下去一个写请求都不会发（自检里专门验了这条）。
写请求之间停 1 秒 —— 服务端会限流，密集请求会被直接断连（`RemoteDisconnected`，
没有任何响应）。

`--selftest` 用假服务端把四个写路径的边界跑了 28 项，**不联网、不碰账号**：

```
$ python claim_all.py --selftest
[OK] 次数已满但 unlockedMax=8：仍会补一次 level=11
[OK] 全满账号：0 个写请求
[OK] 战技：3 个互不相同
[OK] claim-all 无奖可领（1300）：判为正常
----------------------------------------------------
通过 28 项，失败 0 项
```

奖励内容不在接口里，是前端写死的表 —— 五个任务合计 **钻石 ×300 + 金币 ×20000**。

---

## u8_token 从哪来（**不需要抓包**）

提交进度只用 `u8_token`（活动接口的 `x-role-token`）。工具按下面的优先级
**自动找**，只有全都找不到时才需要手动粘一次：

| 优先级 | 来源 | 说明 |
| --- | --- | --- |
| 1 | `--u8` 参数 | 手动指定，接受整条链接或纯 token |
| 2 | `.u8_token` 缓存 | 找到过一次就记住了 |
| 3 | **游戏日志** | `%USERPROFILE%\AppData\LocalLow\Hypergryph\<游戏>\sdklogs\HGWebview.log` |
| 4 | **CEF 缓存** | `%LOCALAPPDATA%\PlatformProcess\Cache\data_1` |
| 5 | 手动粘贴 | 以上都没有时的兜底 |

**关键：只要你在游戏里点开过一次该活动页，第 3/4 步就能自己拿到 token。**

- 第 3 步 —— 游戏客户端每次打开 WebPortal，都会把带 `u8_token` 的完整链接
  以 `WebPortal url: https://ef-webview...` 的形式写进日志。
- 第 4 步 —— webview 是 Chromium 内核，活动页 URL 会落进 CEF 缓存。
  该文件被进程占用，普通读取会 `Permission denied`，脚本用 `CreateFileW`
  显式声明 `FILE_SHARE_READ|WRITE|DELETE` 才能读到。

### 缓存里有多个 token 时，怎么知道是哪个号

换过账号之后，日志和 CEF 缓存里会同时躺着好几个 `u8_token`。它们**都还有效**，
但属于**不同角色** —— 只按「谁在文件里更靠后」去猜会猜错，把进度提交到别人号上。

一个 token 只对得上一个角色，所以工具改成用 `role/sync` **认人**：

```
POST /api/role/login   { "token": "<u8_token>", "serverId": "1" }   → 拿会话 cookie
POST /api/role/sync    {}                                           → {roleId, nickname, uid, avatar}
```

`role/sync` 必须先有会话 cookie，否则返回 `401 {"reason":"UN_LOGIN"}`；
若 cookie 与 `x-role-token` 指向不同角色，则返回 `401 {"reason":"DETECTED_ROLE_CHANGED"}`。

认出来之后按下面的规则挑，**绝不瞎猜**：

| 情况 | 行为 |
| --- | --- |
| 本机只有一个角色 | 直接用，不问 |
| 本机有多个角色 | 列出来让你选，直接回车则放弃 |
| 已锁定 / `--role <roleId>` | 直接挑该 roleId 对应的那个 |

身份结果缓存进 `.u8_roles.json` —— 一个 token 只认一次，之后每次运行零网络开销。
每次成功提交后会自动锁定本次角色到 `.u8_role`，下次即使缓存里混着别的号，
也会自动挑回同一个角色。

---

## 本机有抓包代理 / hosts 劫持 / 换个 Python 就报证书错

这三类都会让 Python 报一堆看起来像「网络坏了」的错，但**浏览器一切正常** ——
因为浏览器信那些 CA，Python 不信。工具都已经处理，这里说清楚怎么读提示。

### 坑 1：hosts 把活动域指到了本机

中间人（`mitm/`）会这么干。工具启动时自动检测，发现被劫持就绕过 hosts、
直连真实 IP（裸 UDP DNS 查，**不走 DoH** —— 本机 DoH 会被网络层拦掉）：

```
[+] 检测到 hosts 劫持，已绕过 -> 43.145.18.240
```

### 坑 2：请求走了代理，而代理在解密 TLS

ProxyPin / Charles / Fiddler 这类工具一开「HTTPS 解密」，就用它自己的 CA 重签证书：

```
URLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed:
           self-signed certificate in certificate chain
```

活动接口是公开 HTTPS，本来就不需要代理，所以工具**默认绕过系统代理直连**，
而且每次都把「走哪条路」说清楚：

```
[>] 检测到系统代理 http://127.0.0.1:64969 —— 已绕过直连（要用它抓包请设 ORBIPOM_USE_PROXY=1）
```

要**用代理抓包**就设 `ORBIPOM_USE_PROXY=1`，这时它会改成：

```
[>] 走代理 http://127.0.0.1:64969（ORBIPOM_USE_PROXY=1）—— TLS 由它解密，证书报错先找它
```

> ⚠️ **这里最容易把自己坑进去**：一旦设了 `ORBIPOM_USE_PROXY=1`，请求就真的走代理了。
> 代理开着 HTTPS 解密的话必然报上面的证书错 —— 报错提示会直接点名是这个变量干的，
> 并给出清除命令。活动接口不需要代理，**抓完包记得清掉**：
> ```powershell
> Remove-Item Env:ORBIPOM_USE_PROXY      # cmd: set ORBIPOM_USE_PROXY=
> ```

### 坑 3：这个 Python 的信任库是空的（最像「网络问题」，其实不是）

**现象**：同一个脚本、同一个目录，`python xxx.py` 报证书错，
`C:\...\Python39\python.exe xxx.py` 却一切正常。看着像「网络时好时坏」。

**根因**：Windows 的有效 PATH 是「系统 PATH + 用户 PATH」**拼接**的，而
`C:\msys64\mingw64\bin` 常排在官方版 Python 前面 ⇒ 裸 `python` 命中的是
**MSYS2 的 Python**。而它：

- **不读 Windows 证书存储**（连 `ssl.enum_certificates` 都没编进去）；
- 它的 OpenSSL 指向 `C:\msys64\mingw64\etc\ssl\cert.pem`，没装 `ca-certificates`
  时那个目录**是空的**。

于是信任库为空，所有 HTTPS 校验失败。**跟网络、跟代理一点关系都没有。**

工具检测到会自己补（先读 Windows ROOT，再退到现成的 CA 包）：

```
[>] 这个 Python 的信任库是空的（它不读 Windows 证书存储）—— 已补 1 个根证书后继续
```

补不上时会直接告诉你换解释器：

```
[-] 这个 Python 的信任库是空的，也没找到可用的根证书包 —— HTTPS 必然失败。
        这不是网络问题，换个解释器就好：py -3 或 %LOCALAPPDATA%\Programs\Python\Python39\python.exe
```

判别一行就够：

```powershell
python -c "import ssl;print(ssl.create_default_context().cert_store_stats())"
# 正常: x509_ca=70    空: x509_ca=0
```

### 还查不出来：`tools/netdiag.py`

它**把两条路分开测**：环境变量、`getproxies()`、信任库、直连握手、
**走代理握手（CONNECT 隧道）**、urllib 直连 / 走代理各一次，一次性列全：

| 现象 | 结论 |
| --- | --- |
| 5a 直连成功、5b 走代理失败 | 问题就在代理 → 关掉它的「HTTPS 解密」，或清掉 `ORBIPOM_USE_PROXY` |
| 5a / 5b 都失败，且第 4 节隧道证书 issuer 不是 TrustAsia | 真有中间人在解密（可能是 TUN / 网络层）→ 改 urllib 配置没用，必须关掉那个模式开关 |
| 5a / 5b 都失败，但第 4 节 issuer 是 TrustAsia、第 3 节正常 | 信任库问题 → 第 2 节 `x509_ca` 是不是 0；换官方版 Python |

> 关键点：**探测必须走和失败请求同一条路**。用裸 socket 直连去探，探到的是真服务器证书 ——
> 拿它下结论只会得出「偶发失败」的错误方向（这个坑踩过一次，已修）。

---

## 目录结构

```
.
├── cli.py                     # 核心：加解密 + 认人 + 改分数 + 奖励查询/领取
├── claim_all.py               # 一键获取奖励（import cli）
├── tools/
│   └── netdiag.py             # 网络诊断（两条路分开测）
├── docs/
│   └── 历史归档/               # 早期探索材料，保留备查
├── local/                     # 本地活动镜像 / 路由拦截（浏览器里改前端 JS）
├── mitm/                      # 中间人（改真实游戏客户端 WebView）
├── README.md
├── 技术分析报告.md
├── CHANGELOG.md
└── LICENSE
```

- **`local/`** —— 活动页在普通浏览器里会显示「网络异常」（它靠
  `window.WVSDK.platform` 判断自己是不是跑在游戏客户端里）。`local/` 把整套前端
  搬到本地跑，可以直接改 JS 刷新即生效。详见 [local/README.md](local/README.md)。
- **`mitm/`** —— 要改**游戏里看到的**，得让游戏客户端自己走我们的服务
  （hosts + 自签根证书 + 本地 443）。⚠️ 这是整机信任面的改动，且这台机器上跑着
  内核级反作弊，**用完务必还原**。详见 [mitm/README.md](mitm/README.md)。

---

## 文档

- **[技术分析报告.md](技术分析报告.md)** —— **修改分数** 与 **一键获取奖励** 两条
  路径的完整还原：密文结构与密钥推导、两步提交链路、请求头要求、服务端校验边界、
  五个任务的权威来源、`goldenAdmin` 为什么没有接口、`claim-all` 的 1300 语义、
  `u8_token` 来源与角色识别、实测记录、踩坑记录
- **[local/README.md](local/README.md)** —— 本地活动站 / 路由拦截的用法与补丁说明
- **[mitm/README.md](mitm/README.md)** —— 中间人的用法、踩过的坑与风险
- **[docs/历史归档/](docs/历史归档/)** —— 早期全量版报告（游戏逻辑还原、错误页归因等）
- **[CHANGELOG.md](CHANGELOG.md)** —— 变更记录（**含 2026-10-04 的破坏性改名说明**）

---

## 敏感文件说明

以下文件由工具运行时生成，**已在 `.gitignore` 中排除，切勿提交**：

| 文件 | 内容 |
| --- | --- |
| `.u8_token` | 活动会话令牌缓存 |
| `.u8_server` | 活动区服号 |
| `.u8_role` | 锁定的 roleId |
| `.u8_roles.json` | token → 角色身份对照表 |
| `mitm/certs/` | 中间人的 CA 私钥（泄漏即可伪造任意 HTTPS 站点） |

`u8_token` 本身就是一个会话凭据，**别贴到 issue、聊天记录或任何公开场合**。

---

## 免责声明

本项目仅用于个人账号的客户端行为分析与技术学习。

- 所有分析对象均为**客户端公开资源**（前端 JS bundle、本机游戏日志与 WebView 缓存）；
- 未涉及任何服务端入侵、越权访问或数据窃取；
- 请勿用于修改他人账号、刷榜或任何破坏游戏公平性的行为；
- 使用本工具产生的任何后果由使用者自行承担。

如有侵权，请联系删除。

---

## 许可证

[MIT](LICENSE) © 2026 3100549873

可自由使用、修改、分发甚至商用，但需保留版权声明；软件按「原样」提供，作者不承担任何后果。
