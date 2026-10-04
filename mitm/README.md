# 中间人（MITM）—— 让**游戏客户端自己**走我们的接口

前面几条路都改不了真实游戏：

| 方式 | 作用范围 |
| ---- | -------- |
| `local/` + `serve.py` | 你浏览器打开的**页面副本** |
| `local/intercept.py` | 脚本拉起的**那个浏览器** |
| **`mitm/`（本目录）** | **任意进程**，包括游戏客户端的 WebView |

原理是标准三件套：

```
hosts:  127.0.0.1 ef-webview.hypergryph.com
本地:   443 上起一个 HTTPS 服务，用自签 CA 签发的证书冒充该域名
信任区: 把这张 CA 装进「受信任的根证书颁发机构」
```

页面、JS、CSS 全部**从上游原样回传**（实测 sha256 逐字节一致），
改写两处：

| 改什么 | 位置 | 效果 |
| ------ | ---- | ---- |
| **接口响应** | `/api/save/profile`、`/api/save/score` 的 `highScore`/`best` | 首页那个「最高分」 |
| **前端 JS** | 得分表 / `maxScore` / 单局结算阈值 / 10 秒看门狗 / **合成逻辑** / **出块等级** | 一局能打到多少分、**怎么合** |

## 文件

```
mitm/
  mitm.py         生成证书 + HTTPS 反向代理（接口改写 + 前端 JS 补丁）
  trust.py        系统侧：hosts 与根证书的安装/还原（默认只预览）
  check.py        一条命令查完链路：hosts / 解析 / 证书 / 监听 / 接口改写 / 前端 JS
  regress.py      回归测试：304 缓存短路 + 出块补丁有没有误伤（需配合 mock）
  mock_upstream.py 本地 mock 上游（复刻两个域名的行为），测试改写逻辑用，不碰外网
  certs/          自签 CA 与服务器证书（已 .gitignore，私钥别外传）
  hosts.bak       首次 --install --apply 时自动生成的 hosts 备份
```

## 用法

```bash
cd output/mitm

python mitm.py --gencert            # 1. 生成 CA + 服务器证书（已生成可跳过）
python trust.py --status            # 2. 先看系统当前状态（只读）
python trust.py --install           # 3. 预览会改什么（不改）
python trust.py --install --apply   # 4. 真的改（需要管理员）

python mitm.py --port 443           # 5. 起服务（443 需要管理员）

python check.py                     # 6. **先自检，再开游戏**
# 进游戏 → 打开「融合！山团团！」→ 看首页「最高分」

# ...用完还原
python trust.py --uninstall --apply
```

> **一定要跑 `check.py`。** 中间人链路有五个环节，任何一环断了游戏里都只显示
> 「网络异常」，看不出断在哪。`check.py` 会直接告诉你是哪一环。
> 它会自动读上级目录的 `.u8_token`，有的话就顺带做**带鉴权**的端到端验证。

> 443 被占用时，先确认没有别的服务在跑；`netstat -ano | findstr :443`。
> 注意：如果之前起过一个旧版 `mitm.py` 忘了关，**它会把 443 占着**，
> 新起的那个会静默失败（Windows 的 `SO_REUSEADDR` 允许重复绑定，先绑的赢）。
> 我调试时自己就撞了两次。

## 前端 JS 补丁（改「单局分数上限」）

活动页的 JS **不在** `ef-webview.hypergryph.com` 上，而在 `web.hycdn.cn` 这个
**共享 CDN** 上（线上 HTML 里 `web.hycdn.cn` 出现 **377 次**）。直接劫它会
把游戏其它内容一起卷进来，所以走「**同域中转**」：

```
1. 页面 HTML / JS 里的 https://web.hycdn.cn/endfield/webview/
   改写成      https://ef-webview.hypergryph.com/__cdn/endfield/webview/
2. 客户端来取 /__cdn/... 时，中间人再去 web.hycdn.cn 取回原内容
   （是 JS 就顺手打补丁）转给客户端
```

**只劫一个域名，而且只影响这个活动页。** 共享库（如 React UMD）不动，仍从 CDN 直取。

打的是**六处**（规则与 `local/patch_score.py` **共用同一套正则**，改版只修一处）：

| 位置 | 原值 | 默认改成 |
| ---- | ---- | -------- |
| `eS=[1,3,6,10,15,21,28,36,45,55,66]` | 每级得分 | ×100 |
| `ey.maxScore:99999` | 硬性夹取上限 | 9999999 |
| `r.score<1500&&e.score>=1500` | **真正的单局上限**（跨过就自动结算） | 99999999 |
| `"playing"===r&&n>i&&0===e&&t()` | 10 秒自动结算看门狗 | 关掉 |
| `h=d?ek:r.level+1` | `processMerges()` 的新等级计算 | `h=d\|\|1===r.level?ek:r.level+1` |
| `spawnLevelMin:1,spawnLevelMax:5` | `ey` 里的出块等级区间 | `1,1`（只出最小的） |

```bash
python mitm.py --port 443                    # 接口 + 前端 JS 都改
python mitm.py --port 443 --no-js-patch      # 只改接口，不碰 JS
python mitm.py --port 443 --js-scale 1000    # 得分放大 1000 倍
python mitm.py --port 443 --keep-autosettle  # 保留 10 秒看门狗
python mitm.py --port 443 --no-mega-merge    # 保留原合成逻辑（1+1=2）
python mitm.py --port 443 --spawn-level 2    # 固定出 2 级
python mitm.py --port 443 --keep-spawn       # 保留原出块区间（1~5 随机）
```

> 关掉看门狗是必须的：它是「只要当前分 > 历史最高分就结算」，抬了得分表之后
> 一局只撑 10 秒。

### 「两只最小的直接合成最高级」

`processMerges()` 里真正决定新等级的就是一行三元表达式：

```js
var d = r.level === ek,          // ek = 等级总数（实测 11），d = 已经是最高级
    h = d ? ek : r.level + 1,    // 新等级
    ...
if (d) renderer.playMergeFadeOut(g);          // 最上级互撞：只淡出，不生成
else { ... this.phys.spawn(h, v.x, v.y, …) }  // 其余：真的生成一只 h 级
```

补上 `||1===r.level` 之后，源等级是 1 时 `h` 直接取 `ek`；而 `d` 仍然是 `false`，
所以走 `spawn` 分支，**真的会生成一只 11 级**（不会掉进 `playMergeFadeOut` 那条路）。
`eM(h)` 内部有 `Math.min(Math.max(round(h),1),ek)` 夹取，`h=ek` 不越界。

**必须同时钉死出块等级，否则等于没改。** 出块等级由 `ey` 的区间决定：

```js
nextSpawnLevel(){ var {spawnLevelMin:e,spawnLevelMax:t}=ey, r=t-e+1,
                  n=e+Math.floor(Math.random()*r), ... }
```

原区间是 `1~5`。出一只 3 级，就得再等一只 3 级才能合 —— 而 3+3 走的还是原来的 `+1`。
所以默认把两个都钉成 1：`r = 1`，`n` 恒为 1，`r>1&&…` 那条「防三连」分支也不会生效。
（`lT` 里另有一行 `spawnLevelMin:ey.spawnLevelMin,…` 是 devtools 面板的基线快照，
写的是 `ey.xxx` 而不是数字，正则只认数字，**不会被误改** —— `regress.py` 专门验这条。）

两个副作用，都是**故意保留**的：

- **加的分按源等级算**。`processMerges` 调的是 `t.onMerge(h, r.level)`，
  而 store 里是 `eM(r).score` —— `r` 是**源**等级，所以 1+1 只加 1 级的分
  （原值 1 分，×100 后是 100 分）。想要「合一次就爆分」就把 `--js-scale` 调大。
- `h===ek` 会触发 `onGolden` 回调（最高级的金色特效），这是正常的。

> ⚠️ **改完 JS 一定要「重新进一次活动」。** 活动页 HTML 会被客户端缓存，
> 不重进的话它拿的是缓存的**原始** HTML —— 里面的 JS 地址还是 `web.hycdn.cn`，
> JS 根本不经过中间人，日志里连一个 `/__cdn/` 请求都不会有。
> 判断标准很简单：日志里出现 `[页面] CDN前缀×N 转本域` 和 `/__cdn/...` 请求，
> 才说明这次真的走了新路径。见「踩过的坑 11」。

## 已验证的部分

| 项 | 结果 |
| -- | ---- |
| TLS 握手（`openssl s_client`） | ✅ 证书链 `CN=ef-webview.hypergryph.com`，能正常回源 |
| 页面透传 | ✅ `HTTP 200`，与线上 **sha256 完全一致**，`content-encoding: gzip` 原样保留 |
| 接口改写 | ✅ `profile`/`score` 的 `highScore`/`best` → 9999999；`rank` 不动 |
| **带鉴权端到端** | ✅ `role/login` 拿 cookie → `save/profile` → `best/highScore = 9999999` |
| 页面 CDN 前缀改写 | ✅ 活动资源转 `ef-webview.hypergryph.com/__cdn/...`；React UMD 仍在 CDN（有意） |
| **前端 JS 补丁（经 `/__cdn/`）** | ✅ 六处全中：`eS`→×100、`maxScore`→9999999、结算阈值→99999999、看门狗关闭、`1+1=最高级`、出块区间→`1,1` |
| **带条件头的改写（防 304 短路）** | ✅ `regress.py` 14 项全过：带 `If-None-Match` 打页面/JS 仍是 200 + 已改写，且响应里没有 `ETag`、带 `no-store` |
| **出块补丁不误伤 devtools 基线** | ✅ `lT` 里的 `spawnLevelMin:ey.spawnLevelMin,…` 原样保留 |
| 垫片注入（`--inject-shim`，调试用） | ✅ gzip 页面解压后注入成功 |
| 上游 IP 解析（裸 UDP DNS） | ✅ `[DNS] ef-webview.hypergryph.com -> 43.145.18.240 (via 223.5.5.5)` |
| CA 真的进了系统信任区 | ✅ 用**默认**校验（不 `-k`）请求 `https://ef-webview.hypergryph.com:8443/` 能过 TLS |
| hosts 劫持能打到游戏客户端 | ✅ 游戏运行时 `netstat` 里出现 `Endfield.exe` / `QtWebEngineProcess.exe` 发往 `127.0.0.1:443` 的连接 |

**没验证的部分**：游戏客户端是否对 `ef-webview.hypergryph.com` 做**证书固定（pinning）**。
理论上不该做（CEF / QtWebEngine 默认走 Windows 证书库），但只有真机跑一遍才知道。

### 本地 mock 测试（不碰外网）

`--upstream-ip/--upstream-port` 与 `--cdn-ip/--cdn-port` 可以把上游指到本地 mock，
用来验证改写逻辑本身（`mock_upstream.py` 复刻了两个域名的行为）。
mock 的证书要能冒充 `web.hycdn.cn`，所以额外签一个 SAN：

```bash
# 1) mock 上游（同时冒充两个域名，按 Host 头分流）
python mock_upstream.py --port 9443

# 2) 中间人指到 mock
python mitm.py --gencert --force --extra-san web.hycdn.cn
python mitm.py --port 8443 --upstream-ip 127.0.0.1 --upstream-port 9443 \
                          --cdn-ip 127.0.0.1 --cdn-port 9443

# 3) 自检 + 看 JS 有没有被打补丁
python check.py --port 8443
# 4) 回归测试：304 短路 + 出块误伤（check.py 覆盖不到的两类）
python regress.py --port 8443
# 测完记得恢复成最小 SAN（CA 不会被换）
python mitm.py --gencert --force
```

**`check.py` 和 `regress.py` 的分工**（这个区别很关键）：

| | `check.py` | `regress.py` |
|--|-----------|--------------|
| 怎么请求 | **直连**中间人，不带条件头 | **带 `If-None-Match`**，模拟真实客户端 |
| 能发现 | 链路断在哪、改写有没有生效 | **304 缓存短路**、补丁误伤 |
| 局限 | 不带条件头，所以**它绿了不代表游戏里绿** | 需要 mock 在跑 |

真实的「JS 改了没生效」就是 `check.py` 全绿、游戏里却没反应 ——
因为客户端带 `If-None-Match` 拿到 304，用自己缓存的原始 HTML 跑。见「踩过的坑 11」。


## 踩过的坑

### 1. 上游页面是 gzip 预压缩的

存在 OSS 里，带 `content-encoding: gzip`、**没有** `content-length`。
第一版把 `content-encoding` 头剥掉却原样转发压缩体 —— 浏览器直接乱码。
现在 `rewrite()` 返回 `(body, modified)`，**没动过 body 就原样保留编码**，
只有真的改过才丢 `content-encoding`。

### 2. 自环（最坑的一个）

hosts 把域名指到 `127.0.0.1` 之后，**中间人自己**去连上游也会被劫到本地，
变成「自己连自己」。表现是：

```
502 upstream failed: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed:
    unable to get local issuer certificate
```

看起来像证书问题，其实是自环。

修法：**解析出真实 IP，直接连 IP，SNI / Host 仍然是真实域名。**

```python
raw   = socket.create_connection((UPSTREAM_IP, 443), timeout=30)
ssock = ctx.wrap_socket(raw, server_hostname=HOST)
conn  = http.client.HTTPSConnection(HOST, 443, timeout=30, context=ctx)
conn.sock = ssock          # 预置 sock，request() 就不会再自己 connect
```

顺带把 `orbipom.py` 也保护了：它现在有个 `bypass_hosts()`，
检测到域名被解析到回环就自动改直连真实 IP，不会再被自己的 hosts 打死。

### 3. 拿不到上游 IP：DoH 在这台机器上用不了

原来只用 DoH（`dns.alidns.com` / `doh.pub` / `cloudflare-dns.com`），实测全挂：

```
[DNS] dns.alidns.com 失败: unable to get local issuer certificate
[DNS] doh.pub 失败: self-signed certificate in certificate chain
[DNS] cloudflare-dns.com 失败: [WinError 10054] 远程主机强迫关闭了一个现有的连接。
```

DoH 走 HTTPS，而这条链路上有中间人（证书链不干净），所以 TLS 那层过不去。
**改用裸 UDP DNS**（`223.5.5.5` / `119.29.29.29` / `114.114.114.114` / `8.8.8.8`），
不过 TLS，反而干净。`dns_query_a()` 是手搓的 DNS 报文，DoH 只作兜底。

实在不行还能手动指定：`python mitm.py --port 443 --upstream-ip <真实IP>`。

### 4. TLS 握手不能放在 `accept()` 里

第一版把 `ssl_ctx.wrap_socket()` 套在**监听 socket** 上，结果握手在 `accept()` 里
**串行**执行 —— 只要有一个连接卡住（扫描器、半开连接、探测），后面全堵死。
（当时的症状：8443 好好的，443 握手超时，代码一模一样。）

修法：`ssl_ctx` 存在 `Server` 上，在 `Handler.setup()` 里 **每个连接自己的线程**
做握手，并让 `handle_one_request()` 吞掉 `SSLError` / `OSError`。

### 5. `certutil` 的两个本地化陷阱（`trust.py --status` 误报）

中文 Windows 上 `certutil` 的输出是中文的，两个坑：

- 不能用英文标记 `"Cert Hash"` 判断 —— 中文版是「证书哈希(sha1)」，会误报「未装」。
- **命中时输出里会带一句 `找不到解密的证书和私钥。`** —— 那只是说这张证书没配私钥，
  和「找没找到证书」无关。用裸的 `"找不到"` 判断会把**命中判成未命中**。

现在只依赖不随语言变的两样：`rc == 0`，以及证书主体里的 `"Orbipom"`。

### 6. `--status` 显示「用户库/机器库」都装了

实测两个库里都有（装机时两边都进去过）。所以 `--uninstall` 现在**两个库都清**，
只清一边会留残留。

### 7. MSYS2 的 Python 看不到 Windows 证书库

用 `C:\msys64\mingw64\bin\python.exe` 测「CA 有没有被信任」会得到**假阴性**
（`TLSV1_ALERT_UNKNOWN_CA`），因为它用的是自带的 CA 包
（`ssl.get_default_verify_paths().cafile` 不为 `None`），根本不读 Windows 存储。
官方版 Python（python.org）才走 `enum_certificates` → Windows 存储。

`check.py` 会检测这一点并直接警告你换 Python。

### 8. 纯浏览器里显示「网络异常」是正常的

因为浏览器没有 `WVSDK`（那个桥由游戏原生 SDK 提供）。调试时用 `--inject-shim` 补上即可，
**真实游戏里千万别开**，它会覆盖掉真正的 SDK。

### 9. `--gencert --force` 曾经会把 CA 一起换掉（已修）

原来的 `gencert()` 不管 `--force` 是什么语义，都无条件重新生成 CA。
后果很隐蔽：系统里装的那张 CA 立刻作废，客户端报 `unknown ca`，
而 `--status` 还显示「已装」，看起来一切正常。**实测踩过，整条链路全挂。**

现在 `--force` 只重签**服务器证书**，CA 默认复用；
真要换 CA 得显式加 `--force-ca`，并且会提示必须重新 `trust.py --install --apply`。

配套地：

- `trust.py --status` 现在会比对「系统里装的指纹」和「当前 `ca.crt` 的指纹」，
  不一致就明确报警 —— 只报「装没装」是不够的。
- `trust.py --uninstall` 会删掉**所有** Orbipom CA（不只是当前这张）。
  换过 CA 的机器上会留旧的，而旧 CA 照样能签发任意站点证书，是实打实的安全残留。

### 10. 换 CA 之后机器库可能删不掉

`certutil -delstore Root <指纹>`（不带 `-user`）需要管理员。
用户库不需要，机器库需要。删不掉就先记着，别以为已经清干净了。

### 11. JS 没被改的真正原因：客户端的 304 缓存（最坑的一个）

改完 JS 补丁，游戏里「单局上限」纹丝不动，日志长这样：

```
"GET /act/orbipom-merge/?u8_token=...&channel=1&lang=zh-cn&platform=Windows HTTP/1.1" 304 -
[接口] /act-server/orbipom-merge/api/save/profile <- 200  ✅ 改写 99999 -> 9999999
（一个 /__cdn/ 请求都没有）
```

「接口改成功了、页面也是我们回的」→ 第一反应会以为正则写错了。
其实正则没错，**是客户端压根没用我们的 HTML**：

1. 活动页 HTML 存在 OSS 上，带 `ETag`，客户端第一次取过之后就有缓存了；
2. 之后每次请求都带 `If-None-Match`，上游回 **304**，客户端就用**自己缓存的那份**；
3. 缓存里是**原始** HTML —— 里面的 JS 地址还是 `https://web.hycdn.cn/...`；
4. 于是 JS 直连 CDN 取，**不经过中间人**，补丁当然不生效。

注意日志里的 `304 -` 是**中间人自己**打印的：它老老实实把条件请求转给了上游，
上游回 304，它就回 304 —— 改写逻辑（`rewrite()`）在 304 分支里根本没机会跑。

修法（`needs_fresh()` + `DROP_COND`）：

```python
# 请求侧：这些条件头会让上游回 304，直接丢掉
DROP_COND = {"if-none-match", "if-modified-since", "if-range", "if-match",
             "if-unmodified-since"}

def needs_fresh(target):          # 哪些请求必须拿到 200 的完整 body
    if any(p in target for p in FAKE_PATHS):   return True
    if "orbipom-merge" not in target:          return False
    return target.endswith(".js") or target.startswith("/act/orbipom-merge")
```

- 命中 `needs_fresh()` → 请求里**剥掉** `If-*`；响应里**丢掉** `ETag` /
  `Last-Modified` / `Expires`，换成 `Cache-Control: no-store, no-cache, must-revalidate`
  + `Pragma: no-cache`。客户端下次就不会再拿缓存来问。
- 没命中的（CSS、图片、字体）**照旧**透传 `ETag`，不要为了这个把整个站点变成不可缓存。

回归测试（`mock_upstream.py` 会按 `md5` 出稳定 ETag 并支持 304）：

```
=== 经中间人：带 If-None-Match 打页面（必须仍是 200 + 改写后的 body）===
   HTTP 200 | /__cdn/ 出现 2 次 | 残留 web.hycdn.cn 1 次
   etag 透给客户端了吗: None | cache-control: no-store, no-cache, must-revalidate
=== 经中间人：带 If-None-Match 打玩法 JS（必须仍是 200 + 已打补丁）===
   HTTP 200 | maxScore: True | eS 已放大: True
```

> 顺带说明为什么 `check.py` 只跑本地 `--port 8443` 也能发现：`check.py` 是**直连**中间人
> 抓页面和 JS 的，不带 `If-None-Match`，所以它一直显示绿的 —— **自检绿 ≠ 游戏里生效**。
> 这也是为什么加了第 6 步，并且要求它先验「页面 `<script src>` 里还有没有 `web.hycdn.cn`」。

### 12. `ssl.SSLEOFError` 刷屏（不是错误，是噪音）

客户端探测 / 半开连接会在 `setup()` 里就抛 `SSLEOFError`，
而 `handle_one_request()` 的 `try` 还没进去，所以捕获不到，直接打整段 traceback。
在 `Server.handle_error()` 里吞掉即可：

```python
def handle_error(self, request, client_address):
    exc = sys.exc_info()[1]
    if isinstance(exc, ssl.SSLError):
        sys.stderr.write("  [连接] TLS 握手未完成（%s），已忽略\n" % type(exc).__name__)
        return
    if isinstance(exc, (ConnectionError, OSError)):
        return
    super().handle_error(request, client_address)
```

## ⚠️ 风险

1. **装根证书是整机信任面的改动。** 私钥就在 `certs/ca.key`，谁能读到它，
   谁就能伪造**任意** HTTPS 站点。用完立刻 `--uninstall --apply`。
2. **这台机器上装着 ACE（AntiCheatExpert）内核级反作弊**：
   `games/Endfield Game/AntiCheatExpert/ACE-BASE.sys`、`ACE-CORE.sys`。
   改 hosts + 装根证书恰好是反作弊最敏感的一类系统改动，**有被判定的风险**。
   改前端 JS 也一样 —— 那是在改客户端运行时行为。
3. 只劫 `ef-webview.hypergryph.com` 一个域名，但它同时也是活动页与活动接口的域名。
   **用完记得还原**，否则游戏里这个活动会一直连不上（因为本地 443 关了）。
   前端 JS 走 `/__cdn/` 同域中转，**不需要**额外劫 `web.hycdn.cn`。
4. 服务端本来就把分数夹在 99999（见技术分析报告 §4.2），
   所以**显示的分数变了也不会被记账** —— 改的是「看到什么」，不是「存了什么」。
   把前端结算阈值抬到 99999999 也一样：一局能刷到几百万，提交上去服务端照样按 99999 封顶。
