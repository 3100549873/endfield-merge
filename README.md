# 终末地 WebView 活动请求体加解密研究

《明日方舟：终末地》WebView 活动「融合！山团团！」(`orbipom-merge`) 的  
请求体加解密与提交链路复现工具，配套一份完整的技术分析。

**单文件，零第三方依赖**，Python ≥ 3.6 即可运行。

---

## 快速开始

```bash
git clone https://github.com/3100549873/endfield-merge.git
cd endfield-merge
python orbipom.py --score 12345
```

首次运行（只需粘一次活动链接）：

```
[-] 需要 u8_token —— 它是提交分数的唯一凭证。
    u8_token / 活动链接 (留空则只生成密文，不提交): https://.../?u8_token=XXXX&server=1
    [+] 已缓存到 .u8_token（server=1）
[>] role/login 建立会话 ...
    [+] 会话已建立 (cookie: v1d5-orbipom-merge)
[>] 加密完成  {"score":12345}
    d = <base64(iv || AES-GCM(score))>
[>] 提交分数 ...
    HTTP 200  {"code":0,"data":{"best":...,"isNewBest":...},"msg":""}
```

之后运行（走缓存，**一行都不用输**）：

```
[+] u8_token 来源: 缓存 .u8_token (584 chars)  serverId=1
[+] 对应角色: 角色A (roleId=10000000000, uid=100000000)
[>] role/login 建立会话 ...
[>] 加密完成  {"score":12345}
[>] 提交分数 ...
    HTTP 200  {"code":0,"data":{"best":...,"isNewBest":...},"msg":""}
```

---

## u8_token 从哪来（**不需要抓包**）

提交分数只用 `u8_token`（活动接口的 `x-role-token`）。工具按下面的优先级  
**自动找**，只有全都找不到时才需要手动粘一次：

| 优先级 | 来源             | 说明                                                                     |
| --- | -------------- | ---------------------------------------------------------------------- |
| 1   | `--u8` 参数      | 手动指定，接受整条链接或纯 token                                                    |
| 2   | `.u8_token` 缓存 | 找到过一次就记住了                                                              |
| 3   | **游戏日志**       | `%USERPROFILE%\AppData\LocalLow\Hypergryph\<游戏>\sdklogs\HGWebview.log` |
| 4   | **CEF 缓存**     | `%LOCALAPPDATA%\PlatformProcess\Cache\data_1`                          |
| 5   | 手动粘贴           | 以上都没有时的兜底                                                              |

**关键：只要你在游戏里点开过一次该活动页，第 3/4 步就能自己拿到 token。**

- 第 3 步 —— 游戏客户端每次打开 WebPortal，都会把带 `u8_token` 的完整链接  
  以 `WebPortal url: https://ef-webview...` 的形式写进日志。
- 第 4 步 —— webview 是 Chromium 内核，活动页 URL 会落进 CEF 缓存。  
  该文件被进程占用，普通读取会 `Permission denied`，脚本用 `CreateFileW`  
  显式声明 `FILE_SHARE_READ|WRITE|DELETE` 才能读到（等价于 PowerShell 的 `Copy-Item`）。

---

缓存里有多个 token 时，怎么知道是哪个号

换过账号之后，日志和 CEF 缓存里会同时躺着好几个 `u8_token`。它们**都还有效**，  
但属于**不同角色** —— 只按「谁在文件里更靠后」去猜会猜错，把分提交到别人号上。

一个 token 只对得上一个角色，所以工具改成用 `role/sync` **认人**：

```
POST /api/role/login   { "token": "<u8_token>", "serverId": "1" }   → 拿会话 cookie
POST /api/role/sync    {}                                           → {roleId, nickname, uid, avatar}
```

`role/sync` 必须先有会话 cookie，否则返回 `401 {"reason":"UN_LOGIN"}`。

认出来之后按下面的规则挑，**绝不瞎猜**：

| 情况                      | 行为                |
| ----------------------- | ----------------- |
| 本机只有一个角色                | 直接用，不问            |
| 本机有多个角色                 | 列出来让你选，直接回车则放弃    |
| 已锁定 / `--role <roleId>` | 直接挑该 roleId 对应的那个 |

身份结果缓存进 `.u8_roles.json` —— 一个 token 只认一次，之后每次运行零网络开销，  
也不会把服务端敲到限流。每次成功提交后会自动锁定本次角色到 `.u8_role`，  
下次即使缓存里混着别的号，也会自动挑回同一个角色。

实测本机 6 个候选就是这样分成两拨的：

```
角色 A (roleId=10000000000, uid=100000000)  ← CEF[1] + CEF[3] + CEF[4] + CEF[5]
角色 B (roleId=10000000000, uid=100000000)  ← CEF[2] + CEF[6]
```

---

## 接口契约

活动侧只有两个接口。第一步拿 `u8_token` 换会话 cookie：

```http
POST /act-server/orbipom-merge/api/role/login
content-type: application/json
x-role-token: <u8_token>
x-role-server-id: 1

{ "token": "<u8_token>", "serverId": "1" }
```

**`token` 在请求头和请求体里各出现一次，两处都要带。** 成功后服务端下发会话  
cookie（`v1d5-orbipom-merge`，有效期 7 天），紧接着提交分数：

```http
POST /act-server/orbipom-merge/api/save/score
{ "d": "<base64(iv || AES-128-GCM({\"score\":N}))>" }
```

两步缺一不可：跳过 `role/login` 直接提交会因为拿不到会话 cookie 而失败。

`u8_token` 绑在游戏角色上，换角色必须清掉缓存，否则分数会继续提交到旧角色：

```bash
python orbipom.py reset
```

---

## 实现要点

**AES-128-GCM 为纯 Python 实现**，S-box 由 GF(2⁸) 求逆 + 仿射变换程序化生成，  
避免手抄 256 个常量出错。正确性由三层验证保证：

1. FIPS-197 AES-128 分组向量 + NIST SP 800-38D GCM 官方向量
2. 与 `cryptography` 库在固定密钥/IV 下逐位比对（8 个用例，含 0/16/17/64/200 字节边界）
3. 真实提交被服务端接受

> 开发中正是靠官方向量自检抓出了「GCM 的 CTR 计数器应从 `inc32(J0)` 起算」  
> 这一处实现错误 —— 空明文用例会掩盖该 bug，边界用例缺一不可。

---

## 文档

- **[技术分析报告.md](技术分析报告.md)** —— 加密方案还原、活动接口契约、  
  攻击面评估、`u8_token` 来源与角色识别、实测记录、踩坑与方法论

---

## 敏感文件说明

以下文件由工具运行时生成，**已在 `.gitignore` 中排除，切勿提交**：

| 文件               | 内容              |
| ---------------- | --------------- |
| `.u8_token`      | 活动会话令牌缓存        |
| `.u8_server`     | 活动区服号           |
| `.u8_role`       | 锁定的 roleId      |
| `.u8_roles.json` | token → 角色身份对照表 |

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
