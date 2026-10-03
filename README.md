# 终末地 WebView 活动请求体加解密研究

《明日方舟：终末地》WebView 活动「融合！山团团！」(`orbipom-merge`) 的
请求体加解密与链路复现工具，配套一份完整的技术分析。

**单文件，零第三方依赖**，Python ≥ 3.6 即可运行。

---

## 快速开始

```bash
git clone https://github.com/3100549873/endfield-merge.git
cd endfield-merge
python orbipom.py
```

首次运行（需要一次短信验证）：

```
==============================================================
 鹰角 融合！山团团！(orbipom-merge) 全流程
==============================================================
[+] u8_token 来源: HAR <file>.har (584 chars)
[>] 手机号 (留空跳过): 138****8888
[>] 发送验证码到 138****8888 ...
    [+] 已发送，请查收短信
[>] 验证码 (留空跳过): 000000
[>] 登录中 ...
    [+] 登录成功  hgId=...
[>] 换取 oauth 凭据 ...
    [+] uid=...
    [+] 已缓存到 .account.json —— 下次运行不再需要验证码
[>] 分数: 12345
[>] role/login 建立会话 ...
    [+] 会话已建立 (cookie: v1d5-orbipom-merge)
[>] 加密完成  {"score":12345}
    d = <base64(iv || AES-GCM(score))>
[>] 提交分数 ...
    HTTP 200  {"code":0,"data":{"best":...,"isNewBest":...},"msg":""}
```

之后运行（凭据全部走缓存，**没有短信**）：

```
[+] u8_token 来源: 缓存 .u8_token (584 chars)
[+] 账号凭据: 缓存 .account.json（今天）  hgId=...
[>] 分数: 12345
[>] role/login 建立会话 ...
    [+] 会话已建立 (cookie: v1d5-orbipom-merge)
[>] 加密完成  {"score":12345}
[>] 提交分数 ...
    HTTP 200  {"code":0,"data":{"best":...,"isNewBest":...},"msg":""}
```

---

## 用法

### 全流程

```bash
python orbipom.py                              # 全交互（账号凭据优先读缓存）
python orbipom.py --phone 138****8888          # 预填手机号
python orbipom.py --phone 138****8888 --code 000000 --score 12345
python orbipom.py --score 12345 --u8 <token>   # 指定 u8_token，直接提交
python orbipom.py --har capture.har            # 指定抓包文件
python orbipom.py --no-login                   # 完全不碰账号，只提交分数
python orbipom.py --relogin                    # 忽略缓存，强制重新发短信登录
```

### 账号登录：只发一次短信

**提交分数只依赖 `u8_token`，账号登录并非必需。** 代码里 `submit_score()` 只读
`x-role-token`（即 `u8_token`），手机号 → 验证码 → `oauth` 那一整条链路是账号侧的
附带产物，不参与提交。

所以账号凭据做成了**可选 + 缓存**：

| 场景 | 行为 |
|---|---|
| 首次运行，无缓存 | 走一次短信流程，成功后写入 `.account.json` |
| 之后运行 | 直接复用缓存，**不再发短信**（默认有效期 30 天） |
| 缓存 token 失效 | `oauth_grant` 探活失败 → 自动清除缓存 → 重新走短信 |
| `--no-login` | 完全不碰账号，只提交分数 |
| `--relogin` | 忽略缓存，强制重新发短信 |

登录失败、不填手机号、不填验证码，**都不会阻断提交**，只打印一行提示继续走。

`u8_token` 解析优先级：

1. `--u8` 参数
2. `.u8_token` 缓存文件（首次取到后自动写入）
3. **自动发现抓包** —— 在 脚本目录 / `~/Downloads` / `~/Desktop` 下按修改时间
   倒序查找 `*.har`，取第一个能提取出 `u8_token` 的
4. 都没有则交互式提示粘贴一次

`u8_token` 就是活动链接里的 `?u8_token=XXXX` 参数，也可从游戏客户端
`role/login` 请求的 `x-role-token` 头或请求体 `token` 字段取得。

### 子命令

```bash
python orbipom.py selftest             # AES-GCM 官方向量自检
python orbipom.py key                  # 打印活动 AES 密钥
python orbipom.py encrypt '{"score":12345}'
python orbipom.py decrypt <base64>     # 也支持直接丢 {"d":"..."} 整个 body

python orbipom.py login sendcode 138****8888
python orbipom.py login phone    138****8888 000000
```

### 作为模块复用

```python
import orbipom

orbipom.selftest()                          # 跑官方向量
d = orbipom.encrypt({"score": 12345})       # → base64 字符串
orbipom.decrypt(d)                          # → {"score": 12345}

# 底层 AES-128-GCM（纯 Python，零依赖）
ct = orbipom.gcm_encrypt(key, iv, b"data")  # 返回 ciphertext || tag
pt = orbipom.gcm_decrypt(key, iv, ct)       # 校验 tag 后解密
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

- **[技术分析报告.md](技术分析报告.md)** —— 加密方案还原、攻击面评估、
  账号链路、实测记录、踩坑与方法论

---

## 敏感文件说明

以下文件由工具运行时生成，**已在 `.gitignore` 中排除，切勿提交**：

| 文件 | 内容 |
|---|---|
| `.u8_token` | 活动会话令牌缓存 |
| `.account.json` | 账号凭据（token / hgId / deviceToken / oauth），首次短信登录后落盘 |
| `.device.json` | 设备指纹（机器标识） |

`--har` 指向的抓包文件同样含会话凭据，不要放进仓库。

---

## 免责声明

本项目仅用于个人账号的客户端行为分析与技术学习。

- 所有分析对象均为**客户端公开资源**（前端 JS bundle、自己的抓包）；
- 未涉及任何服务端入侵、越权访问或数据窃取；
- 请勿用于修改他人账号、刷榜或任何破坏游戏公平性的行为；
- 使用本工具产生的任何后果由使用者自行承担。

如有侵权，请联系删除。

---

## 许可证

[MIT](LICENSE) © 2026 3100549873

可自由使用、修改、分发甚至商用，但需保留版权声明；软件按「原样」提供，作者不承担任何后果。
