# 变更记录

本仓库按「能被别人拿去用」的粒度记变更。版本号只为方便引用，不代表 API 稳定性承诺。

---

## 未发布

### 计划中

- 把 `local/` 的前端镜像流程改成可复现（当前 `fetch.py` 依赖线上 chunk 哈希，
  官方换版本就会失效）
- `mitm/` 增加「用完自动还原」的一键回收，降低忘记 `trust.py --uninstall` 的风险

---

## 2026-10-04

### 变更（破坏性）

**脚本改名** —— 旧名字表达不出用途，且两个脚本容易混：

| 旧 | 新 | 说明 |
| --- | --- | --- |
| `orbipom.py` | **`cli.py`** | 核心：加解密 + 认人 + 改分数 + 奖励查询/领取 |
| `orbipom_full.py` | **`claim_all.py`** | 一键获取奖励 |
| `netdiag.py` | **`tools/netdiag.py`** | 独立小工具 |

`git log --follow cli.py` 可以追到改名之前的全部历史。

**兼容处理**：`claim_all.py` 不再硬编码 `import orbipom`，改为按 `cli` → `orbipom`
顺序查找 —— 如果你的目录里还躺着旧文件名，照样能跑，不会因为一次改名就报 ImportError。

### 变更（目录）

```
cli.py / claim_all.py     顶层（必须放同一目录）
tools/netdiag.py          独立小工具
docs/历史归档/             早期全量版报告（保留备查）
local/                    本地活动镜像 / 路由拦截
mitm/                     中间人（改游戏客户端）
```

### 变更（文档）

- **`README.md`** 重写 —— 只讲两条在用的路径（**修改分数** / **一键获取奖励**），
  加上三类证书报错的排查（hosts 劫持、代理解密 TLS、**信任库为空**）
- **`技术分析报告.md`** 重写 —— 聚焦同一组路径：密文结构与密钥推导、两步提交链路、
  请求头要求、服务端校验边界、五个任务的权威来源、`goldenAdmin` 为什么没有独立接口、
  `claim-all` 的 `1300` 语义、`u8_token` 来源与角色识别
- 早期全量版报告（含游戏逻辑还原、PC 浏览器错误页归因、中间人改客户端等）
  移入 `docs/历史归档/`
- 两份文档里的账号名与 roleId 全部脱敏

### 修复

| 问题 | 影响 | 修法 |
| --- | --- | --- |
| **证书探测走了另一条路** | 请求走代理、却用裸 socket 直连去探证书 —— 探到的是**另一张**证书，据此输出「偶发失败」把排查方向带偏 | 新增 `_connect_via_proxy()`，探测改为沿**同一条路**（CONNECT 隧道）握手 |
| **MSYS2 的 Python 信任库为空** | Windows 有效 PATH 是「系统段 + 用户段」拼接，`C:\msys64\mingw64\bin` 常排在官方版 Python 前面 ⇒ 裸 `python` 命中 MSYS2 那个。而它**不读 Windows 证书存储**（没有 `ssl.enum_certificates`），OpenSSL 又指向空的 `mingw64\etc\ssl\cert.pem` ⇒ 所有 HTTPS 报 `self-signed certificate in certificate chain`，看着像被中间人劫持 | `_ssl_context()` 检测到 `x509_ca == 0` 时自动补根证书（先读 Windows ROOT，再退到 msys64/Git 的 `ca-bundle.crt`、`certifi`）；补不上就明确提示换解释器（`py -3`） |
| `.gitignore` 被误删 | 若不补回，`git add -A` 会把 `.u8_*` 凭据、`mitm/certs/` 私钥、`local/site/` 镜像一起收进去 | 重建并补全忽略规则 |

### 验证

- `cli.py selftest` —— AES-128-GCM 对 FIPS-197 / NIST SP 800-38D 官方向量全部匹配
- `claim_all.py --selftest` —— **28/28 通过**（不联网、不碰账号）
- 两个 `--dry-run` 在三种解释器下均正常：Python 3.9.9 / 3.13.14 / MSYS2 3.12.12
- 提交前扫描确认：无凭据、无私钥、无镜像

---

## 2026-10-03

### 新增

- **奖励接口全链路**：`/api/reward` 查询、`/api/reward/claim` 单个领取、
  `/api/reward/claim-all` 一键领取；搞清 `status` 共享枚举
  （`0=CLAIMED`、`1=DELIVERED`，未完成时列表里是 `null`，**从不返回 0**）
  与 `claim` 的幂等语义
- **`goldenAdmin` 的真相**：它**没有独立接口**，由 `save/merge` 响应里的
  `unlockedMax >= 11` 在前端推导。只刷合成次数点不亮这个任务
- **`claim-all` 的边界语义**：无奖可领时不是返回空 `results`，而是报
  `{"code":1300,"msg":"NO_REWARD_TO_CLAIM","data":{}}` —— `data` 是 `{}`（JS 真值），
  所以前端判成功靠的是 `code`
- **合成等级表（11 级）与技能表**的完整还原
- **`u8_token` 本机自动获取**：从游戏日志 `HGWebview.log` 与 CEF 缓存里找，
  不再需要抓包；用 `role/sync` 认人解决多 token 歧义

---

## 2026-10-02

### 新增

- **AES-128-GCM 纯 Python 实现** —— S-box 由 GF(2⁸) 求逆 + 仿射变换程序化生成，
  不手抄 256 个常量
- **请求体加密方案的完整还原** —— `d` 字段 = `base64(iv(12) ‖ ciphertext ‖ tag(16))`，
  密钥由两段常量拼接后 `importKey("raw", …, "AES-GCM", …)` 导入
- **分数提交链路** —— `role/login` 换会话 cookie → `save/score` 提交密文；
  服务的响应给的是 `best`（历史最高，只升不降）而非本次提交值
- **服务端校验边界实测** —— 分数钳到 `99999`，范围外与非整数的处理
- **仓库建立** —— MIT 许可证、LF 换行统一

### 已知限制

- 密钥硬编码在前端 bundle 里，所以加密**只防篡改、不防伪造**；
  真正的访问控制只有 `u8_token`
- 服务端限流会**直接断连**（`RemoteDisconnected`，不给任何响应），
  而不是返回错误码 —— 密集写请求必须自带间隔
