#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
《明日方舟：终末地》WebView 活动「融合！山团团！」(orbipom-merge)
请求体加解密 + 账号链路复现工具。

自包含单文件，零第三方依赖，Python >= 3.6。

用法:
    python orbipom.py                              # 全交互（账号凭据优先读缓存）
    python orbipom.py --phone 138****8888          # 预填手机号
    python orbipom.py --phone 138****8888 --code 000000 --score 12345
    python orbipom.py --score 12345 --u8 <token>   # 指定 u8_token，直接提交
    python orbipom.py --har capture.har            # 指定抓包文件
    python orbipom.py --no-login                   # 完全不碰账号，只提交分数
    python orbipom.py --relogin                    # 忽略缓存，强制重新发短信登录

缓存文件（均在 .gitignore 内，勿提交）:
    .u8_token      活动会话令牌
    .account.json  账号凭据（首次短信登录后落盘，默认复用 30 天）
    .device.json   设备指纹

注意: 提交分数只依赖 u8_token，账号登录并非必需。
      --no-login 可完全跳过短信流程。

加密方案（还原自前端 chunk 821.js）:
    d = base64( iv(12) || AES-128-GCM(key, iv, JSON.stringify(payload)) )
    key = T[i] ^ N[i]     # T/N 为前端硬编码常量数组
"""

import argparse
import base64
import glob
import gzip
import http.cookiejar
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

# 账号域
AS = "https://as.hypergryph.com"
APP_CODE = "dd7b852d5f1dd9da"
# 活动域
ACT = "https://ef-webview.hypergryph.com/act-server/orbipom-merge"
SERVER_ID = "1"

U8_CACHE = os.path.join(HERE, ".u8_token")
DEVICE_FILE = os.path.join(HERE, ".device.json")
ACCOUNT_FILE = os.path.join(HERE, ".account.json")
ACCOUNT_TTL = 30 * 86400          # 账号凭据缓存有效期：30 天

OK, NO, AR = "[+]", "[-]", "[>]"


# ============================================================ AES-128-GCM ===
# 纯 Python 实现。S-box 程序化生成（GF(2^8) 求逆 + 仿射变换），避免手抄常量出错。
# 正确性由 FIPS-197 与 NIST SP 800-38D 官方向量校验，见 selftest()。


def _gmul(a, b):
    """GF(2^8) 乘法，模 x^8 + x^4 + x^3 + x + 1 (0x11B)。"""
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


def _build_sbox():
    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _gmul(a, b) == 1:
                inv[a] = b
                break

    def rotl8(x, n):
        return ((x << n) | (x >> (8 - n))) & 0xFF

    box = [0] * 256
    for a in range(256):
        s = inv[a]
        box[a] = (s ^ rotl8(s, 1) ^ rotl8(s, 2) ^ rotl8(s, 3) ^ rotl8(s, 4) ^ 0x63) & 0xFF
    return box


SBOX = _build_sbox()
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _expand_key(key):
    """AES-128 密钥扩展，返回 11 组 16 字节轮密钥。"""
    if len(key) != 16:
        raise ValueError("AES-128 需要 16 字节密钥")
    w = [[key[i * 4 + j] for j in range(4)] for i in range(4)]
    for i in range(4, 44):
        t = w[i - 1][:]
        if i % 4 == 0:
            t = t[1:] + t[:1]                          # RotWord
            t = [SBOX[b] for b in t]                   # SubWord
            t[0] ^= RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [bytes(b for word in w[r * 4:r * 4 + 4] for b in word) for r in range(11)]


def _add_round_key(s, rk):
    for i in range(16):
        s[i] ^= rk[i]


def _shift_rows(s):
    t = s[:]
    for r in range(1, 4):
        for c in range(4):
            s[r + 4 * c] = t[r + 4 * ((c + r) % 4)]


def _mix_columns(s):
    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
        s[i] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
        s[i + 1] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
        s[i + 2] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
        s[i + 3] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)


def aes_encrypt_block(rks, block):
    """对单个 16 字节块做 AES-128 加密。"""
    s = list(block)
    _add_round_key(s, rks[0])
    for rnd in range(1, 10):
        s = [SBOX[b] for b in s]
        _shift_rows(s)
        _mix_columns(s)
        _add_round_key(s, rks[rnd])
    s = [SBOX[b] for b in s]
    _shift_rows(s)
    _add_round_key(s, rks[10])
    return bytes(s)


_R = 0xE1000000000000000000000000000000


def _gf_mul_gcm(x, y):
    """GCM 专用 GF(2^128) 乘法（NIST SP 800-38D Alg.1，MSB-first 位序）。"""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


def _ghash(h, data):
    y = 0
    for i in range(0, len(data), 16):
        y = _gf_mul_gcm(y ^ int.from_bytes(data[i:i + 16], "big"), h)
    return y


def _pad16(b):
    if len(b) % 16:
        b += b"\x00" * (16 - len(b) % 16)
    return b


def _gcm_core(key, iv):
    rks = _expand_key(key)
    h = int.from_bytes(aes_encrypt_block(rks, b"\x00" * 16), "big")
    if len(iv) != 12:
        raise ValueError("本实现仅支持 96-bit IV")
    return h, int.from_bytes(iv + b"\x00\x00\x00\x01", "big"), rks


def _gcm_tag(h, j0, rks, aad, ct):
    s = _ghash(h, _pad16(aad) + _pad16(ct) +
               ((len(aad) * 8) << 64 | (len(ct) * 8)).to_bytes(16, "big"))
    return bytes(a ^ b for a, b in
                 zip(aes_encrypt_block(rks, j0.to_bytes(16, "big")), s.to_bytes(16, "big")))


def _gcm_ctr(rks, j0, data):
    """CTR 加密。计数器从 inc32(J0) 起算 —— J0 本身只用于生成 tag。"""
    out = bytearray()
    ctr = (j0 & ~0xFFFFFFFF) | ((j0 + 1) & 0xFFFFFFFF)
    for i in range(0, len(data), 16):
        ks = aes_encrypt_block(rks, ctr.to_bytes(16, "big"))
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], ks))
        ctr = (ctr & ~0xFFFFFFFF) | ((ctr + 1) & 0xFFFFFFFF)
    return bytes(out)


def gcm_encrypt(key, iv, plaintext, aad=b""):
    """返回 ciphertext || tag（16 字节 tag）。"""
    h, j0, rks = _gcm_core(key, iv)
    ct = _gcm_ctr(rks, j0, plaintext)
    return ct + _gcm_tag(h, j0, rks, aad, ct)


def gcm_decrypt(key, iv, ct_and_tag, aad=b""):
    """校验 tag 并解密；tag 不匹配抛 ValueError。"""
    if len(ct_and_tag) < 16:
        raise ValueError("密文过短")
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    h, j0, rks = _gcm_core(key, iv)
    if _gcm_tag(h, j0, rks, aad, ct) != tag:
        raise ValueError("GCM tag 校验失败（密钥或数据被篡改）")
    return _gcm_ctr(rks, j0, ct)


# ========================================================== 活动加解密 ===
# T / N 为前端 chunk 821.js 中硬编码的两个常量数组，密钥为其逐元素异或。

T = [251, 150, 215, 226, 208, 65, 218, 199, 149, 20, 213, 124, 94, 31, 63, 192]
N = [50, 240, 34, 160, 232, 125, 185, 153, 62, 10, 180, 83, 154, 146, 177, 75]

KEY = bytes(a ^ b for a, b in zip(T, N))   # c966f542383c635eab1e612fc48d8e8b
IV_LEN, TAG_LEN = 12, 16


def encrypt(payload):
    """把 {"score": N} 加密成 d 字段的 base64 字符串。"""
    pt = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    iv = os.urandom(IV_LEN)
    return base64.b64encode(iv + gcm_encrypt(KEY, iv, pt)).decode("ascii")


def decrypt(d):
    """解密 d 字段，返回原始 dict。"""
    raw = base64.b64decode(d + "=" * ((4 - len(d) % 4) % 4))
    if len(raw) < IV_LEN + TAG_LEN:
        raise ValueError("密文过短，不是合法的 iv||ct 结构")
    return json.loads(gcm_decrypt(KEY, raw[:IV_LEN], raw[IV_LEN:]).decode("utf-8"))


# ============================================================ HTTP 基础 ===


def device_headers():
    """设备指纹。首次运行随机生成并落盘复用，避免每次登录都换设备。"""
    if os.path.exists(DEVICE_FILE):
        with open(DEVICE_FILE, encoding="utf-8") as f:
            return json.load(f)
    dev = {
        "X-DeviceId": os.urandom(16).hex(),
        "X-DeviceId2": os.urandom(16).hex(),
        "X-DeviceModel": "DESKTOP-" + os.urandom(3).hex().upper(),
        "X-DeviceType": "2",
        "X-OSVer": "10.0.26200",
    }
    with open(DEVICE_FILE, "w", encoding="utf-8") as f:
        json.dump(dev, f, indent=2)
    return dev


def _read(resp):
    raw = resp.read()
    if resp.headers.get("Content-Encoding") == "gzip":
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8", "replace")
    try:
        return json.loads(text)
    except ValueError:
        return text


def as_post(path, payload, extra=None):
    """账号域 POST，返回 (status, body)。"""
    h = {
        "Content-Type": "application/json",
        "X-AppCode": APP_CODE,
        "X-Captcha-Version": "4.0",
        "Accept-Encoding": "gzip",
        "Accept-Language": "zh-CN,en,*",
        "User-Agent": "Mozilla/5.0",
    }
    h.update(device_headers())
    h.update(extra or {})
    req = urllib.request.Request(AS + path, data=json.dumps(payload).encode(),
                                 method="POST", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=30,
                                    context=ssl.create_default_context()) as r:
            return r.status, _read(r)
    except urllib.error.HTTPError as e:
        return e.code, _read(e)
    except Exception as e:                  # 连接重置 / 超时 / DNS 等
        return None, "网络异常 %s: %s" % (type(e).__name__, e)


# ============================================================ 账号登录 ===


def send_phone_code(phone):
    """发送短信验证码。返回 (ok, body)。"""
    st, body = as_post("/general/v1/send_phone_code", {"phone": phone, "type": 2})
    return (isinstance(body, dict) and body.get("status") == 0), body


def login_by_phone_code(phone, code):
    """手机号 + 验证码换 token。返回 data dict 或 None。"""
    st, body = as_post("/user/auth/v2/token_by_phone_code",
                       {"appCode": APP_CODE, "code": code, "phone": phone})
    if isinstance(body, dict) and body.get("status") == 0:
        return body["data"]
    return None


def oauth_grant(acc):
    """用 deviceToken 换 oauth 凭据。缺 deviceToken 会被设备验证拦截(status:109)。
    同时兼作账号 token 的探活手段：token 失效时返回 None。"""
    token = (acc or {}).get("token")
    if not token:
        return None
    st, body = as_post("/user/oauth2/v2/grant",
                       {"appCode": APP_CODE, "token": token, "type": 0,
                        "deviceToken": (acc or {}).get("deviceToken", "")})
    if isinstance(body, dict) and body.get("status") == 0:
        return body["data"]
    return None


# ---------------------------------------------------------- 账号凭据缓存 ---
# 目的：短信验证码只发一次。首次登录后把凭据落盘，后续直接复用。
# 文件含 token，已在 .gitignore 中排除。


def load_account():
    """读取账号缓存。文件缺失/损坏/过期均返回 None。"""
    try:
        with open(ACCOUNT_FILE, encoding="utf-8") as f:
            c = json.load(f)
    except Exception:
        return None
    if not isinstance(c, dict) or not (c.get("acc") or {}).get("token"):
        return None
    if time.time() - c.get("saved_at", 0) > ACCOUNT_TTL:
        return None
    return c


def save_account(acc, oauth):
    """落盘账号凭据。含 token，务必保持在 .gitignore 内。"""
    try:
        with open(ACCOUNT_FILE, "w", encoding="utf-8") as f:
            json.dump({"saved_at": time.time(), "acc": acc, "oauth": oauth},
                      f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def clear_account():
    """删除账号缓存（token 失效时调用）。"""
    try:
        os.remove(ACCOUNT_FILE)
    except Exception:
        pass


def account_age(c):
    """把 saved_at 说成人话：今天 / N 天前。"""
    d = int((time.time() - c.get("saved_at", 0)) // 86400)
    return "今天" if d <= 0 else "%d 天前" % d


def resolve_account(a):
    """决定账号凭据来源。返回 (acc, oauth, 说明)。

    --no-login 直接放弃；否则先试缓存，缓存 token 用 oauth_grant 探活，
    探活失败就清掉缓存，交由调用方走短信流程。
    """
    if a.no_login:
        return None, None, None
    if a.relogin:
        return None, None, None
    c = load_account()
    if not c:
        return None, None, None
    acc = c.get("acc") or {}
    oauth = oauth_grant(acc)                 # 顺带探活
    if oauth:
        return acc, oauth, "缓存 .account.json（%s）" % account_age(c)
    print("%s 缓存的账号凭据已失效，将重新登录" % NO)
    clear_account()
    return None, None, None


# ========================================================== u8_token ===
# 活动接口的 x-role-token 就是活动链接里的 u8_token，前端不做任何加工。
# 它无法由账号链路推导（账号 token / oauth token / code 均被 role/login 拒绝），
# 只能从活动链接或游戏客户端的 role/login 抓包获取。


def u8_from_har(path):
    """先找 x-role-token 请求头，再回退解析 role/login 请求体的 token 字段。"""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            entries = json.load(f)["log"]["entries"]
    except Exception:
        return None
    for e in entries:
        req = e.get("request", {})
        for h in req.get("headers", []):
            if h.get("name", "").lower() == "x-role-token" and h.get("value"):
                return h["value"]
        pd = (req.get("postData") or {}).get("text")
        if pd and "role/login" in req.get("url", ""):
            try:
                v = json.loads(pd).get("token")
                if v:
                    return v
            except Exception:
                pass
    return None


def find_har(explicit=None):
    """定位抓包文件。

    优先用 --har 指定的；否则在 脚本目录 / ~/Downloads / ~/Desktop 里
    按修改时间倒序找 *.har，返回第一个能提取出 u8_token 的。
    """
    if explicit:
        return explicit if os.path.exists(explicit) else None

    home = os.path.expanduser("~")
    dirs = [HERE, os.path.join(home, "Downloads"), os.path.join(home, "Desktop")]
    cands = []
    for d in dirs:
        try:
            cands += glob.glob(os.path.join(d, "*.har"))
        except Exception:
            pass
    if not cands:
        return None
    cands.sort(key=lambda p: os.path.getmtime(p), reverse=True)

    for c in cands:
        if u8_from_har(c):
            return c
    return cands[0]


def resolve_u8(cli_u8, har_path):
    """按 --u8 > .u8_token 缓存 > HAR 的优先级取 u8_token。"""
    if cli_u8:
        return cli_u8, "--u8 参数"
    if os.path.exists(U8_CACHE):
        with open(U8_CACHE, encoding="utf-8") as f:
            v = f.read().strip()
        if v:
            return v, "缓存 .u8_token"
    har = find_har(har_path)
    if har:
        v = u8_from_har(har)
        if v:
            return v, "HAR %s" % os.path.basename(har)
    return None, None


def save_u8(v):
    try:
        with open(U8_CACHE, "w", encoding="utf-8") as f:
            f.write(v)
    except Exception:
        pass


# ========================================================== 活动提交 ===


def submit_score(u8, score):
    """先 role/login 建立会话 cookie，再提交分数。两步都必需。"""
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    hdr = {
        "content-type": "application/json",
        "accept": "application/json, text/plain, */*",
        "x-role-token": u8,
        "x-role-server-id": SERVER_ID,
        "origin": "https://ef-webview.hypergryph.com",
        "referer": "https://ef-webview.hypergryph.com/act/orbipom-merge/"
                   "?u8_token=%s&server=%s" % (u8, SERVER_ID),
        "user-agent": "Mozilla/5.0",
    }

    def call(path, payload):
        """带一次重试的 POST。连接被重置/超时不抛栈，返回 (None, 说明)。"""
        last = None
        for attempt in range(2):
            req = urllib.request.Request(ACT + path,
                                         data=json.dumps(payload).encode(),
                                         method="POST", headers=hdr)
            try:
                with opener.open(req, timeout=30) as r:
                    return r.status, _read(r)
            except urllib.error.HTTPError as e:
                return e.code, _read(e)
            except Exception as e:          # 连接重置 / 超时 / DNS 等
                last = e
                if attempt == 0:
                    time.sleep(1)
        return None, "网络异常 %s: %s" % (type(last).__name__, last)

    print("%s role/login 建立会话 ..." % AR)
    st, body = call("/api/role/login", {"token": u8, "serverId": SERVER_ID})
    if st != 200 or not (isinstance(body, dict) and body.get("code") == 0):
        print("    %s 会话建立失败: HTTP %s %s" % (NO, st, body))
        return st, body
    print("    %s 会话已建立 (cookie: %s)" % (OK, ", ".join(c.name for c in cj) or "无"))

    d = encrypt({"score": score})
    print("%s 加密完成  {\"score\":%d}" % (AR, score))
    print("    d = %s" % d)
    print("%s 提交分数 ..." % AR)
    st, body = call("/api/save/score", {"d": d})
    print("    HTTP %s  %s" % (st, body))
    return st, body


# ============================================================ 全流程 ===


def _ask(prompt):
    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def _ask_int(prompt):
    while True:
        raw = _ask(prompt)
        try:
            v = int(raw)
        except ValueError:
            print("    需要整数，重来")
            continue
        if v < 0:
            print("    负数会被服务端拒绝，重来")
            continue
        return v


def _login_interactive(a):
    """短信验证码登录。成功后落盘缓存，之后不再需要验证码。

    登录失败一律不阻断流程 —— 提交分数只依赖 u8_token，账号凭据只是附带产物。
    """
    phone = a.phone or _ask("%s 手机号 (留空跳过): " % AR)
    if not phone:
        print("%s 未提供手机号，跳过账号登录（不影响提交）" % AR)
        return None, None

    if a.code:
        code = a.code
    else:
        print("%s 发送验证码到 %s ..." % (AR, phone))
        ok, body = send_phone_code(phone)
        if not ok:
            print("    %s 发送失败: %s" % (NO, body))
            print("    %s 跳过账号登录（不影响提交）" % AR)
            return None, None
        print("    %s 已发送，请查收短信" % OK)
        code = _ask("%s 验证码 (留空跳过): " % AR)
    if not code:
        print("%s 未输入验证码，跳过账号登录（不影响提交）" % AR)
        return None, None

    print("%s 登录中 ..." % AR)
    acc = login_by_phone_code(phone, code)
    if not acc:
        print("    %s 登录失败（手机号或验证码错误），跳过账号登录" % NO)
        return None, None
    print("    %s 登录成功  hgId=%s" % (OK, acc.get("hgId")))

    print("%s 换取 oauth 凭据 ..." % AR)
    oauth = oauth_grant(acc)
    if oauth:
        print("    %s uid=%s" % (OK, oauth.get("uid")))
    else:
        print("    %s grant 失败（不影响后续提交）" % NO)

    save_account(acc, oauth)
    print("    %s 已缓存到 .account.json —— 下次运行不再需要验证码" % OK)
    return acc, oauth


def run_full_flow(a):
    print("=" * 62)
    print(" 鹰角 融合！山团团！(orbipom-merge) 全流程")
    print("=" * 62)

    # u8_token
    u8, src = resolve_u8(a.u8, a.har)
    if u8:
        print("%s u8_token 来源: %s (%d chars)" % (OK, src, len(u8)))
    else:
        print("%s 未找到 u8_token。" % NO)
        print("    已在 脚本目录 / ~/Downloads / ~/Desktop 查找 *.har，未找到有效抓包。")
        print("    活动接口鉴权用的 x-role-token 就是活动链接里的 u8_token，")
        print("    例如 .../act/orbipom-merge/?u8_token=XXXX&server=1")
        print("    也可用 --har <路径> 指定抓包文件。")
        v = _ask("    粘贴 u8_token (留空跳过): ")
        if v:
            u8 = v
            save_u8(v)
            print("    %s 已缓存" % OK)

    # ---- 账号凭据：优先复用缓存，避免反复发短信 ----
    if a.no_login:
        print("%s 已跳过账号登录（--no-login）" % AR)
    else:
        acc, oauth, src_acc = resolve_account(a)
        if acc:
            print("%s 账号凭据: %s  hgId=%s" % (OK, src_acc, acc.get("hgId")))
        else:
            if a.relogin:
                print("%s --relogin：忽略缓存，重新登录" % AR)
            _login_interactive(a)

    score = a.score if a.score is not None else _ask_int("%s 分数: " % AR)

    if not u8:
        print("\n%s 没有 u8_token，无法提交。分数密文已生成：" % NO)
        print("    %s" % encrypt({"score": score}))
        return 1
    submit_score(u8, score)
    print("=" * 62)
    return 0


# ============================================================== CLI ===


def selftest():
    """FIPS-197 / NIST SP 800-38D 官方向量。"""
    k = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = aes_encrypt_block(_expand_key(k), pt)
    assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", ct.hex()

    z16, z12 = b"\x00" * 16, b"\x00" * 12
    assert gcm_encrypt(z16, z12, b"", b"").hex() == "58e2fccefa7e3061367f1d57a4e7455a"
    assert gcm_encrypt(z16, z12, z16, b"").hex() == (
        "0388dace60b6a392f328c2b971b2fe78" "ab6e47d42cec13bdf53a67b21257bddf")
    print("AES-128-GCM 自检通过：FIPS-197 + NIST SP 800-38D 向量全部匹配")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="orbipom-merge 请求体加解密 + 账号链路复现工具",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", nargs="?",
                    choices=["selftest", "key", "encrypt", "decrypt", "login"],
                    help="子命令；省略则进入全流程")
    ap.add_argument("args", nargs="*", help="子命令参数")
    ap.add_argument("--phone")
    ap.add_argument("--code")
    ap.add_argument("--score", type=int)
    ap.add_argument("--u8")
    ap.add_argument("--har", default="",
                    help="抓包文件路径；留空则自动在 脚本目录 / ~/Downloads / ~/Desktop 查找")
    ap.add_argument("--no-login", dest="no_login", action="store_true",
                    help="完全跳过账号登录，只用 u8_token 提交分数")
    ap.add_argument("--relogin", action="store_true",
                    help="忽略 .account.json 缓存，强制重新发短信登录")
    a = ap.parse_args(argv)

    if a.cmd == "selftest":
        selftest()
        return 0
    if a.cmd == "key":
        print("KEY =", KEY.hex())
        return 0
    if a.cmd == "encrypt":
        print(encrypt(json.loads(a.args[0])))
        return 0
    if a.cmd == "decrypt":
        d = a.args[0]
        try:
            obj = json.loads(d)
            if isinstance(obj, dict) and "d" in obj:
                d = obj["d"]
        except Exception:
            pass
        print(json.dumps(decrypt(d), ensure_ascii=False))
        return 0
    if a.cmd == "login":
        sub = a.args[0] if a.args else ""
        if sub == "sendcode" and len(a.args) >= 2:
            ok, body = send_phone_code(a.args[1])
            print("HTTP", "OK" if ok else "FAIL", body)
            return 0 if ok else 1
        if sub == "phone" and len(a.args) >= 3:
            acc = login_by_phone_code(a.args[1], a.args[2])
            if acc:
                print("登录成功")
                for k in ("token", "hgId", "deviceToken"):
                    print("  %-12s = %s" % (k, acc.get(k)))
                return 0
            print("登录失败")
            return 1
        print("用法: orbipom.py login sendcode <phone>")
        print("      orbipom.py login phone <phone> <code>")
        return 1

    return run_full_flow(a)


if __name__ == "__main__":
    sys.exit(main())
