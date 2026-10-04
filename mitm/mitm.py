#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""中间人：把 ef-webview.hypergryph.com 劫到本地，改写接口响应。

和前面几条路的区别：

    local/ + serve.py   改浏览器看得到的「页面副本」
    intercept.py        改 Playwright 拉起的那个浏览器的请求
    本脚本              改**任意**进程的请求 —— 包括游戏客户端的 WebView

原理是标准的三件套：

  1. hosts 把 `ef-webview.hypergryph.com` 指到 127.0.0.1
  2. 本地 443 起一个 HTTPS 服务，用**自签 CA 签发的证书**冒充该域名
  3. 系统信任区装上这张 CA，客户端才会认这张证书

只劫这一个域名。页面本体、JS、CSS 都从上游原样回传，**只改 `/api/save/profile`
和 `/api/save/score` 的响应**（把 highScore / best 换掉）—— 首页那个「最高分」就是这么来的。

证书用 openssl 现生成，放在 certs/ 下（.gitignore 掉，别提交私钥）。

用法:
    python mitm.py --gencert              # 生成 CA + 服务器证书
    python mitm.py --port 443             # 起服务（真实劫持要 443，需管理员）
    python mitm.py --port 8443 --selftest # 本地自检，不碰系统
"""

import argparse
import gzip
import http.client
import http.server
import os
import re
import socket
import socketserver
import ssl
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CERTS = os.path.join(HERE, "certs")
CA_KEY = os.path.join(CERTS, "ca.key")
CA_CRT = os.path.join(CERTS, "ca.crt")
SRV_KEY = os.path.join(CERTS, "server.key")
SRV_CRT = os.path.join(CERTS, "server.crt")

HOST = "ef-webview.hypergryph.com"
DROP_REQ = {"host", "connection", "keep-alive", "proxy-connection", "transfer-encoding",
            "upgrade", "te", "trailer", "accept-encoding"}
DROP_RES = {"connection", "keep-alive", "transfer-encoding", "upgrade", "trailer"}

# 条件请求头 —— 对**我们可能改写的**资源必须剥掉。
# 上游一旦回 304，客户端就用自己缓存里的原始文件，我们的改写等于没做。
# 实测踩过：游戏客户端拿 304 复用了缓存的原始 HTML（里面的 JS 地址还是
# web.hycdn.cn），结果日志里连一个 /__cdn/ 请求都没有，JS 完全没被改。
DROP_COND = {"if-none-match", "if-modified-since", "if-range", "if-match",
             "if-unmodified-since"}


def needs_fresh(target):
    """这个请求能不能被 304 / 缓存短路掉？

    只要是我们**可能改写**的资源（活动接口、活动页 HTML、活动 JS），
    就必须拿到完整 body 才能改 —— 所以不能让它走 304。
    其它资源（图片、音频、字体…）照常允许 304，省流量。
    """
    if any(p in target for p in FAKE_PATHS):
        return True
    if "orbipom-merge" not in target:
        return False
    return target.endswith(".js") or target.startswith("/act/orbipom-merge")

FAKE_HIGH_SCORE = 5201314
FAKE_PATHS = ("/api/save/profile", "/api/save/score")
RE_FAKE_FIELD = re.compile(r'("(?:highScore|best)"\s*:\s*)\d+')

# 上游真实 IP。**必须绕开系统解析** —— hosts 已经把 HOST 指向 127.0.0.1 了，
# 再用 getaddrinfo 连上游就会连到自己（自环），表现为 upstream CERTIFICATE_VERIFY_FAILED。
UPSTREAM_IP = None
UPSTREAM_PORT = 443

# ---- 前端 JS 也走中间人：同域中转（改「单局分数上限」用）----
#
# 活动页的 JS **不在** ef-webview.hypergryph.com 上，而在 web.hycdn.cn 这个
# **共享 CDN** 上（线上 HTML 里 web.hycdn.cn 出现 377 次）。
#
# 直接劫 web.hycdn.cn 会把游戏其它内容一起卷进来，影响面太大；所以走「同域中转」：
#   1. 页面 HTML / JS 里的 `https://web.hycdn.cn/endfield/webview/`
#      改写成 `https://ef-webview.hypergryph.com/__cdn/endfield/webview/`
#   2. 客户端来取 `/__cdn/...` 时，中间人再去 web.hycdn.cn 取回原内容
#      （是 JS 就顺手打补丁）转给客户端
#
# 这样**只劫一个域名**，而且只影响这个活动页。
CDN_HOST = "web.hycdn.cn"
CDN_PREFIX = "/__cdn/"
SELF_BASE = "https://" + HOST          # 注意别带尾斜杠，否则拼出 //__cdn/
CDN_ACT_PREFIX = "endfield/webview/"
RE_CDN_ACT = re.compile(r"https://web\.hycdn\.cn/" + re.escape(CDN_ACT_PREFIX))
REPL_CDN_ACT = SELF_BASE + CDN_PREFIX + CDN_ACT_PREFIX

CDN_IP = None
CDN_PORT = 443

# 前端补丁参数（默认值和 local/patch_score.py 一致）
PATCH_JS = True
JS_SCALE = 5201314
JS_CAP = 5201314
JS_RUN_CAP = 99999999
JS_KEEP_WATCHDOG = False
JS_MEGA_MERGE = True          # 两只最小的直接合成最高级
JS_SPAWN_LEVEL = 1            # 出块等级固定为 1
JS_KEEP_SPAWN = False         # True = 保留原出块区间（1~5 随机）

# 补丁规则从 local/patch_score.py 借，**保持单一来源** ——
# 前端一改版只需要修那一处。拿不到就退化成「只改接口，不碰 JS」。
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "local")))
try:
    from patch_score import (ORIG_SCORES, RE_CAP, RE_MERGE, RE_RUNCAP, RE_SCORES,
                             RE_SPAWN, RE_WATCHDOG, MEGA_MERGE_ON, spawn_fix)
    JS_RULES_ERR = None
except Exception as _e:                                    # noqa: BLE001
    (ORIG_SCORES, RE_CAP, RE_RUNCAP, RE_SCORES, RE_WATCHDOG,
     RE_MERGE, RE_SPAWN) = (None,) * 7
    MEGA_MERGE_ON = None
    spawn_fix = None
    JS_RULES_ERR = _e

# 裸 UDP DNS 优先。这台机器上 DoH（HTTPS）会被网络层中间人拦掉 —— 实测
# dns.alidns.com / doh.pub 都报证书错（self-signed / unable to get local issuer），
# cloudflare 直接被 reset。裸 UDP 53 不经过 TLS，反而干净。
DNS_SERVERS = ("223.5.5.5", "119.29.29.29", "114.114.114.114", "8.8.8.8")
DOH_PROVIDERS = (
    "https://dns.alidns.com/resolve?name={h}&type=A",
    "https://doh.pub/dns-query?name={h}&type=A",
)


def dns_query_a(host, server, timeout=5):
    """最小 DNS 客户端：手搓报文，UDP 直查 A 记录，只取第一个地址。"""
    import random
    import struct
    tid = random.randint(0, 0xFFFF)
    q = struct.pack(">HHHHHH", tid, 0x05201314, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode("ascii") for p in host.split("."))
    q += b"\x00" + struct.pack(">HH", 1, 1)          # QTYPE=A, QCLASS=IN
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (server, 53))
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    rid, _flags, _qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if rid != tid or an == 0:
        return None
    i = 12
    while data[i] != 0:                              # 跳过 QNAME
        i += data[i] + 1
    i += 5                                           # QTYPE + QCLASS
    ips = []
    for _ in range(an):
        if data[i] & 0xC0 == 0xC0:                   # 压缩指针
            i += 2
        else:
            while data[i] != 0:
                i += data[i] + 1
            i += 1
        atype, _aclass, _ttl, rdlen = struct.unpack(">HHIH", data[i:i + 10])
        i += 10
        if atype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in data[i:i + 4]))
        i += rdlen
    return ips[0] if ips else None


def resolve_upstream(host=None):
    """拿上游真实 IP，**必须绕开 hosts**。先裸 UDP DNS，再退到 DoH。"""
    host = host or HOST
    for srv in DNS_SERVERS:
        try:
            ip = dns_query_a(host, srv)
            if ip:
                sys.stderr.write("  [DNS] %s -> %s (via %s)\n" % (host, ip, srv))
                return ip
            sys.stderr.write("  [DNS] %s 无 A 记录\n" % srv)
        except Exception as e:
            sys.stderr.write("  [DNS] %s 失败: %s\n" % (srv, e))

    import json
    import urllib.request
    for tpl in DOH_PROVIDERS:
        url = tpl.format(h=host)
        try:
            req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read().decode("utf-8"))
            ips = [a["data"] for a in data.get("Answer", [])
                   if a.get("type") == 1 and a.get("data")]
            if ips:
                sys.stderr.write("  [DNS] %s -> %s (via DoH %s)\n"
                                 % (host, ips[0], url.split("/")[2]))
                return ips[0]
        except Exception as e:
            sys.stderr.write("  [DNS] DoH %s 失败: %s\n" % (url.split("/")[2], e))
    return None


def upstream_ip(host):
    """某个上游域名该连哪个 IP。"""
    global UPSTREAM_IP, CDN_IP
    if host == HOST:
        if not UPSTREAM_IP:
            UPSTREAM_IP = resolve_upstream(HOST)
        return UPSTREAM_IP
    if host == CDN_HOST:
        if not CDN_IP:
            CDN_IP = resolve_upstream(CDN_HOST)
        return CDN_IP
    return resolve_upstream(host)


def open_upstream(host=None, port=None):
    """连到真实 IP，但 SNI / Host 仍是真实域名。

    `--upstream-port` / `--cdn-port` 只是为了本地测试：起一个 mock 上游
    （用同一张服务器证书），就能在不碰外网的前提下把整条路走一遍。
    """
    host = host or HOST
    port = port or (UPSTREAM_PORT if host == HOST else CDN_PORT)
    ip = upstream_ip(host)
    if not ip:
        raise RuntimeError("拿不到 %s 的真实 IP" % host)
    ctx = ssl.create_default_context()
    raw = socket.create_connection((ip, port), timeout=30)
    ssock = ctx.wrap_socket(raw, server_hostname=host)
    conn = http.client.HTTPSConnection(host, port, timeout=30, context=ctx)
    conn.sock = ssock          # 预置 sock，request() 就不会再自己 connect
    return conn

# 调试用：把 WVSDK 垫片注入到代理回来的页面里。
# **默认关闭** —— 游戏客户端里 WVSDK 是原生桥提供的，注入反而会把它覆盖掉。
# 只有在用普通浏览器验证中间人时才需要打开。
INJECT_SHIM = False
SHIM = ("<script>(function(){if(!window.WVSDK){window.WVSDK={ENV:{},callback:{},API:{},"
        "platform:\"Qt\",invoke:function(){return Promise.resolve({status:0,errorCode:0});},"
        "invokeWithReturnValue:function(){return Promise.resolve({status:1,errorCode:0});}};}})();"
        "</script>")


# ------------------------------------------------------------------ 证书

def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def gencert(force=False, extra_san=(), force_ca=False):
    """生成 CA 与服务器证书。

    **CA 默认只在不存在时生成。** 这一点很关键：系统「受信任的根证书颁发机构」里
    装的是 CA，如果把 CA 重新生成了，装过的那张就对不上，客户端会直接报
    `unknown ca` —— 而 `--force` 的语义应该是「重签服务器证书」，
    不该顺手把 CA 也换掉（踩过：以为只是重签，结果整条链路全挂）。
    """
    if os.path.isfile(SRV_CRT) and not force:
        print("证书已存在：%s（要重签加 --force）" % SRV_CRT)
        return
    os.makedirs(CERTS, exist_ok=True)

    if sh(["openssl", "version"]).returncode != 0:
        sys.exit("找不到 openssl")

    have_ca = os.path.isfile(CA_CRT) and os.path.isfile(CA_KEY)
    if have_ca and not force_ca:
        print("[1/3] 复用已有 CA（系统里装的就是它，重生成会让信任失效）")
    else:
        print("[1/3] 生成 CA ...")
        r = sh(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
                "-days", "3650", "-nodes",
                "-keyout", CA_KEY, "-out", CA_CRT,
                "-subj", "/CN=Orbipom Local Debug CA/O=orbipom-local",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
        if r.returncode:
            sys.exit("CA 生成失败：%s" % r.stderr)
        print("      CA 换了 —— 系统里的旧 CA 已失效，必须重新跑 trust.py --install --apply")

    print("[2/3] 生成服务器证书（SAN=%s）..." % HOST)
    ext = os.path.join(CERTS, "server.ext")
    sans = ["DNS:" + HOST, "DNS:*.hypergryph.com"] + ["DNS:" + h for h in extra_san]
    with open(ext, "w", encoding="utf-8") as fh:
        fh.write("basicConstraints=CA:FALSE\n"
                 "keyUsage=critical,digitalSignature,keyEncipherment\n"
                 "extendedKeyUsage=serverAuth\n"
                 "subjectAltName=%s\n" % ",".join(sans))
    if extra_san:
        print("     额外 SAN（仅本地 mock 测试用）：%s" % ", ".join(extra_san))
    csr = os.path.join(CERTS, "server.csr")
    for cmd in (
        ["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-sha256",
         "-keyout", SRV_KEY, "-out", csr, "-subj", "/CN=" + HOST],
        ["openssl", "x509", "-req", "-in", csr, "-CA", CA_CRT, "-CAkey", CA_KEY,
         "-CAcreateserial", "-out", SRV_CRT, "-days", "825", "-sha256",
         "-extfile", ext],
    ):
        r = sh(cmd)
        if r.returncode:
            sys.exit("证书生成失败：%s" % r.stderr)

    print("[3/3] 校验链 ...")
    r = sh(["openssl", "verify", "-CAfile", CA_CRT, SRV_CRT])
    print("     " + r.stdout.strip() + r.stderr.strip())
    print("\nCA 证书: %s" % CA_CRT)
    print("指纹   : %s" % sh(["openssl", "x509", "-in", CA_CRT, "-noout",
                              "-fingerprint", "-sha256"]).stdout.strip())


# ------------------------------------------------------------------ 代理

def _sub1(text, rx, repl, notes, label):
    """只在**唯一匹配**时替换。0 处 = 这个文件不含这条规则（正常）；
    >1 处 = 不敢动，跳过。绝不因为一处不匹配就整体失败。"""
    if rx is None:
        return text
    n = len(rx.findall(text))
    if n != 1:
        if n > 1:
            notes.append("%s 匹配 %d 处，跳过" % (label, n))
        return text
    notes.append(label)
    return rx.sub(repl, text, count=1)


def patch_js(text):
    """改前端 JS：得分表 / maxScore / 结算阈值 / 看门狗 / 合成逻辑 / 出块等级。

    规则与 `local/patch_score.py` 共用（同一套正则），改的是同一批位置。
    返回 (新文本, 生效项列表)。
    """
    notes = []
    out = text

    out = _sub1(out, RE_SCORES,
                "eS=[" + ",".join(str(v * JS_SCALE) for v in ORIG_SCORES) + "]",
                notes, "得分表×%d" % JS_SCALE)
    out = _sub1(out, RE_CAP, "maxScore:%d" % JS_CAP, notes, "maxScore->%d" % JS_CAP)
    out = _sub1(out, RE_RUNCAP,
                "r.score<%d&&e.score>=%d" % (JS_RUN_CAP, JS_RUN_CAP),
                notes, "结算阈值->%d" % JS_RUN_CAP)
    if not JS_KEEP_WATCHDOG:
        out = _sub1(out, RE_WATCHDOG, '"playing"===r&&!1&&0===e&&t()',
                    notes, "关掉10s看门狗")
    if JS_MEGA_MERGE:
        out = _sub1(out, RE_MERGE, MEGA_MERGE_ON, notes, "1+1=最高级")
    if not JS_KEEP_SPAWN:
        # 出块不钉死的话，1+1=最高级就是白改：出一只 3 级还得再等一只 3 级
        out = _sub1(out, RE_SPAWN, spawn_fix(JS_SPAWN_LEVEL),
                    notes, "出块固定%d级" % JS_SPAWN_LEVEL)

    # 把 CDN 前缀转到本域，这样后续 chunk / 语言包也走中间人
    out, n = RE_CDN_ACT.subn(REPL_CDN_ACT, out)
    if n:
        notes.append("CDN前缀×%d 转本域" % n)
    return out, notes


def rewrite(target, payload, headers, status=0):
    """按需改写响应体，返回 (body, 是否改过)。

    注意上游活动页是 **gzip 预压缩**存在 OSS 里的（`content-encoding: gzip`），
    要动它就得先解压；解压后就不能再带 `content-encoding` 了（调用方据此决定）。

    凡是命中 FAKE_PATHS 的响应都会打一行日志 —— 这是「游戏里到底有没有走我们」的
    唯一直接证据：**没登录时上游回 401，没有字段可改**，日志会写出来，
    免得把「401」误判成「改写没生效」。
    """
    enc = (headers.get("content-encoding") or "").lower()
    ctype = (headers.get("content-type") or "").lower()

    def decode(b):
        if enc in ("", "identity"):
            return b
        if enc == "gzip":
            try:
                return gzip.decompress(b)
            except OSError:
                return None
        return None      # br / zstd 之类没解压器，原样放行

    def as_text(b):
        try:
            return b.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def encode(t):
        return t.encode("utf-8")

    # ---- 接口响应改写 ----
    if any(p in target for p in FAKE_PATHS):
        raw = decode(payload)
        text = as_text(raw) if raw is not None else None
        if text is None:
            sys.stderr.write("  [接口] %s <- %d  body 解不开（%s），原样放行\n"
                             % (target, status, enc or "identity"))
            return payload, False
        found = RE_FAKE_FIELD.findall(text)
        new = RE_FAKE_FIELD.sub(lambda m: m.group(1) + str(FAKE_HIGH_SCORE), text)
        if new != text:
            before = re.findall(r'"(?:highScore|best)"\s*:\s*(\d+)', text)
            sys.stderr.write("  [接口] %s <- %d  ✅ 改写 %s -> %d\n"
                             % (target, status, "/".join(before), FAKE_HIGH_SCORE))
            return encode(new), True
        if found:
            sys.stderr.write("  [接口] %s <- %d  已经是 %d，无需改\n"
                             % (target, status, FAKE_HIGH_SCORE))
        elif status == 401:
            sys.stderr.write("  [接口] %s <- 401  未登录（响应里没有字段可改）。"
                             "游戏里正常带 cookie，不会走到这\n" % target)
        else:
            sys.stderr.write("  [接口] %s <- %d  响应里没有 highScore/best\n"
                             % (target, status))
        return payload, False

    # ---- 前端 JS / HTML：CDN 中转 + 打补丁 ----
    # 只在活动页自己的资源上动手，别碰 CDN 上共享的东西。
    if PATCH_JS and "orbipom-merge" in target:
        raw = decode(payload)
        text = as_text(raw) if raw is not None else None
        if text is not None:
            if target.endswith(".js") or "javascript" in ctype:
                new, notes = patch_js(text)
                if new != text:
                    sys.stderr.write("  [JS]  %s <- %d  %s\n"
                                     % (target.split("/")[-1], status,
                                        "、".join(notes)))
                    return encode(new), True
            elif "text/html" in ctype:
                new, n = RE_CDN_ACT.subn(REPL_CDN_ACT, text)
                if n:
                    sys.stderr.write("  [页面] CDN前缀×%d 转本域（%s）\n"
                                     % (n, target))
                    return encode(new), True

    # ---- 调试用：往活动页注入垫片 ----
    if INJECT_SHIM and "/act/orbipom-merge" in target and "text/html" in ctype:
        raw = decode(payload)
        text = as_text(raw) if raw is not None else None
        if text and "orbipom-mitm-shim" not in text:
            new = re.sub(r"(<head[^>]*>)",
                         r"\1<!--orbipom-mitm-shim-->" + SHIM, text, count=1)
            if new != text:
                sys.stderr.write("  [垫片] 已注入 WVSDK（仅调试用）\n")
                return new.encode("utf-8"), True

    return payload, False


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "orbipom-mitm/1.0"

    def setup(self):
        # TLS 握手放在**每个连接自己的线程**里做。
        # 千万不要 wrap 监听 socket —— 那样握手会在 accept() 里串行执行，
        # 只要有一个连接（扫描器、探测、半开连接）卡住，后面全部堵死。
        self.request = self.server.ssl_ctx.wrap_socket(self.request, server_side=True)
        super().setup()

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ssl.SSLError, OSError) as e:
            # 客户端握手失败 / 提前断开都是常态，别刷 traceback
            sys.stderr.write("  [连接] %s: %s\n" % (type(e).__name__, e))
            self.close_connection = True

    def log_message(self, fmt, *a):
        line = re.sub(r'(u8_token=)[^&\s"]+', r"\1<redacted>", fmt % a)
        sys.stderr.write("  %s %s\n" % (self.address_string(), line))

    def _proxy(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None

        # /__cdn/... 是从 web.hycdn.cn 中转过来的（见文件头「同域中转」说明）。
        # 只有走中转的那些请求才去 CDN 取；其余一律按本域（ef-webview）上游处理。
        if self.path.startswith(CDN_PREFIX):
            up_host = CDN_HOST
            up_path = self.path[len(CDN_PREFIX) - 1:]
        else:
            up_host = HOST
            up_path = self.path

        headers = {k: v for k, v in self.headers.items() if k.lower() not in DROP_REQ}
        fresh = needs_fresh(self.path)
        if fresh:
            # 剥掉条件请求头，逼上游回 200 带完整 body —— 否则 304 会让改写落空
            for k in [k for k in headers if k.lower() in DROP_COND]:
                del headers[k]
        headers["Host"] = up_host
        headers["Accept-Encoding"] = "identity"

        attempts = 3 if self.command in ("GET", "HEAD") else 1
        resp, payload, last = None, b"", None
        for i in range(attempts):
            conn = None
            try:
                conn = open_upstream(up_host)
                conn.request(self.command, up_path, body=body, headers=headers)
                resp = conn.getresponse()
                payload = resp.read()
                break
            except Exception as e:
                last = e
                resp = None
                if i < attempts - 1:
                    time.sleep(0.6 * (i + 1))
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
        if resp is None:
            try:
                self.send_error(502, "upstream failed: %s" % last)
            except OSError:
                pass
            return

        payload, modified = rewrite(self.path, payload, resp.headers, resp.status)

        self.send_response(resp.status)
        for k, v in resp.getheaders():
            low = k.lower()
            if low in DROP_RES or low == "content-length":
                continue
            # 只有真的动过 body 才敢丢 content-encoding；
            # 没动过就必须原样保留，否则 gzip 的页面会直接乱码。
            if modified and low == "content-encoding":
                continue
            # 要改写的资源不能把验证器透给客户端 —— 否则它下次带着
            # If-None-Match 来问，又会被 304 短路掉。
            if fresh and low in ("etag", "last-modified", "expires"):
                continue
            self.send_header(k, v)
        if modified or fresh:
            # 改过的资源别让客户端缓存，否则改了看不到效果
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("Pragma", "no-cache")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(payload)
            except OSError:
                pass

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = _proxy


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler, ssl_ctx):
        self.ssl_ctx = ssl_ctx
        super().__init__(addr, handler)

    def handle_error(self, request, client_address):
        """TLS 握手失败 / 客户端提前断开都是常态（探测、扫描、半开连接）。

        `setup()` 里抛的异常**不会**走到 `Handler.handle_one_request()`，
        而是由 socketserver 交给这里 —— 不覆写就会刷一整页 traceback
        （实测：`ssl.SSLEOFError: EOF occurred in violation of protocol`，
        每来一个探测就刷一次）。
        """
        exc = sys.exc_info()[1]
        if isinstance(exc, ssl.SSLError):
            sys.stderr.write("  [连接] TLS 握手未完成（%s），已忽略\n"
                             % type(exc).__name__)
            return
        if isinstance(exc, (ConnectionError, OSError)):
            return
        super().handle_error(request, client_address)


def serve(host, port):
    global UPSTREAM_IP

    if not (os.path.isfile(SRV_CRT) and os.path.isfile(SRV_KEY)):
        sys.exit("没有证书，先跑: python mitm.py --gencert")

    if not UPSTREAM_IP:
        print("解析上游真实 IP（绕开 hosts，先 UDP DNS 再 DoH）...")
        UPSTREAM_IP = resolve_upstream(HOST)
    if not UPSTREAM_IP:
        sys.exit("拿不到上游 IP。可以手动指定: python mitm.py --upstream-ip 1.2.3.4")

    if PATCH_JS and JS_RULES_ERR is None:
        # CDN 也提前解析，免得第一个 JS 请求慢一拍
        upstream_ip(CDN_HOST)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(SRV_CRT, SRV_KEY)

    httpd = Server((host, port), Handler, ctx)

    print("中间人已启动")
    print("  监听    : https://%s:%d/" % (host, port))
    print("  冒充    : %s" % HOST)
    print("  上游    : %s (:%d)  ← 走 IP，绕开 hosts，否则会自环"
          % (UPSTREAM_IP, UPSTREAM_PORT))
    print("  改写    : %s 的 highScore/best -> %d"
          % ("、".join(FAKE_PATHS), FAKE_HIGH_SCORE))
    if not PATCH_JS:
        print("  前端JS  : 关（--no-js-patch，只改接口）")
    elif JS_RULES_ERR is not None:
        print("  前端JS  : 不可用 —— 读不到 ../local/patch_score.py 的规则（%s）"
              % JS_RULES_ERR)
    else:
        print("  前端JS  : 开 —— 经 /__cdn/ 中转 %s 的活动资源" % CDN_HOST)
        print("            得分表×%d、maxScore->%d、结算阈值->%d、10s看门狗%s"
              % (JS_SCALE, JS_CAP, JS_RUN_CAP,
                 "保留" if JS_KEEP_WATCHDOG else "关闭"))
        print("            合成逻辑: %s"
              % ("两只最小 -> 直接最高级（1+1=ek）" if JS_MEGA_MERGE
                 else "原样（1+1=2）"))
        print("            出块等级: %s"
              % ("固定 %d 级" % JS_SPAWN_LEVEL if not JS_KEEP_SPAWN
                 else "原样（1~5 级随机）"))
    if INJECT_SHIM:
        print("  垫片    : 开（调试用，会覆盖页面里的 WVSDK —— 真实游戏里别开）")
    print("\n要让客户端真的走这里，还需要（见 trust.py）：")
    print("  1) hosts: 127.0.0.1 %s" % HOST)
    print("  2) 把 %s 装进系统「受信任的根证书颁发机构」" % CA_CRT)
    if PATCH_JS and JS_RULES_ERR is None:
        print("  （前端JS 走同域中转，**不需要**再劫 %s —— 只劫上面一个域名）" % CDN_HOST)
    print("\nCtrl+C 停止。\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")


def selftest(port):
    """不碰系统：用 openssl s_client 连自己，确认 TLS 与改写都正常。"""
    print("[1] 直连本地 MITM（-k 跳过信任校验）...")
    r = sh(["openssl", "s_client", "-connect", "127.0.0.1:%d" % port,
            "-servername", HOST, "-quiet",
            "-verify_return_error"], input="GET /act/orbipom-merge/ HTTP/1.0\r\n\r\n")
    print("    verify_return_error -> rc=%d（预期非 0：自签 CA 未受信）" % r.returncode)

    print("[2] 忽略信任校验，取页面首行 ...")
    r = sh(["openssl", "s_client", "-connect", "127.0.0.1:%d" % port,
            "-servername", HOST, "-quiet", "-verify_quiet"],
           input="GET /act/orbipom-merge/ HTTP/1.0\r\n\r\n")
    line = (r.stdout or "").splitlines()
    print("    %s" % (line[0] if line else "(无响应)"))

    print("[3] 打 profile 接口，看是否被改写 ...")
    r = sh(["openssl", "s_client", "-connect", "127.0.0.1:%d" % port,
            "-servername", HOST, "-quiet"],
           input="POST /act-server/orbipom-merge/api/save/profile HTTP/1.0\r\n"
                 "Content-Length: 0\r\n\r\n")
    tail = (r.stdout or "")[-300:]
    print("    %s" % tail.replace("\r", ""))


def main():
    global FAKE_HIGH_SCORE, INJECT_SHIM, UPSTREAM_IP, UPSTREAM_PORT
    global CDN_IP, CDN_PORT
    global PATCH_JS, JS_SCALE, JS_CAP, JS_RUN_CAP, JS_KEEP_WATCHDOG
    global JS_MEGA_MERGE, JS_SPAWN_LEVEL, JS_KEEP_SPAWN

    ap = argparse.ArgumentParser()
    ap.add_argument("--gencert", action="store_true", help="生成 CA + 服务器证书")
    ap.add_argument("--force", action="store_true",
                    help="重签服务器证书（**不会**动 CA）")
    ap.add_argument("--force-ca", action="store_true",
                    help="连 CA 一起重新生成。系统里装过的旧 CA 会失效，"
                         "必须重新跑 trust.py --install --apply")
    ap.add_argument("--extra-san", action="append", default=[], metavar="DNS名",
                    help="给服务器证书多加一个 SAN。**只在本地 mock 测试时用** —— "
                         "生产路径不需要（中间人连真 CDN 用的是 CDN 自己的真证书）")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=443, help="真实劫持用 443（需管理员）")
    ap.add_argument("--upstream-ip", default=None, metavar="IP",
                    help="上游真实 IP；不给就自动解析（裸 UDP DNS 优先，DoH 兜底）。"
                         "**必须**绕开 hosts，否则会自环")
    ap.add_argument("--upstream-port", type=int, default=443, metavar="N",
                    help="上游端口，默认 443。只在本地 mock 测试时才需要改")
    ap.add_argument("--cdn-ip", default=None, metavar="IP",
                    help="CDN(%s) 的真实 IP，测试用" % CDN_HOST)
    ap.add_argument("--cdn-port", type=int, default=443, metavar="N",
                    help="CDN 端口，默认 443。只在本地 mock 测试时才需要改")
    ap.add_argument("--high-score", type=int, default=5201314, metavar="N",
                    help="把接口里的 highScore/best 改写成 N")

    g = ap.add_argument_group("前端 JS 补丁（改「单局分数上限」）")
    g.add_argument("--no-js-patch", action="store_true",
                   help="不碰前端 JS，只改接口（默认会改）")
    g.add_argument("--js-scale", type=int, default=5201314, metavar="N",
                   help="得分表放大倍数，默认 5201314")
    g.add_argument("--js-cap", type=int, default=5201314, metavar="N",
                   help="maxScore 硬上限，默认 5201314")
    g.add_argument("--js-run-cap", type=int, default=99999999, metavar="N",
                   help="单局结算阈值，原值 1500，默认 99999999")
    g.add_argument("--keep-autosettle", action="store_true",
                   help="保留 10 秒自动结算看门狗（默认关掉）")
    g.add_argument("--no-mega-merge", action="store_true",
                   help="保留原合成逻辑（1+1=2）。默认改成「两只最小的直接合成最高级」")
    g.add_argument("--spawn-level", type=int, default=1, metavar="N",
                   help="出块等级固定为 N（默认 1）。1+1=最高级 的配套 —— "
                        "不钉死出块，合完一只就得再等同级的，等于没改")
    g.add_argument("--keep-spawn", action="store_true",
                   help="保留原出块区间（线上是 1~5 级随机）")

    ap.add_argument("--inject-shim", action="store_true",
                    help="调试用：给代理回来的页面注入 WVSDK 垫片（普通浏览器验证时开，"
                         "真实游戏里千万别开）")
    ap.add_argument("--selftest", action="store_true", help="本地自检后退出")
    args = ap.parse_args()

    FAKE_HIGH_SCORE = args.high_score
    INJECT_SHIM = args.inject_shim
    UPSTREAM_IP = args.upstream_ip
    UPSTREAM_PORT = args.upstream_port
    CDN_IP = args.cdn_ip
    CDN_PORT = args.cdn_port
    PATCH_JS = not args.no_js_patch
    JS_SCALE = args.js_scale
    JS_CAP = args.js_cap
    JS_RUN_CAP = args.js_run_cap
    JS_KEEP_WATCHDOG = args.keep_autosettle
    JS_MEGA_MERGE = not args.no_mega_merge
    JS_SPAWN_LEVEL = args.spawn_level
    JS_KEEP_SPAWN = args.keep_spawn
    if not JS_KEEP_SPAWN and not 1 <= JS_SPAWN_LEVEL <= 11:
        sys.exit("--spawn-level 要在 1~11 之间（11 = 等级总数 ek，线上实测）")

    if args.gencert:
        gencert(force=args.force, extra_san=args.extra_san,
                force_ca=args.force_ca)
        return

    if args.selftest:
        selftest(args.port)
        return

    serve(args.host, args.port)


if __name__ == "__main__":
    main()
