#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
《明日方舟：终末地》WebView 活动「融合！山团团！」(orbipom-merge)
请求体加解密工具。

自包含单文件，零第三方依赖，Python >= 3.6。

用法:
    python orbipom.py --score 1145         # 指定分数

u8_token 从哪来（按优先级，全程不需要抓包）:
    1. --u8 参数
    2. .u8_token 缓存
    3. 游戏日志 %USERPROFILE%\\AppData\\LocalLow\\Hypergryph\\<游戏>\\sdklogs\\HGWebview.log
       —— 游戏客户端每次打开 WebPortal 都会把带 u8_token 的完整链接写进去
    4. CEF 缓存 %LOCALAPPDATA%\\PlatformProcess\\Cache\\data_1
       —— webview 的 Chromium 缓存，URL 落在里面（文件被占用，需特殊读取）
    5. 以上都没有才让你手动粘一次

    也就是说：只要在游戏里点开过一次该活动页，本工具就能自己找到 token。

缓存里有多个 token 怎么办（换过账号就会这样）:
    一个 token 只对得上一个角色。工具会拿每个候选去 POST /api/role/login
    建会话、再 POST /api/role/sync 读回 {roleId, nickname, uid}，据此认人：
      * 只有一个角色       → 直接用，不问
      * 多个角色           → 列出来让你选（绝不猜，猜错就把分提交到别人号上）
      * 已锁定 / --role N  → 直接挑 roleId=N 的那个
    身份结果缓存进 .u8_roles.json，一个 token 只认一次，之后零网络开销。

缓存文件（均在 .gitignore 内，勿提交）:
    .u8_token       活动会话令牌
    .u8_server      活动区服号   —— 活动链接里的 &server=N
    .u8_role        锁定的 roleId —— 认过人就记下来，下次不用再问
    .u8_roles.json  token→角色身份对照表

提交分数只用 u8_token（活动接口的 x-role-token）。它取自活动链接，
无法从账号信息推导，粘一次即缓存。

加密方案（还原自前端 chunk 821.js）:
    d = base64( iv(12) || AES-128-GCM(key, iv, JSON.stringify(payload)) )
    key = T[i] ^ N[i]     # T/N 为前端硬编码常量数组
"""

import argparse
import base64
import gzip
import http.cookiejar
import json
import os
import re
import socket
import ssl
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

# 活动域
ACT = "https://ef-webview.hypergryph.com/act-server/orbipom-merge"
SERVER_ID = "1"

U8_CACHE = os.path.join(HERE, ".u8_token")
U8_SERVER = os.path.join(HERE, ".u8_server")   # 活动链接里的 &server=N，默认 "1"
U8_ROLE = os.path.join(HERE, ".u8_role")       # 锁定的 roleId，用于在多个候选里认人
ROLES_FILE = os.path.join(HERE, ".u8_roles.json")  # token → 角色身份，认一次存一次

# 游戏客户端会把每次打开的 WebPortal 链接（含 u8_token）写进这个日志。
# 因此无需抓包 —— 在游戏里点开活动页，再读日志即可。
LOG_REL = os.path.join("AppData", "LocalLow", "Hypergryph",
                       "%s", "sdklogs", "HGWebview.log")
LOG_GAMES = ("Endfield", "Arknights")

OK, NO, AR = "[+]", "[-]", "[>]"


# ======================================================== hosts 劫持绕过 ===
# 如果用过 mitm/ 那套（hosts 把活动域指到 127.0.0.1），本机上**任何**连这个域名的
# 程序都会被劫到本地服务上，这个工具也不例外 —— 表现为 502 或者连到自己。
# 这里在检测到「域名被解析到回环」时自动改用 DoH 拿真实 IP：
# 只改 TCP 连接的地址，SNI / Host 仍是真实域名，证书校验照常。

_UPSTREAM_HOST = "ef-webview.hypergryph.com"
_REAL_IP = None
_ORIG_GETADDRINFO = socket.getaddrinfo

_DNS_SERVERS = ("223.5.5.5", "119.29.29.29", "114.114.114.114", "8.8.8.8")
_DOH = ("https://dns.alidns.com/resolve?name={h}&type=A",
        "https://doh.pub/dns-query?name={h}&type=A")


def _udp_dns_a(host, server, timeout=5):
    """最小 DNS 客户端：UDP 直查 A 记录。

    优先用这个而不是 DoH —— 本机 DoH 会被网络层中间人拦掉（证书链不干净），
    裸 UDP 53 不经过 TLS，反而能过。
    """
    import random
    import struct
    tid = random.randint(0, 0xFFFF)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
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


def _resolve_real_ip(host):
    """拿真实 IP：先裸 UDP DNS，再退 DoH。"""
    for srv in _DNS_SERVERS:
        try:
            ip = _udp_dns_a(host, srv)
            if ip:
                return ip
        except Exception:
            continue
    for tpl in _DOH:
        try:
            req = urllib.request.Request(tpl.format(h=host),
                                         headers={"accept": "application/dns-json"})
            with _opener().open(req, timeout=8) as r:
                data = json.loads(r.read().decode("utf-8"))
            ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
            if ips:
                return ips[0]
        except Exception:
            continue
    return None


def _patched_getaddrinfo(host, port, *a, **kw):
    if host == _UPSTREAM_HOST and _REAL_IP:
        return _ORIG_GETADDRINFO(_REAL_IP, port, *a, **kw)
    return _ORIG_GETADDRINFO(host, port, *a, **kw)


def bypass_hosts():
    """活动域被 hosts 指到本机时，改成直连真实 IP。"""
    global _REAL_IP
    try:
        infos = _ORIG_GETADDRINFO(_UPSTREAM_HOST, 443, type=socket.SOCK_STREAM)
        addrs = {i[4][0] for i in infos}
    except Exception:
        return False
    if not addrs or not addrs <= {"127.0.0.1", "::1"}:
        return False                     # 没被劫持，什么都不用做
    ip = _resolve_real_ip(_UPSTREAM_HOST)
    if not ip:
        print("%s hosts 把 %s 指到了本机，UDP/DoH 都拿不到真实 IP —— "
              "先确认网络，或用 mitm/trust.py --uninstall 去掉 hosts 条目"
              % (NO, _UPSTREAM_HOST))
        return False
    _REAL_IP = ip
    socket.getaddrinfo = _patched_getaddrinfo
    print("%s 检测到 hosts 劫持，已绕过 -> %s" % (OK, ip))
    return True


# ------------------------------------------------ 系统代理：默认绕过 ---
# 本机常挂着抓包代理（ProxyPin / Charles / Fiddler）并把它设成了系统代理。
# 这类代理一开「HTTPS 解密」就用它自己的 CA 重签证书，而 Python 不认这个 CA，
# 于是报：
#     URLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed:
#                self-signed certificate in certificate chain
# 症状很迷惑：浏览器好好的（它信那个 CA），只有 Python 挂；而且开关一拨就变，
# 看起来像「网络时好时坏」。
#
# 活动接口是公开 HTTPS，本来就不需要代理，所以默认**直连**。
# 想用代理抓包就设环境变量 ORBIPOM_USE_PROXY=1。

_USE_PROXY = os.environ.get("ORBIPOM_USE_PROXY", "").strip().lower() \
    not in ("", "0", "false", "no")
_ROUTE_NOTED = False
_TRUST_NOTE = False

# 信任库为空时，退而求其次去这些地方找 CA 包。
# 第 1、2 条是重点：MSYS2 / Git-Bash 的 CA 包在 /usr/ssl 下，
# 而它的 Python 却指向 mingw64 前缀里那个**空的** etc/ssl/certs。
_CA_BUNDLES = (
    r"C:\msys64\usr\ssl\certs\ca-bundle.crt",
    r"C:\msys64\usr\ssl\cert.pem",
    r"C:\msys64\mingw64\etc\ssl\cert.pem",
    r"C:\Program Files\Git\usr\ssl\certs\ca-bundle.crt",
    r"C:\Program Files\Git\mingw64\etc\ssl\certs\ca-bundle.crt",
    r"C:\Program Files\Git\mingw64\ssl\certs\ca-bundle.crt",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
)


def _trust_store_empty(ctx):
    """信任库里一个 CA 都没有 —— 这种「静默失败」是最坑的一类。"""
    try:
        return not ctx.cert_store_stats().get("x509_ca")
    except Exception:
        return False


def _note_trust(n):
    global _TRUST_NOTE
    if _TRUST_NOTE:
        return
    _TRUST_NOTE = True
    if n:
        print("%s 这个 Python 的信任库是空的（它不读 Windows 证书存储）—— "
              "已补 %d 个根证书后继续" % (AR, n))
    else:
        print("%s 这个 Python 的信任库是空的，也没找到可用的根证书包 —— HTTPS 必然失败。\n"
              "        这不是网络问题，换个解释器就好：py -3 或 "
              "%%LOCALAPPDATA%%\\Programs\\Python\\Python39\\python.exe" % (NO,))


def _ssl_context():
    """建默认 SSL 上下文；**信任库为空时自己补根证书**。

    为什么需要：MSYS2 / Git-Bash 自带的 Python 虽然是 win32 构建，但**不读 Windows
    证书存储**（连 `ssl.enum_certificates` 都不存在），而它的 OpenSSL 又指向
    `C:\\msys64\\mingw64\\etc\\ssl\\cert.pem` —— 没装 ca-certificates 时那个目录是空的。
    结果是信任库为空，所有 HTTPS 都报 `self-signed certificate in certificate chain`，
    看着像「网络被中间人劫持」，其实跟网络一点关系都没有。

    而 Windows 的有效 PATH 是「系统 PATH + 用户 PATH」拼接，`C:\\msys64\\mingw64\\bin`
    常常排在官方版 Python 前面 —— 于是 `python xxx.py` 命中 msys64 版、报证书错，
    而 `C:\\...\\Python39\\python.exe xxx.py` 一切正常。同一个脚本、同一个目录，
    换种调用方式结果就不同，极容易误判成「网络时好时坏」。
    """
    ctx = ssl.create_default_context()
    if not _trust_store_empty(ctx):
        return ctx

    n = 0
    # ① 官方版 Python：直接读 Windows ROOT 存储（msys64 版没这个函数）
    enum = getattr(ssl, "enum_certificates", None)
    if enum is not None:
        try:
            for der, enc, trust in enum("ROOT"):
                if enc != "x509":
                    continue
                try:
                    ctx.load_verify_locations(cadata=der)   # bytes = DER
                    n += 1
                except Exception:
                    pass
        except Exception:
            pass

    # ② 再退到机器上现成的 CA 包
    if not n:
        cands = []
        try:
            import certifi
            cands.append(certifi.where())
        except Exception:
            pass
        cands.extend(_CA_BUNDLES)
        for path in cands:
            if path and os.path.isfile(path):
                try:
                    ctx.load_verify_locations(cafile=path)
                    n += 1
                    break
                except Exception:
                    pass

    _note_trust(n)
    return ctx


def _effective_proxy():
    """本次请求**实际**会走的代理，None = 直连。

    两个方向都要判：只有显式开了 ORBIPOM_USE_PROXY 才会走代理；
    默认情况下 _opener() 挂的是空 ProxyHandler，系统代理已被绕过。
    """
    if not _USE_PROXY:
        return None
    try:
        ps = urllib.request.getproxies()
    except Exception:
        ps = {}
    return ps.get("https") or ps.get("http") or None


def _note_route():
    """把「这次请求走哪条路」说一次 —— 两个方向都说，免得证书报错时找错方向。"""
    global _ROUTE_NOTED
    if _ROUTE_NOTED:
        return
    _ROUTE_NOTED = True
    p = _effective_proxy()
    if p:
        print("%s 走代理 %s（ORBIPOM_USE_PROXY=%s）—— TLS 由它解密，证书报错先找它"
              % (AR, p, os.environ.get("ORBIPOM_USE_PROXY")))
        return
    try:
        ps = urllib.request.getproxies()
    except Exception:
        ps = {}
    sp = ps.get("https") or ps.get("http")
    if sp:
        print("%s 检测到系统代理 %s —— 已绕过直连（要用它抓包请设 ORBIPOM_USE_PROXY=1）"
              % (AR, sp))


def _opener(cj=None):
    """建 opener。默认挂一个空的 ProxyHandler 把系统代理关掉。"""
    handlers = []
    if not _USE_PROXY:
        handlers.append(urllib.request.ProxyHandler({}))     # 空 dict = 不走代理
    if cj is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(cj))
    handlers.append(urllib.request.HTTPSHandler(context=_ssl_context()))
    _note_route()
    return urllib.request.build_opener(*handlers)


def _connect_via_proxy(proxy, host, port, timeout=8):
    """按 HTTP 代理的规矩发 CONNECT，返回隧道里的裸 socket。

    代理 URL 形如 http://127.0.0.1:64969。这样探到的证书，
    才是 urllib 走代理时**真正看到**的那一张。
    """
    u = urllib.parse.urlsplit(proxy if "://" in proxy else "http://" + proxy)
    s = socket.create_connection((u.hostname or "127.0.0.1", u.port or 8080),
                                 timeout=timeout)
    try:
        s.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
                   % (host, port, host, port)).encode("ascii"))
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(1)
            if not chunk:
                raise IOError("代理在 CONNECT 阶段就断了")
            buf += chunk
            if len(buf) > 8192:
                raise IOError("代理 CONNECT 响应异常")
        head = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        if " 200" not in head:
            raise IOError("代理拒绝 CONNECT: %s" % head)
        return s
    except Exception:
        s.close()
        raise


def _peer_issuer(host=None, port=443, timeout=8, via_proxy=None):
    """拿「实际在应答的那一方」的证书签发者 —— 用来点名是谁在解密 TLS。

    via_proxy 给代理 URL 时，先 CONNECT 再握手，探到的就是**走代理那条路**看到的
    证书；不给就直连。两者结论可能完全不同，别混着用 —— 之前就是拿裸 socket 的
    结果去解释「其实走了代理」的失败，把方向带偏了。

    只做 TLS 握手，**不发送任何 HTTP 请求**，所以不会泄露 token。

    注意：verify_mode=CERT_NONE 时 getpeercert() 返回的是**空字典**（不是 None），
    必须走 binary_form 自己解 DER —— 踩过一次。
    """
    host = host or _UPSTREAM_HOST
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    der = None
    try:
        if via_proxy:
            s = _connect_via_proxy(via_proxy, host, port, timeout)
        else:
            s = socket.create_connection((host, port), timeout=timeout)
        with s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
    except Exception:
        return None
    if not der:
        return None

    # 解 DER：优先用 CPython 自带的解码器（内部 API，失败就退到手工扫 CN）
    try:
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write(ssl.DER_cert_to_PEM_cert(der))
            info = ssl._ssl._test_decode_cert(path)
            issuer = dict(x[0] for x in info.get("issuer", ()))
            return issuer.get("commonName") or issuer.get("organizationName")
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
    except Exception:
        pass

    # 兜底：在 DER 里找可打印的 CN 串（够用就行）
    import re as _re
    text = der.decode("latin-1")
    hits = _re.findall(r"[\x20-\x7e]{6,64}", text)
    for h in hits:
        if any(k in h.lower() for k in ("ca", "proxy", "pin", "charles",
                                       "fiddler", "mitm", "trustasia")):
            return h
    return None


def _net_hint(err, host=None):
    """把 SSL/代理类错误翻译成人话，并点名实际应答方。返回附加说明。

    关键：探测必须走**和失败请求同一条路**。请求走了代理、却用裸 socket 直连去探，
    探到的是另一张证书 —— 拿它下结论会把方向彻底带偏（踩过）。
    """
    text = "%s" % err
    if "CERTIFICATE_VERIFY_FAILED" not in text and "self-signed certificate" not in text:
        return ""

    proxy = _effective_proxy()
    who = _peer_issuer(host=host, via_proxy=proxy)   # 同一条路，才有可比性
    real = bool(who) and "trustasia" in who.lower()

    # ① 路径里有代理 —— 最常见，也最可能是自己挖的坑
    if proxy:
        lines = ["证书校验失败：本次请求走了代理 %s，TLS 是它解密的，"
                 "而 Python 不认它的 CA。" % proxy]
        if who:
            lines.append("        隧道里拿到的证书由「%s」签发 —— 就是它在解密。" % who)
        if _USE_PROXY:
            lines.append("        而代理是显式开的：ORBIPOM_USE_PROXY=%s。"
                         "活动接口是公开 HTTPS，不需要代理，清掉它即可："
                         % os.environ.get("ORBIPOM_USE_PROXY"))
            lines.append("          PowerShell:  Remove-Item Env:ORBIPOM_USE_PROXY")
            lines.append("          cmd:         set ORBIPOM_USE_PROXY=")
        else:
            lines.append("        二选一：① 关掉代理的「HTTPS 解密 / 抓包」开关；或")
            lines.append("                  ② 把它的根证书装进「受信任的根证书颁发机构」。")
        lines.append("        看完整环境诊断：python tools/netdiag.py")
        return "\n".join(lines)

    # ② 信任库是空的 —— 解释器的问题，跟网络、跟代理都无关。
    #    必须排在「拿到真证书 ⇒ 偶发」前面：网络确实通、证书确实是真的，
    #    但校验库一个 CA 都没有，照样过不了。
    if _trust_store_empty(ssl.create_default_context()):
        lines = ["证书校验失败：这个 Python 的**信任库是空的**（一个 CA 都没有）——",
                 "        跟网络、跟代理都没关系，是它不读 Windows 证书存储。",
                 "        MSYS2 / Git-Bash 自带的 python.exe 就是这样：OpenSSL 指向",
                 "        C:\\msys64\\mingw64\\etc\\ssl\\cert.pem，没装 ca-certificates 时那个目录是空的。",
                 "        而 Windows 的 PATH 是「系统 PATH + 用户 PATH」拼起来的，",
                 "        C:\\msys64\\mingw64\\bin 常排在官方版 Python 前面 —— 于是裸 `python` 命中它、",
                 "        报证书错，写全路径调 Python39\\python.exe 却一切正常。"]
        if who:
            lines.append("        （顺带一提：对端证书是真的，由「%s」签发 —— 网络没被拦。）" % who)
        lines.append("        最省事：换官方版解释器 ——")
        lines.append("          py -3 claim_all.py")
        lines.append("          %LOCALAPPDATA%\\Programs\\Python\\Python39\\python.exe claim_all.py")
        lines.append("        或给这个 Python 补 CA 包（工具已自动尝试，看开头的 [>] 提示）。")
        return "\n".join(lines)

    # ③ 直连仍然失败
    if real:
        # 同一条路重连拿到的就是真证书 —— 这次失败是偶发的（握手被重置等）
        return ("证书校验失败，但同一条路重连一次拿到的正是真服务器证书（由「%s」签发）——\n"
                "        说明这次是偶发失败，直接重跑一次即可。\n"
                "        反复出现的话把 `python tools/netdiag.py` 的输出发出来。" % who)

    lines = ["证书校验失败 —— 已确认是直连，说明中间人在网络层解密 TLS，"
             "而 Python 不信任它的 CA。"]
    if who:
        lines.append("        实际应答方证书由「%s」签发 —— 就是它在解密。" % who)
    else:
        lines.append("        连握手都拿不到证书，先把抓包/中间人软件整个关掉再试。")
    lines.append("        二选一：① 关掉它的「HTTPS 解密 / 抓包」开关；或")
    lines.append("                  ② 把它的根证书装进「受信任的根证书颁发机构」。")
    lines.append("        看完整环境诊断：python tools/netdiag.py")
    return "\n".join(lines)




def _pad(s, width):
    """按**显示宽度**左对齐补齐：中文占 2 列，直接 %-10s 会错位。"""
    w = sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)
    return s + " " * max(0, width - w)


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


def _read(resp):
    raw = resp.read()
    if resp.headers.get("Content-Encoding") == "gzip":
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8", "replace")
    try:
        return json.loads(text)
    except ValueError:
        return text


def _act_headers(token, server):
    sid = str(server or SERVER_ID)
    return {
        "content-type": "application/json",
        "accept": "application/json, text/plain, */*",
        "x-role-token": token,
        "x-role-server-id": sid,
        "origin": "https://ef-webview.hypergryph.com",
        "referer": "https://ef-webview.hypergryph.com/act/orbipom-merge/"
                   "?u8_token=%s&server=%s" % (token, sid),
        "user-agent": "Mozilla/5.0",
    }


def role_info(token, server=None, retries=3):
    """用 token 建会话并读回角色身份，返回 (dict|None, 说明)。

    先 POST /api/role/login 拿会话 cookie（这一步是必须的，直接打 role/sync
    会 401 UN_LOGIN），再 POST /api/role/sync 拿身份：
        {roleId, serverId, uid, nickname, avatar}
    roleId 就是「这个 token 属于哪个角色」的唯一答案 —— 缓存里堆了多个
    token 时，靠它区分谁是谁，而不是靠猜。

    纯只读：不提交任何分数。用于 where 与多候选时的自动认人。
    """
    sid = str(server or SERVER_ID)
    hdr = _act_headers(token, sid)
    last = None
    for attempt in range(retries):
        cj = http.cookiejar.CookieJar()
        opener = _opener(cj)

        def post(path, payload):
            req = urllib.request.Request(ACT + path,
                                         data=json.dumps(payload).encode(),
                                         method="POST", headers=hdr)
            try:
                with opener.open(req, timeout=30) as r:
                    return r.status, _read(r)
            except urllib.error.HTTPError as e:
                return e.code, _read(e)

        try:
            st, body = post("/api/role/login", {"token": token, "serverId": sid})
            if not (isinstance(body, dict) and body.get("code") == 0):
                return None, "role/login 未通过 (HTTP %s %s)" % (st, body)
            st, body = post("/api/role/sync", {})
            if isinstance(body, dict) and body.get("code") == 0 and body.get("data"):
                return body["data"], None
            return None, "role/sync 无数据 (%s)" % body
        except Exception as e:               # 连接重置 / 超时 —— 服务端会限流
            last = e
            if attempt < retries - 1:
                time.sleep(1.5 * (attempt + 1))
    hint = _net_hint(last, _UPSTREAM_HOST)
    return None, "网络异常 %s: %s%s" % (type(last).__name__, last,
                                        ("\n        " + hint) if hint else "")


# ========================================================== u8_token ===
# 活动接口的 x-role-token 就是活动链接里的 u8_token，前端不做任何加工。
# 它无法由账号链路推导（账号 token / oauth token / code 均被 role/login 拒绝），
# 只能取自活动链接本身 —— 或本机的游戏日志 / CEF 缓存，见 u8_from_local()。


def parse_activity_input(text):
    """从用户输入里抠出 (u8_token, server)。

    server 取自链接的 `&server=N`，即 role/login 请求体里的 `serverId`。
    拿不到就返回 None，由调用方回退到默认值。
    """
    s = (text or "").strip()
    if not s:
        return "", None
    if "u8_token=" not in s:
        return s, None                      # 纯 token，无 server 信息
    rest = s.split("u8_token=", 1)[1]
    token = rest
    for sep in ("&", "#", " "):
        token = token.split(sep, 1)[0]
    token = token.strip()

    server = None
    for key in ("server=", "serverId=", "server_id="):
        if key in s:
            v = s.split(key, 1)[1]
            for sep in ("&", "#", " "):
                v = v.split(sep, 1)[0]
            v = v.strip()
            if v:
                server = v
                break
    return token, server


# ---------------------------------------------------- 从游戏日志自动取 token ---
# 游戏客户端每次打开 WebPortal 都会把完整链接写进 HGWebview.log：
#     [error] [main_controller.cpp] ... WebPortal url: https://ef-webview...?u8_token=...
# 所以「在游戏里点开一次活动页」= 日志里就有 token，完全不需要抓包。

_LOG_MARK = "WebPortal url: "


def find_webview_logs():
    """返回本机存在的 HGWebview.log 路径（Endfield / Arknights）。"""
    home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    out = []
    for g in LOG_GAMES:
        p = os.path.join(home, LOG_REL % g)
        if os.path.exists(p):
            out.append(p)
    return out


def u8_from_log(activity="orbipom-merge"):
    """从 HGWebview.log 里抠出最近一条活动链接的 (token, server, 日志路径)。

    activity 为 None 时接受任意 ef-webview 链接；给定时只认 URL 含该名字的。
    取**最后一条**命中（日志是追加写的，最后即最新）。找不到返回三个 None。
    """
    best = None
    for path in find_webview_logs():
        try:
            with open(path, "rb") as f:
                raw = f.read().decode("utf-8", "replace")
        except Exception:
            continue
        for chunk in raw.split(_LOG_MARK)[1:]:
            url = chunk.split()[0] if chunk.split() else ""
            if not url.startswith("http"):
                continue
            if activity and activity not in url:
                continue
            best = (url, path)
    if not best:
        return None, None, None
    url, path = best
    tok, srv = parse_activity_input(urllib.parse.unquote(url))
    return tok, srv, path


# ------------------------------------------------ 从 CEF 缓存自动取 token ---
# 游戏客户端的 webview 是 Chromium 内核，打开活动页后 URL 会落进
#   %LOCALAPPDATA%\PlatformProcess\Cache\data_1
# 该文件被进程占用，必须先复制再读。里面会累积多次会话，取最后一条即最新。

def _cef_cache_path():
    base = os.environ.get("LOCALAPPDATA") or os.path.join(
        os.environ.get("USERPROFILE") or os.path.expanduser("~"), "AppData", "Local")
    return os.path.join(base, "PlatformProcess", "Cache", "data_1")


def _read_locked_file(path):
    """读取被其他进程占用的文件（CEF 缓存就是这么被锁的）。

    Windows 上 open()/shutil 用默认共享模式会被拒绝，必须用 CreateFileW
    显式声明 FILE_SHARE_READ|WRITE|DELETE —— 与 PowerShell 的 Copy-Item 等效。
    非 Windows 或调用失败时回退普通读取。
    """
    if os.name != "nt":
        with open(path, "rb") as f:
            return f.read()
    import ctypes
    from ctypes import wintypes

    GENERIC_READ = 0x80000000
    SHARE = 0x1 | 0x2 | 0x4          # READ | WRITE | DELETE
    OPEN_EXISTING = 3
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = ctypes.c_void_p
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                ctypes.c_void_p]
    h = k32.CreateFileW(path, GENERIC_READ, SHARE, None, OPEN_EXISTING, 0, None)
    if not h or h == ctypes.c_void_p(-1).value:
        raise OSError("CreateFileW 失败 err=%s" % ctypes.get_last_error())
    try:
        chunks, buf = [], ctypes.create_string_buffer(1 << 20)
        n = wintypes.DWORD(0)
        while k32.ReadFile(h, buf, len(buf), ctypes.byref(n), None) and n.value:
            chunks.append(buf.raw[:n.value])
        return b"".join(chunks)
    finally:
        k32.CloseHandle(h)


def u8_candidates_from_cef(activity="orbipom-merge"):
    """从 CEF 缓存里捞出该活动的所有 u8_token（去重，保持文件顺序）。"""
    path = _cef_cache_path()
    if not os.path.exists(path):
        return []
    try:
        raw = _read_locked_file(path).decode("utf-8", "replace")
    except Exception:
        return []

    pat = re.compile(r"act/" + re.escape(activity) + r"/?\?u8_token=([^&\"\s\\]{60,})")
    out = []
    for m in pat.finditer(raw):
        tok = urllib.parse.unquote(m.group(1))
        if tok not in out:
            out.append(tok)
    return out


def u8_from_local(activity="orbipom-merge"):
    """本机自动找 token。返回 (token, server, 说明, 其余候选)。

    优先游戏日志（带 server 参数），其次 CEF 缓存。都找不到返回 (None,)*3 + []。
    """
    tok, srv, path = u8_from_log(activity)
    if tok:
        return tok, srv, "游戏日志 %s" % os.path.basename(os.path.dirname(os.path.dirname(path))), []

    cands = u8_candidates_from_cef(activity)
    if cands:
        # 文件里靠后的更可能是最近一次会话
        newest = cands[-1]
        return newest, None, "CEF 缓存 (%d 个候选)" % len(cands), cands[:-1][::-1]
    return None, None, None, []


# ------------------------------------------------- 认人：token → 角色身份 ---
# 换过账号之后，缓存和 CEF 里会同时躺着好几个 u8_token。它们都能用，但属于
# 不同角色。只按「谁在文件里更靠后」去猜会猜错，所以这里统一用 role/sync
# 把每个 token 对应的 roleId/nickname 认出来，再按 roleId 挑人。
#
# 结果落盘到 .u8_roles.json：一个 token 的身份是固定的，认一次就够，
# 之后每次运行都是零网络开销，也不会把服务端敲到限流。

_ROLE_MEMO = None


def _load_roles():
    global _ROLE_MEMO
    if _ROLE_MEMO is None:
        try:
            with open(ROLES_FILE, encoding="utf-8") as f:
                _ROLE_MEMO = json.load(f)
        except Exception:
            _ROLE_MEMO = {}
    return _ROLE_MEMO


def _save_roles():
    try:
        with open(ROLES_FILE, "w", encoding="utf-8") as f:
            json.dump(_ROLE_MEMO or {}, f, ensure_ascii=False, indent=1)
    except Exception:
        pass


def identify(token, server=None, refresh=False):
    """查 token 属于哪个角色。返回 (身份 dict|None, 说明)。

    带磁盘缓存：同一 token 只真正打一次网络。refresh=True 强制重查。
    """
    memo = _load_roles()
    if not refresh and token in memo:
        return memo[token], None
    ident, err = role_info(token, server)
    if ident:
        memo[token] = ident
        _save_roles()
    return ident, err


def describe(ident):
    """把身份压成一行给人看的字串。"""
    if not ident:
        return "身份未知"
    return "%s (roleId=%s, uid=%s)" % (ident.get("nickname") or "?",
                                       ident.get("roleId"), ident.get("uid"))


def collect_candidates(activity="orbipom-merge", use_cache=True):
    """本机全部候选，按优先级排列并去重。返回 [(来源, token, server)]。"""
    rows = []
    if use_cache:
        try:
            with open(U8_CACHE, encoding="utf-8") as f:
                v = f.read().strip()
        except Exception:
            v = ""
        if v:
            rows.append(("缓存 .u8_token", v, load_server()))

    tok, srv, path = u8_from_log(activity)
    if tok:
        rows.append(("游戏日志", tok, srv))

    for i, c in enumerate(u8_candidates_from_cef(activity), 1):
        rows.append(("CEF[%d]" % i, c, None))

    out, seen = [], set()
    for label, t, s in rows:
        if t in seen:
            continue
        seen.add(t)
        out.append((label, t, s))
    return out


def group_by_role(rows, pin=None, activity="orbipom-merge"):
    """按 roleId 归并候选。返回 (分组列表, 已找到 pin)。

    分组：[{roleId, ident, members:[(来源, token, server)]}]，保持首次出现顺序。
    认不出身份的归 roleId=None 一组。
    pin 非空时，一旦认出该 roleId 就立刻停下 —— 省掉多余的网络请求。
    """
    groups, index = [], {}
    for label, tok, srv in rows:
        ident, err = identify(tok, srv or load_server())
        rid = (ident or {}).get("roleId")
        if pin and rid and str(rid) == pin:
            groups.append({"roleId": rid, "ident": ident,
                           "members": [(label, tok, srv)], "hit": True})
            return groups, True
        if rid not in index:
            index[rid] = len(groups)
            groups.append({"roleId": rid, "ident": ident, "members": [], "hit": False})
        groups[index[rid]]["members"].append((label, tok, srv))
    return groups, False


def _pick_group(g, src_suffix=""):
    """从一组里挑一个 token —— 组内越靠后的越可能是最近一次会话。"""
    label, tok, srv = g["members"][-1]
    return tok, label + src_suffix, srv or load_server(), g["ident"]


def resolve_u8(cli_u8, role=None, use_cache=True, ask=None):
    """挑一个 u8_token，并保证挑到的是「对的那个人」。

    优先级：--u8 > .u8_token 缓存 > 游戏日志 > CEF 缓存。
    候选多于一个时按 roleId 认人（role/sync），而不是按文件位置瞎猜：
      * --role 或 .u8_role 里锁定的 roleId 优先；
      * 本机只有一个角色时直接用；
      * 出现多个角色又锁不定时交给 ask 回调让你选，绝不替你决定。

    返回 (token, 来源, server, 身份)。彻底拿不到返回 (None, None, None, None)。
    """
    pin = str(role) if role else load_role()

    # --- 0) 显式指定，最高优先级；顺手把身份锁下来 ---
    if cli_u8:
        tok, srv = parse_activity_input(cli_u8)
        ident, _ = identify(tok, srv)
        save_u8(tok, srv)
        if ident:
            save_role(ident.get("roleId"))
        return tok, "--u8 参数", srv or load_server(), ident

    rows = collect_candidates(use_cache=use_cache)
    if not rows:
        return None, None, None, None

    # --- 1) 只有一个候选：不用问 ---
    if len(rows) == 1:
        label, tok, srv = rows[0]
        ident, _ = identify(tok, srv or load_server())
        if ident:
            save_role(ident.get("roleId"))
        return tok, label, srv or load_server(), ident

    # --- 2) 有 pin：直接找到对应角色，命中就停 ---
    if pin:
        groups, hit = group_by_role(rows, pin=pin)
        if hit:
            tok, src, srv, ident = _pick_group(groups[-1], "（锁定 roleId=%s）" % pin)
            save_u8(tok, srv)
            save_role(pin)          # --role 显式指定过就把它变成默认
            return tok, src, srv, ident
        print("%s 锁定的 roleId=%s 不在本机候选里，继续按其它方式判断。" % (AR, pin))

    # --- 3) 认全部候选，看本机到底有几个角色 ---
    groups, _ = group_by_role(rows)
    known = [g for g in groups if g["roleId"]]

    if len(known) == 1:
        tok, src, srv, ident = _pick_group(known[0], "（本机唯一角色）")
        save_u8(tok, srv)
        save_role(known[0]["roleId"])
        return tok, src, srv, ident

    # --- 4) 多个角色：交给你选，猜错就会把分提交到别人号上 ---
    if len(known) > 1:
        if ask:
            idx = ask(known)
            if idx is not None:
                tok, src, srv, ident = _pick_group(known[idx], "（已选定）")
                save_u8(tok, srv)
                save_role(known[idx]["roleId"])
                return tok, src, srv, ident
        return None, None, None, None

    # --- 5) 一个身份都认不出来（token 全过期/网络不通）：退回第一个候选 ---
    tok, src, srv, ident = _pick_group(groups[0], "（身份未知）")
    return tok, src, srv, ident


def save_u8(v, server=None):
    try:
        with open(U8_CACHE, "w", encoding="utf-8") as f:
            f.write(v)
    except Exception:
        pass
    if server:
        try:
            with open(U8_SERVER, "w", encoding="utf-8") as f:
                f.write(str(server))
        except Exception:
            pass


def load_server():
    """读活动链接里记下的 serverId，缺省回退 SERVER_ID。"""
    try:
        with open(U8_SERVER, encoding="utf-8") as f:
            v = f.read().strip()
        return v or SERVER_ID
    except Exception:
        return SERVER_ID


def save_role(role_id):
    """记住「这次用的是哪个角色」。下次候选里混着多个账号时靠它认人。"""
    if not role_id:
        return
    try:
        with open(U8_ROLE, "w", encoding="utf-8") as f:
            f.write(str(role_id))
    except Exception:
        pass


def load_role():
    """读锁定的 roleId；没有则返回空串（表示还没锁定，需要判断）。"""
    try:
        with open(U8_ROLE, encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""


def drop_u8_cache(keep_role=False):
    """删除 u8 缓存（token 失效时调用，下次会重新解析）。

    keep_role=True 保留角色锁定 —— 换 token 不等于换角色，多数情况下
    还想继续提交到同一个人。
    """
    paths = [U8_CACHE, U8_SERVER]
    if not keep_role:
        paths.append(U8_ROLE)
    for p in paths:
        try:
            os.remove(p)
        except Exception:
            pass


# ========================================================== 活动会话 ===
# role/login 不返回业务数据，只负责下发会话 cookie。之后所有活动接口
# （save/score、reward、reward/claim、save/profile …）都必须带上它 ——
# 只给 x-role-token 而没 cookie，一律 401 {"reason":"UN_LOGIN"}。
#
# 服务端对密集请求会限流（无响应直接关连接 → RemoteDisconnected），
# 所以下面统一带一次退避重试，调用方之间也要留间隔。


def act_session(u8, server=None):
    """建会话。返回 (call, cj, err)。

    call(path, payload=None, method=None) → (status, body)
      payload 为 None 时默认 GET，否则 POST。带一次重试。
    err 非 None 表示建会话失败，此时 call 为 None。
    """
    sid = str(server or SERVER_ID)
    cj = http.cookiejar.CookieJar()
    opener = _opener(cj)
    hdr = _act_headers(u8, sid)

    def call(path, payload=None, method=None):
        verb = method or ("POST" if payload is not None else "GET")
        data = json.dumps(payload).encode() if payload is not None else None
        last = None
        for attempt in range(2):
            req = urllib.request.Request(ACT + path, data=data,
                                         method=verb, headers=hdr)
            try:
                with opener.open(req, timeout=30) as r:
                    return r.status, _read(r)
            except urllib.error.HTTPError as e:
                return e.code, _read(e)
            except Exception as e:          # 连接重置 / 超时 / DNS 等
                last = e
                if attempt == 0:
                    time.sleep(1)
        hint = _net_hint(last, _UPSTREAM_HOST)
        return None, "网络异常 %s: %s%s" % (type(last).__name__, last,
                                            ("\n        " + hint) if hint else "")

    st, body = call("/api/role/login", {"token": u8, "serverId": sid})
    if st != 200 or not (isinstance(body, dict) and body.get("code") == 0):
        return None, cj, "会话建立失败: HTTP %s %s" % (st, body)
    return call, cj, None


def session_ident(call, u8=None):
    """用已有会话读角色身份，顺手写进身份表。拿不到返回 None。"""
    st, body = call("/api/role/sync", {})
    if isinstance(body, dict) and body.get("code") == 0 and body.get("data"):
        ident = body["data"]
        if u8:
            memo = _load_roles()
            memo[u8] = ident
            _save_roles()
        return ident
    return None


def submit_score(u8, score, server=None):
    """建会话 → 提交分数。两步都必需。

    返回 (status, body, login_ok, ident)。login_ok=False 说明 u8_token 没换到
    会话，多半是 token 已过期 —— 调用方据此决定是否丢缓存重取。
    ident 是这次真正提交到的角色，用来确认没提交到别人号上。
    """
    call, cj, err = act_session(u8, server)
    if err:
        print("    %s %s" % (NO, err))
        return None, err, False, None
    print("    %s 会话已建立 (cookie: %s)" % (OK, ", ".join(c.name for c in cj) or "无"))

    ident = session_ident(call, u8)
    print("%s 目标角色: %s" % (AR, describe(ident) if ident else "查询失败"))

    d = encrypt({"score": score})
    print("%s 加密完成  {\"score\":%d}" % (AR, score))
    print("    d = %s" % d)
    print("%s 提交分数 ..." % AR)
    st, body = call("/api/save/score", {"d": d})
    print("    HTTP %s  %s" % (st, body))
    return st, body, True, ident


# ============================================================ 奖励 ===
# 端点（与前端 821.67c1cf.js 里 reward:{...} 那张表逐字对应）：
#   GET  /api/reward             → 任务列表 {tasks:[...], claimableCount:N}
#                                  每条 {id, current, target, status, claimable}
#   POST /api/reward/claim       {taskId} → {taskId, status}
#   POST /api/reward/claim-all   （无 body）→ 一次性领掉全部可领的
#   POST /api/reward/share       （无 body）→ 上报「完成分享 1 次」
# 四个都要会话 cookie；/api/reward 是 GET-only（POST 会 404）。
#
# status 是共享枚举（前端 eN）：0=CLAIMED、1=DELIVERED，两者在列表里都显示「已领取」；
# null 表示还没完成。claimable 优先于 status —— 只要 claimable 为真，按钮就是「领取」。
#
# claim 是幂等的：已领过的再领不会报错，也不会重复发奖。
# 返回里的 status 0/1 对应「本次发放 / 之前已领过」（实测口径，见 --raw）。


def _raw(label, obj):
    """--raw 时把原始 JSON 打出来，便于对着抓包核对。"""
    print("    %s %s" % (label, json.dumps(obj, ensure_ascii=False, indent=2)
                         .replace("\n", "\n    ")))


def reward_tasks(call):
    """拉取奖励任务列表。返回 (tasks, claimableCount, err)。"""
    st, body = call("/api/reward", None, "GET")
    if st != 200 or not (isinstance(body, dict) and body.get("code") == 0):
        return None, 0, "HTTP %s %s" % (st, body)
    data = body.get("data") or {}
    return data.get("tasks") or [], data.get("claimableCount") or 0, None


def reward_claim(call, task_id):
    """领取单个任务。返回 (ok, body)。"""
    st, body = call("/api/reward/claim", {"taskId": task_id})
    ok = isinstance(body, dict) and body.get("code") == 0
    return ok, body


def reward_claim_all(call):
    """一次性领取全部可领任务。返回 (ok, body)。"""
    st, body = call("/api/reward/claim-all", {})
    ok = isinstance(body, dict) and body.get("code") == 0
    return ok, body


def reward_share(call):
    """上报「完成分享 1 次」。返回 (ok, body)。"""
    st, body = call("/api/reward/share", {})
    ok = isinstance(body, dict) and body.get("code") == 0
    return ok, body


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


def _ask_role(groups):
    """本机出现多个角色时，列出来让你选。返回下标；直接回车返回 None。"""
    print("\n%s 本机候选里认出了 %d 个不同角色 —— 不能替你猜：" % (AR, len(groups)))
    for i, g in enumerate(groups):
        ident = g["ident"] or {}
        print("    [%d] %s roleId=%s  uid=%s  来源: %s"
              % (i + 1, _pad(ident.get("nickname") or "?", 12), _pad(g["roleId"], 12),
                 _pad(ident.get("uid") or "?", 11),
                 ", ".join(m[0] for m in g["members"])))
    print("    提交到别人的号上就麻烦了，所以这里让你自己定。")
    raw = _ask("    要提交到哪个角色 [1-%d，回车放弃]: " % len(groups))
    if not raw:
        return None
    try:
        idx = int(raw) - 1
    except ValueError:
        print("    %s 看不懂，放弃" % NO)
        return None
    if 0 <= idx < len(groups):
        return idx
    print("    %s 超出范围，放弃" % NO)
    return None


def run_full_flow(a):
    print("=" * 62)
    print("融合！山团团！(orbipom-merge) 全流程")
    print("=" * 62)

    # ---- u8_token：先查缓存；缓存里有多个角色时按 roleId 认人，不瞎猜 ----
    u8, src, server, ident = resolve_u8(a.u8, role=a.role, ask=_ask_role)
    if u8:
        print("%s u8_token 来源: %s (%d chars)  serverId=%s"
              % (OK, src, len(u8), server or SERVER_ID))
        if ident:
            print("%s 对应角色: %s" % (OK, describe(ident)))

    if not u8:
        if a.u8 or load_role() or collect_candidates():
            print("\n%s 本机有候选，但认不出/定不了是哪个角色。" % NO)
            print("    跑 `python orbipom.py where` 看候选与角色对照表，")
            print("    再用 `--role <roleId>` 指定，或直接粘一条活动链接。")
        else:
            print("\n%s 需要 u8_token —— 它是提交分数的唯一凭证。" % NO)
            print("    从活动链接里复制 ?u8_token= 后面那串即可，整条链接也行：")
            print("    https://ef-webview.hypergryph.com/act/orbipom-merge/?u8_token=XXXX&server=1")
            print("    粘一次会存进 .u8_token，以后就不用再管。")
        tok, srv = parse_activity_input(
            _ask("    u8_token / 活动链接 (留空则只生成密文，不提交): "))
        if tok:
            u8 = tok
            server = srv or server
            src = "手动粘贴"
            save_u8(tok, srv)
            ident, _ = identify(tok, srv)
            if ident:
                save_role(ident.get("roleId"))
                print("    %s 已锁定角色 %s" % (OK, describe(ident)))
            print("    %s 已缓存到 .u8_token%s"
                  % (OK, ("（server=%s）" % srv) if srv else ""))

    score = a.score if a.score is not None else _ask_int("%s 分数: " % AR)

    if not u8:
        print("\n%s 没有 u8_token，无法提交。分数密文已生成：" % NO)
        print("    %s" % encrypt({"score": score}))
        return 1

    st, body, login_ok, ident = submit_score(u8, score, server)
    if ident:
        save_role(ident.get("roleId"))

    # 会话失效时，先在本机候选里翻其它 token（多次会话会并存，且都在有效期）。
    # 有角色锁定时只翻同一个角色的，避免把分提交到别人号上。
    if not login_ok:
        pin = load_role()
        for label, c, csrv in collect_candidates(use_cache=False):
            if c == u8:
                continue
            if pin:
                ci, _ = identify(c, csrv or server)
                if not ci or str(ci.get("roleId")) != pin:
                    continue
            print("%s 换本机候选 %s 重试 ..." % (AR, label))
            st, body, login_ok, ident = submit_score(c, score, csrv or server)
            if login_ok:
                save_u8(c, csrv or server)
                if ident:
                    save_role(ident.get("roleId"))
                u8 = c
                break

    # 缓存和本机都没有能用的：丢掉缓存，让用户粘一个
    if not login_ok and src:
        print("\n%s 缓存里的 u8_token 都用不了，已清除缓存。" % NO)
        drop_u8_cache(keep_role=True)
        tok, srv = parse_activity_input(
            _ask("    请粘贴新的 u8_token 或活动链接 (留空放弃): "))
        if tok:
            save_u8(tok, srv)
            server = srv or server
            ident, _ = identify(tok, srv)
            if ident:
                save_role(ident.get("roleId"))
                print("%s 新 u8_token 已缓存，锁定角色 %s，重试提交 ..."
                      % (OK, describe(ident)))
            else:
                print("%s 新 u8_token 已缓存，重试提交 ..." % OK)
            st, body, login_ok, ident = submit_score(tok, score, server)
        else:
            print("%s 未提供新 token，放弃" % NO)

    print("=" * 62)
    return 0 if login_ok else 1


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


def cmd_where():
    """where —— 列出 token 从哪找到的，以及每个 token 属于哪个角色。只读。"""
    def mask(t):
        return "%s...%s (%d)" % (t[:10], t[-6:], len(t))

    print("u8_token 来源排查（只读，不会提交任何分数）\n")

    logs = find_webview_logs()
    cefp = _cef_cache_path()
    print("  来源位置")
    print("    缓存文件   : %s" % U8_CACHE)
    print("    角色锁定   : %s%s" % (U8_ROLE,
          ("  → roleId=%s" % load_role()) if load_role() else "  （未锁定）"))
    print("    游戏日志   : %s" % (", ".join(logs) if logs else "未找到 HGWebview.log"))
    print("    CEF 缓存   : %s" % cefp)

    rows = collect_candidates()
    if not rows:
        print("\n%s 本机没有任何候选。" % NO)
        print("    请先在游戏里点开一次该活动页，或手动粘一次活动链接。")
        return 1

    print("\n  本机候选（共 %d 个，按优先级）" % len(rows))
    print("    %s %s %s" % (_pad("来源", 16), _pad("token", 22), "角色"))
    print("    " + "-" * 70)
    for label, tok, srv in rows:
        ident, err = identify(tok, srv or load_server())
        if ident:
            role = "%s  roleId=%s" % (ident.get("nickname") or "?", ident.get("roleId"))
        else:
            role = "无法识别（%s）" % (err or "token 已失效")
        print("    %s %s %s" % (_pad(label, 16), _pad(mask(tok), 22), role))

    groups, _ = group_by_role(rows)
    known = [g for g in groups if g["roleId"]]
    print("\n  按角色归并：%d 个角色" % len(known))
    for g in known:
        srcs = ", ".join(m[0] for m in g["members"])
        print("    %s roleId=%s  uid=%s  ← %s"
              % (_pad(g["ident"].get("nickname") or "?", 10), _pad(g["roleId"], 12),
                 _pad(g["ident"].get("uid") or "?", 11), srcs))

    print("\n  提示：候选多于一个角色时，用 --role <roleId> 指定要提交到谁，")
    print("        选定后会自动记进 %s，以后不用再指定。" % os.path.basename(U8_ROLE))
    return 0 if known else 1


def _open_activity(a):
    """公共前置：挑 token → 建会话 → 读身份。返回 (call, ident, err)。

    所有需要打活动接口的子命令都先走这一步 —— 会话 cookie 与 x-role-token
    必须成对且互相一致，缺一个都是 401。
    """
    u8, src, server, ident = resolve_u8(a.u8, role=a.role, ask=_ask_role)
    if not u8:
        print("%s 没有可用的 u8_token。" % NO)
        print("    先在游戏里点开一次活动页，或跑 `python orbipom.py where` 看候选。")
        return None, None, "no token"
    print("%s u8_token 来源: %s (%d chars)  serverId=%s"
          % (OK, src, len(u8), server or SERVER_ID))

    call, cj, err = act_session(u8, server)
    if err:
        print("%s %s" % (NO, err))
        print("    token 多半已过期，跑 `python orbipom.py reset` 清缓存后重取。")
        return None, None, err

    if not ident:
        ident = session_ident(call, u8)
    print("%s 目标角色: %s" % (AR, describe(ident) if ident else "查询失败"))
    return call, ident, None


def _reward_table(tasks):
    """奖励任务对齐表格。id 是服务端原始值，不翻译，免得看走眼。"""
    print("    %s %s %s %s" % (_pad("任务", 14), _pad("进度", 12),
                               _pad("状态", 10), "可领取"))
    print("    " + "-" * 50)
    for t in tasks:
        state = "已领取" if t.get("status") else "未领取"
        print("    %s %s %s %s" % (_pad(str(t.get("id")), 14),
                                   _pad("%s/%s" % (t.get("current"), t.get("target")), 12),
                                   _pad(state, 10),
                                   "是" if t.get("claimable") else ""))


def cmd_reward(a):
    """reward —— 列出奖励任务进度与领取状态。只读，不会领任何东西。"""
    print("奖励任务（只读）\n")
    call, ident, err = _open_activity(a)
    if err:
        return 1

    if a.raw:
        st, body = call("/api/reward", None, "GET")
        print("\n%s GET /api/reward  ->  HTTP %s" % (AR, st))
        _raw("原始响应:", body)
        if st != 200 or not (isinstance(body, dict) and body.get("code") == 0):
            print("%s 拉取失败" % NO)
            return 1
        data = body.get("data") or {}
        tasks, claimable = data.get("tasks") or [], data.get("claimableCount") or 0
    else:
        tasks, claimable, err = reward_tasks(call)
        if err:
            print("%s 拉取失败: %s" % (NO, err))
            return 1

    print()
    _reward_table(tasks)
    print("\n    可领取: %d 个" % claimable)
    if claimable:
        print("    领取: python orbipom.py claim            # 领全部可领的")
        print("          python orbipom.py claim-all        # 同上，但走服务端的批量接口")
        print("          python orbipom.py claim <taskId>   # 只领指定的")
    return 0


def cmd_claim(a):
    """claim [taskId ...] —— 领取奖励；不带 taskId 则领全部可领的。

    服务端 claim 是幂等的：已领过的再领不会报错也不会重复发奖，返回里
    status=0 表示「本次发放」，status=1 表示「之前已领过」。
    """
    want = [x for x in (a.args or []) if x]
    print("领取奖励 —— %s\n" % ("指定: %s" % ", ".join(want) if want else "全部可领"))
    call, ident, err = _open_activity(a)
    if err:
        return 1

    tasks, claimable, err = reward_tasks(call)
    if err:
        print("%s 拉取任务列表失败: %s" % (NO, err))
        return 1
    print()
    _reward_table(tasks)
    print()

    if want:
        by_id = {t.get("id"): t for t in tasks}
        targets = []
        for tid in want:
            if tid in by_id:
                targets.append(by_id[tid])
            else:
                print("%s 没有这个任务: %s" % (NO, tid))
    else:
        targets = [t for t in tasks if t.get("claimable")]

    if not targets:
        print("%s 没有可领取的任务，什么都没做。" % NO)
        return 0

    ok_n = 0
    for t in targets:
        tid = str(t.get("id"))
        ok, body = reward_claim(call, tid)
        data = body.get("data") if isinstance(body, dict) else None
        st = (data or {}).get("status")
        if a.raw:
            print("    POST /api/reward/claim {\"taskId\": \"%s\"}  ->  %s"
                  % (tid, json.dumps(body, ensure_ascii=False)))
        if ok:
            ok_n += 1
            why = "本次发放" if st == 0 else ("之前已领过" if st == 1 else "已领取")
            print("%s %s  %s" % (OK, _pad(tid, 14), why))
        else:
            code = body.get("code") if isinstance(body, dict) else "?"
            msg = body.get("msg") if isinstance(body, dict) else body
            print("%s %s  失败 code=%s %s" % (NO, _pad(tid, 14), code, msg))
        time.sleep(0.8)          # 服务端会限流，逐条之间留点间隔

    print("\n完成: %d/%d" % (ok_n, len(targets)))
    return 0


def cmd_claim_all(a):
    """claim-all —— 走服务端的批量接口 POST /api/reward/claim-all（无 body）。

    和 `claim`（逐个 taskId 调）效果一样，但只有一次请求、也不吃限流。
    前端点「一键领取」走的就是这个。
    """
    print("一键领取 —— POST /api/reward/claim-all（无 body）\n")
    call, ident, err = _open_activity(a)
    if err:
        return 1

    tasks, claimable, err = reward_tasks(call)
    if not err:
        print()
        _reward_table(tasks)
        print("\n    服务端认为可领取: %d 个" % claimable)

    print("\n%s 发送 claim-all ..." % AR)
    ok, body = reward_claim_all(call)
    if a.raw or not ok:
        _raw("原始响应:", body)
    if not ok:
        code = body.get("code") if isinstance(body, dict) else "?"
        msg = body.get("msg") if isinstance(body, dict) else body
        print("%s 失败 code=%s %s" % (NO, code, msg))
        return 1

    data = body.get("data") if isinstance(body, dict) else None
    print("%s 成功  data=%s" % (OK, json.dumps(data, ensure_ascii=False)
                                if data is not None else "(空)"))

    tasks, claimable, err = reward_tasks(call)
    if not err:
        print("\n    领取后:")
        print()
        _reward_table(tasks)
        print("\n    可领取: %d 个" % claimable)
    return 0


def cmd_share(a):
    """share —— 上报「完成分享 1 次」POST /api/reward/share（无 body）。

    真实客户端是先调起原生分享，分享成功后再打这个接口上报。
    这里直接上报 —— 用途是补上「分享」任务的进度，不涉及真的分享。
    前端有节流：本地记录 shared 为真就不再上报（见 e8.shouldReportShare）。
    """
    print("上报分享 —— POST /api/reward/share（无 body）\n")
    call, ident, err = _open_activity(a)
    if err:
        return 1

    print("%s 发送 share ..." % AR)
    ok, body = reward_share(call)
    if a.raw or not ok:
        _raw("原始响应:", body)
    if not ok:
        code = body.get("code") if isinstance(body, dict) else "?"
        msg = body.get("msg") if isinstance(body, dict) else body
        print("%s 失败 code=%s %s" % (NO, code, msg))
        return 1
    print("%s 成功  data=%s" % (OK, json.dumps(body.get("data"),
                                              ensure_ascii=False)
                                if isinstance(body, dict) else "(空)"))

    tasks, claimable, err = reward_tasks(call)
    if not err:
        print("\n    当前任务状态:")
        print()
        _reward_table(tasks)
        print("\n    可领取: %d 个" % claimable)
    return 0


def cmd_reset():
    """清除活动缓存，用于切换游戏角色。

    u8_token 绑在游戏角色上，换了角色必须清掉，否则分数会继续提交到旧角色。
    .u8_role（角色锁定）一并清掉 —— 否则下次会去找旧角色。
    .u8_roles.json（身份对照表）保留：它只是缓存，认错了可以删。
    """
    targets = ((U8_CACHE, "活动会话令牌"), (U8_SERVER, "区服号 serverId"),
               (U8_ROLE, "角色锁定 roleId"))
    for path, desc in targets:
        name = os.path.basename(path)
        if not os.path.exists(path):
            print("     %-14s 本就不存在  %s" % (name, desc))
            continue
        try:
            os.remove(path)
            print("%s %-14s 已删除      %s" % (NO, name, desc))
        except Exception as e:
            print("%s %-14s 删除失败: %s" % (NO, name, e))

    if os.path.exists(ROLES_FILE):
        print("     %-14s 保留        token→角色 对照表（想重置就手动删）"
              % os.path.basename(ROLES_FILE))

    print("\n下次运行会重新在本机候选里认角色；若出现多个角色会让你选。")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="orbipom-merge 请求体加解密工具",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", nargs="?",
                    choices=["selftest", "key", "encrypt", "decrypt", "reset",
                             "where", "reward", "claim", "claim-all", "share"],
                    help="子命令；省略则进入全流程")
    ap.add_argument("args", nargs="*", help="子命令参数")
    ap.add_argument("--score", type=int)
    ap.add_argument("--raw", action="store_true",
                    help="reward / claim / claim-all / share：把原始 JSON 响应也打出来")
    ap.add_argument("--u8", help="u8_token 或整条活动链接；留空则读 .u8_token 缓存")
    ap.add_argument("--role", help="指定要提交到的 roleId（本机有多个账号时用）")
    a = ap.parse_args(argv)

    # 活动域若被 hosts 指到本机（mitm 那套），先绕开，否则请求会打到本地服务上
    if a.cmd not in ("selftest", "key", "encrypt", "decrypt"):
        bypass_hosts()

    if a.cmd == "selftest":
        selftest()
        return 0
    if a.cmd == "key":
        print("KEY =", KEY.hex())
        return 0
    if a.cmd == "reset":
        return cmd_reset()
    if a.cmd == "where":
        return cmd_where()
    if a.cmd == "reward":
        return cmd_reward(a)
    if a.cmd == "claim":
        return cmd_claim(a)
    if a.cmd == "claim-all":
        return cmd_claim_all(a)
    if a.cmd == "share":
        return cmd_share(a)
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

    return run_full_flow(a)


if __name__ == "__main__":
    sys.exit(main())
