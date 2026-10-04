# -*- coding: utf-8 -*-
"""定位「TLS 证书校验失败」到底卡在哪 —— 把**两条路**分开测。

最常见的两种情况，症状都是 self-signed certificate in certificate chain：

  A. 请求走了代理（本机 HTTP_PROXY/HTTPS_PROXY 指向抓包软件），
     软件开了「HTTPS 解密」，用自己的 CA 重签 —— Python 不认它。
     ★ 此时用裸 socket 直连去探，探到的是**真服务器**证书，
       于是很容易误判成「偶发失败」。所以本脚本专门测「走代理」那条路。

  B. 确实直连，但 Python 的信任库读不出来（create_default_context 在
     Windows 上会静默失败），信任库是空的 —— 服务端链里那个自签名根
     就校验不过。

用法:
    python tools/netdiag.py
把输出整段贴回来即可。
"""
import os
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

HOST = "ef-webview.hypergryph.com"
PORT = 443
URL = "https://%s/act-server/orbipom-merge/api/reward" % HOST


def line(k, v):
    print("  %-24s %s" % (k, v))


def section(t):
    print()
    print("=" * 64)
    print(t)
    print("=" * 64)


def decode_der(der):
    """把 DER 证书解成 dict。优先用 CPython 自带的解码器，失败返回 {}。

    注意：verify_mode=CERT_NONE 时 getpeercert() 返回的是**空字典**（不是 None），
    所以必须走 binary_form 自己解。
    """
    if not der:
        return {}
    try:
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write(ssl.DER_cert_to_PEM_cert(der))
            return ssl._ssl._test_decode_cert(path)
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
    except Exception:
        return {}


def fmt(name):
    return dict(x[0] for x in (name or ()))


def handshake(sock, verify=True):
    """在已有 socket 上握手，返回 (证书 dict, 加密套件, 错误文本)。"""
    ctx = ssl.create_default_context() if verify else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with ctx.wrap_socket(sock, server_hostname=HOST) as ss:
            return decode_der(ss.getpeercert(binary_form=True)), ss.cipher()[0], None
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return {}, None, "%s: %s" % (type(e).__name__, str(e)[:160])


def via_proxy(proxy, timeout=10):
    """按 HTTP 代理的规矩发 CONNECT，返回隧道里的裸 socket。"""
    u = urllib.parse.urlsplit(proxy if "://" in proxy else "http://" + proxy)
    s = socket.create_connection((u.hostname or "127.0.0.1", u.port or 8080),
                                 timeout=timeout)
    try:
        s.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
                   % (HOST, PORT, HOST, PORT)).encode("ascii"))
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


def show_cert(tag, info):
    line(tag + " subject", fmt(info.get("subject")))
    line(tag + " issuer", fmt(info.get("issuer")))
    line(tag + " 有效期至", info.get("notAfter"))


# ---------------------------------------------------------------- 环境
section("1. 环境")
line("python", sys.version.split()[0])
line("exe", sys.executable)
line("OpenSSL", ssl.OPENSSL_VERSION)
for k in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
          "ALL_PROXY", "NO_PROXY", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR",
          "ORBIPOM_USE_PROXY"):
    if os.environ.get(k):
        line("env " + k, os.environ[k])
try:
    PROXIES = urllib.request.getproxies()
except Exception as e:
    PROXIES = {}
    line("getproxies()", "FAIL %s" % e)
else:
    line("getproxies()", PROXIES)
PROXY = PROXIES.get("https") or PROXIES.get("http")
line(">>> 系统代理", PROXY or "（没有）")

# ------------------------------------------------------- 信任库（重点）
section("2. 信任库 —— 直连失败多半出在这里")
ctx = ssl.create_default_context()
try:
    stats = ctx.cert_store_stats()
    line("create_default_context", stats)
    if not stats.get("x509_ca"):
        print("  >>> 信任库是空的！这就是根因：Windows ROOT 存储没读进来。")
except Exception as e:
    line("cert_store_stats", "FAIL %s" % e)

try:
    roots = ssl.enum_certificates("ROOT")
    line("Windows ROOT 证书数", len(roots))
    names = []
    for der, enc, trust in roots:
        info = decode_der(der) if enc == "x509" else {}
        subj = fmt(info.get("subject"))
        cn = subj.get("commonName") or subj.get("organizationName") or ""
        if cn:
            names.append(cn)
    for kw in ("TrustAsia", "DigiCert", "ISRG", "GlobalSign", "Sectigo",
               "Certum", "USERTrust", "Baltimore"):
        hit = [n for n in names if kw.lower() in n.lower()]
        if hit:
            print("  %-24s %s" % ("含 " + kw, hit[:3]))
    # 注意：TrustAsia DV TLS RSA CA 2025 是**中间 CA**，本来就该由服务端下发，
    # ROOT 里没有它是正常的 —— 别拿这一条下结论。真正看的是 3a/5a 能不能过。
    print("  （提示：TrustAsia 是中间 CA，ROOT 里没有它属正常；")
    print("    以第 3 节 3a、第 5 节 5a 的校验结果为准。）")
except Exception as e:
    line("enum_certificates", "FAIL %s" % e)

# ------------------------------------------- 路线 1：直连（绕过所有代理）
section("3. 路线 1 —— 直连（绕过代理）")
try:
    raw = socket.create_connection((HOST, PORT), timeout=15)
    line("实际连到", raw.getpeername())
    raw.close()
except Exception as e:
    line("连接", "FAIL %s: %s" % (type(e).__name__, e))

print()
print("  [3a] 直连 + 校验证书")
try:
    s = socket.create_connection((HOST, PORT), timeout=15)
    info, cipher, err = handshake(s)
    if err:
        line("结果", "FAIL " + err)
    else:
        line("结果", "OK  " + cipher)
        show_cert("对端", info)
except Exception as e:
    line("结果", "FAIL %s: %s" % (type(e).__name__, e))

# ------------------------------------------- 路线 2：走代理（这才是关键）
section("4. 路线 2 —— 走代理（urllib 默认就会走这条）")
if not PROXY:
    print("  没配代理，跳过。")
else:
    line("代理", PROXY)
    try:
        s = via_proxy(PROXY)
        info, cipher, err = handshake(s, verify=False)
        if err:
            line("CONNECT+TLS", "FAIL " + err)
        else:
            line("CONNECT+TLS", "OK  " + cipher)
            show_cert("隧道对端", info)
            iss = fmt(info.get("issuer")).get("commonName", "")
            if "trustasia" not in iss.lower():
                print()
                print("  >>> 走代理拿到的**不是**真服务器证书 —— 就是它在解密 TLS。")
                print("      这与「裸 socket 直连拿到真证书」并不矛盾：两条路不同。")
    except Exception as e:
        line("CONNECT+TLS", "FAIL %s: %s" % (type(e).__name__, str(e)[:160]))

# ------------------------------------------------------------- urllib
section("5. urllib 实测")
print("  [5a] 直连（= 工具里的做法：ProxyHandler({})）")
try:
    op = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with op.open(urllib.request.Request(URL), timeout=15) as r:
        line("结果", "HTTP %s" % r.status)
except urllib.error.HTTPError as e:
    line("结果", "HTTP %s（有响应，链路通）" % e.code)
except Exception as e:
    line("结果", "%s: %s" % (type(e).__name__, str(e)[:160]))

print()
print("  [5b] 走系统代理（= 不挂 ProxyHandler 时的默认行为）")
try:
    op = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with op.open(urllib.request.Request(URL), timeout=15) as r:
        line("结果", "HTTP %s" % r.status)
except urllib.error.HTTPError as e:
    line("结果", "HTTP %s（有响应，链路通）" % e.code)
except Exception as e:
    line("结果", "%s: %s" % (type(e).__name__, str(e)[:160]))

# ------------------------------------------------------------------ 判读
section("6. 怎么读这份输出")
print("  ① 看 5a 和 5b 哪个失败 —— 这就是「直连行不行 / 走代理行不行」。")
print()
print("  ② 5b 失败、5a 成功")
print("     → 问题就在代理上，跟信任库无关。工具默认已绕过它，不该再报错；")
print("       若仍报错，检查是不是自己设了 ORBIPOM_USE_PROXY=1。")
print("       想继续抓包：关掉代理的「HTTPS 解密」开关，或装它的根证书。")
print()
print("  ③ 5a 和 5b 都失败，且第 4 节隧道证书的 issuer 不是 TrustAsia")
print("     → 真有中间人在解密（可能是网络层/TUN）。关掉它再试。")
print()
print("  ④ 5a 和 5b 都失败，但第 4 节 issuer 是 TrustAsia、第 3 节也正常")
print("     → 信任库问题：第 2 节 x509_ca 是 0，或 ROOT 里缺某个根。")
print("       解决：补装缺失的根证书，或设 SSL_CERT_FILE 指向 cacert.pem。")
