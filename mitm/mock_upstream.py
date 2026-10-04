#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mock 上游：本地复刻两条上游（ef-webview.hypergryph.com 与 web.hycdn.cn），
用来在**不碰外网**的前提下把中间人整条路走一遍。

复刻的是**实测到的行为**：

ef-webview.hypergryph.com
    GET  /act/orbipom-merge/                       -> 200 text/html（引 CDN 上的 JS）
    POST /act-server/orbipom-merge/api/role/login  -> 200 + Set-Cookie
    POST /act-server/orbipom-merge/api/save/profile
          有 cookie -> 200 {"code":0,"data":{"best":99999,...},"msg":""}
          没 cookie -> 401 {"message":"未登录","reason":"UN_LOGIN"}

web.hycdn.cn
    GET  /endfield/webview/.../act/orbipom-merge-XaVa5Tz/index.3d8293.js
         -> 200 application/javascript，里面含**真实的六处补丁模式**

JS 里的模式是从 local/site/821.67c1cf.js 抄的真串，所以中间人那几条正则
能不能匹配、改了会不会出错，在这里就能验。

    python mock_upstream.py --port 9443
"""

import argparse
import hashlib
import http.server
import json
import os
import ssl
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRV_CRT = os.path.join(HERE, "certs", "server.crt")
SRV_KEY = os.path.join(HERE, "certs", "server.key")

CDN_ACT = ("https://web.hycdn.cn/endfield/webview/unn3irGqmsvyaKnFbTug/"
           "act/orbipom-merge-XaVa5Tz/")

# 故意用**线上原始写法**：绝对 CDN 地址
PAGE = ("""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>融合！山团团！</title>
<link href="{c}favicon-hg.ico" rel="icon">
<script src="https://web.hycdn.cn/static/js/umd/react/react@18.3.1.js"></script>
<script defer src="{c}index.3d8293.js"></script>
</head><body><div id="root"></div></body></html>""").format(c=CDN_ACT)

# 入口 chunk：只有 publicPath（r.p）和 chunk 映射 —— **补丁规则不在这个文件里**，
# 和真实情况一样（规则在懒加载的 821.67c1cf.js 里）。这样才测得出「扫 chunk」那段。
ENTRY_JS = """/* mock entry */
r.p="{c}";
var chunkMap={{146:"dec021",162:"c2d254",821:"67c1cf",965:"fc780b"}};
function loadChunk(id){{ return fetch(r.p + id + "." + chunkMap[id] + ".js"); }}
""".format(c=CDN_ACT)

# 玩法 chunk：六处待补丁的模式，抄的是线上真串
GAME_JS = """/* mock gameplay chunk */
var eS=[1,3,6,10,15,21,28,36,45,55,66];
var ey={{maxScore:99999,spawnLevelMin:1,spawnLevelMax:5,redLineY:8}};
var e_=buildLevels(),ek=e_.length;          // ek = 等级总数（线上实测 11）
// 下面这行是 devtools 面板的基线快照（线上是 lT）。写的是 ey.xxx 而不是数字，
// **不能被出块补丁误改** —— 所以 mock 里也放一份，用来验这条。
var lT={{spawnLevelMin:ey.spawnLevelMin,spawnLevelMax:ey.spawnLevelMax}};
function nextSpawnLevel(){{var{{spawnLevelMin:e,spawnLevelMax:t}}=ey;
  return e+Math.floor(Math.random()*(t-e+1));}}
function onMerge(level){{ return Math.min(ey.maxScore, eS[level-1]); }}
function processMerges(list){{
  for(var r of list){{
    var d=r.level===ek,h=d?ek:r.level+1;
    if(d) renderer.playMergeFadeOut(); else spawn(h);
  }}
}}
if(r.score<1500&&e.score>=1500){{ settle(); }}
setInterval(function(){{ if("playing"===r&&n>i&&0===e&&t()){{ settle(); }} }},10000);
"""

PROFILE_OK = json.dumps({"code": 0, "data": {"best": 99999, "isNewBest": False},
                         "msg": ""}).encode()
PROFILE_401 = json.dumps({"message": "\u672a\u767b\u5f55", "reason": "UN_LOGIN"},
                         ensure_ascii=False).encode()


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):
        sys.stderr.write("  [mock] %-14s %s %s\n"
                         % (self.headers.get("host", "?"), self.command, self.path))

    def _send(self, code, body, ctype, extra=None):
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_maybe_304(self, body, ctype):
        """带 ETag 的可缓存响应：客户端带 If-None-Match 命中就回 304。

        这是**真实 CDN 的行为**，也是「JS 改了没生效」的元凶：
        上游一回 304，客户端就用自己缓存里的原始文件，改写等于没做。
        中间人必须把条件请求头剥掉，所以这里要有 304 能力才测得出来。

        ETag 用 md5 而不是内置 hash() —— 后者每个进程都不同（PYTHONHASHSEED），
        重启一次 ETag 就变，测起来没法复现。
        """
        etag = '"%s"' % hashlib.md5(body).hexdigest()[:12]
        if self.headers.get("if-none-match") == etag:
            self.send_response(304)
            self.send_header("etag", etag)
            self.send_header("content-length", "0")
            self.end_headers()
            return
        self._send(200, body, ctype, {"etag": etag})

    def _dispatch(self):
        n = int(self.headers.get("content-length") or 0)
        if n:
            self.rfile.read(n)
        host = (self.headers.get("host") or "").split(":")[0]
        p = self.path.split("?")[0]

        # ---- CDN ----
        if host == "web.hycdn.cn":
            if p.endswith(".js"):
                name = p.rsplit("/", 1)[-1]
                body = GAME_JS if name.startswith("821.") else ENTRY_JS
                return self._send_maybe_304(body.encode(),
                                            "application/javascript; charset=utf-8")
            return self._send_maybe_304(b"/* asset */", "application/octet-stream")

        # ---- ef-webview ----
        if p == "/act/orbipom-merge/":
            return self._send_maybe_304(PAGE.encode(), "text/html; charset=utf-8")

        if p.endswith("/api/role/login"):
            return self._send(200, b'{"code":0,"data":{},"msg":""}',
                              "application/json",
                              {"set-cookie": "v1d5-orbipom-merge=mocksess; Path=/; "
                                             "Secure; HttpOnly"})

        if p.endswith("/api/save/profile"):
            if "v1d5-orbipom-merge=" in (self.headers.get("cookie") or ""):
                return self._send(200, PROFILE_OK, "application/json")
            return self._send(401, PROFILE_401, "application/json")

        return self._send(404, b'{"message":"not found"}', "application/json")

    do_GET = do_POST = do_HEAD = _dispatch


class Server(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9443)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()

    if not (os.path.isfile(SRV_CRT) and os.path.isfile(SRV_KEY)):
        sys.exit("没有证书：%s\n先跑 python mitm.py --gencert" % SRV_CRT)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(SRV_CRT, SRV_KEY)
    httpd = Server((a.host, a.port), H)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print("mock 上游 https://%s:%d/  (cert=%s)" % (a.host, a.port, SRV_CRT))
    print("  冒充 ef-webview.hypergryph.com 与 web.hycdn.cn（按 Host 头分流）")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")


if __name__ == "__main__":
    main()
