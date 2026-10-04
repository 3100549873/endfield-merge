#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地活动站：静态托管 site/，并把 /act-server/* 反向代理到官方接口。

为什么要代理：
  前端 axios 的 baseURL 原本是 `https://ef-webview.hypergryph.com/act-server/orbipom-merge`
  且 `withCredentials: true`。页面跑在 127.0.0.1 上时这是跨域 + 第三方 cookie，
  浏览器会直接拦掉。fetch.py 已把它改成相对路径 `/act-server/orbipom-merge`，
  这里再原样转发到官方主机 —— 对浏览器来说全程同源，cookie 正常。

Set-Cookie 会做三处改写，否则浏览器会丢弃：
  - 去掉 `Domain=`     → 变成 127.0.0.1 的 host-only cookie
  - 去掉 `Secure`      → 允许 http://127.0.0.1
  - `SameSite=None` → `SameSite=Lax`（不配 Secure 时 None 会被拒）

`--fake-high-score N` 会改写服务端响应里的 `highScore` / `best`：
首页那个「最高分: xxxx」是服务端 `/api/save/profile` 下发的历史最高分，
不是前端配置里的 `maxScore`（后者根本不显示），所以**只有在这里改才看得见**。
注意它只影响本地站，改不了真实游戏客户端，也改不了服务端。

用法:
    python serve.py                       # 默认 127.0.0.1:8765
    python serve.py --port 9000
    python serve.py --fake-high-score 9999999
"""

import argparse
import http.client
import http.server
import os
import re
import socket
import socketserver
import ssl
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
SITE = os.path.join(HERE, "site")
TOKEN_FILE = os.path.join(HERE, "..", ".u8_token")

UPSTREAM_HOST = "ef-webview.hypergryph.com"
PROXY_PREFIX = "/act-server/"

DROP_REQ = {"host", "connection", "keep-alive", "proxy-connection", "transfer-encoding",
            "upgrade", "te", "trailer", "accept-encoding"}
DROP_RES = {"connection", "keep-alive", "transfer-encoding", "upgrade", "trailer"}

# --fake-high-score 的值（0 = 不改写）。只作用于本地站。
# 默认开启：首页那个「最高分」是服务端下发的，不在这里改就看不到任何变化。
FAKE_HIGH_SCORE = 9999999

# 改写哪些接口的响应，以及改哪个字段
FAKE_PATHS = ("/api/save/profile", "/api/save/score")
RE_FAKE_FIELD = re.compile(r'("(?:highScore|best)"\s*:\s*)\d+')

MIME = {
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".gif": "image/gif",
    ".ico": "image/x-icon",
    ".mp3": "audio/mpeg",
    ".ogg": "audio/ogg",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
}


def rewrite_set_cookie(value):
    parts = [p.strip() for p in value.split(";")]
    keep = []
    for p in parts:
        low = p.lower()
        if low.startswith("domain="):
            continue
        if low == "secure":
            continue
        if low.startswith("samesite=none"):
            keep.append("SameSite=Lax")
            continue
        keep.append(p)
    return "; ".join(keep)


def rewrite_payload(target, payload):
    """本地调试用：把服务端响应里的 highScore / best 换成指定值。

    只碰这两个字段，且只在 profile / score 两个接口上 —— 排行榜等其它接口不动。
    """
    if not FAKE_HIGH_SCORE or not any(p in target for p in FAKE_PATHS):
        return payload
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return payload
    new = RE_FAKE_FIELD.sub(lambda m: m.group(1) + str(FAKE_HIGH_SCORE), text)
    if new != text:
        sys.stderr.write("  [改写] %s 的 highScore/best -> %d\n" % (target, FAKE_HIGH_SCORE))
    return new.encode("utf-8")


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "orbipom-local/1.0"

    def log_message(self, fmt, *a):
        # 请求行里带着 u8_token，日志里打码，别让它进终端 scrollback / 日志文件
        line = re.sub(r'(u8_token=)[^&\s"]+', r"\1<redacted>", fmt % a)
        sys.stderr.write("  %s %s\n" % (self.address_string(), line))

    # ---------------- 反向代理 ----------------
    def _proxy(self):
        target = self.path[len(PROXY_PREFIX) - len("/act-server/"):]
        if not target.startswith("/"):
            target = "/" + target

        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None

        headers = {}
        for k, v in self.headers.items():
            if k.lower() in DROP_REQ:
                continue
            headers[k] = v
        headers["Host"] = UPSTREAM_HOST
        # 让上游看到的是「官方来源」，避免 Origin/Referer 校验拒绝
        headers["Origin"] = "https://" + UPSTREAM_HOST
        headers["Referer"] = "https://" + UPSTREAM_HOST + "/act/orbipom-merge/"
        headers["Accept-Encoding"] = "identity"

        # 上游是 EdgeOne，偶发直接掐连接（fetch.py 里也遇到过）。只对只读方法重试，
        # 避免把 POST（比如提交分数）重放成两次。
        attempts = 3 if self.command in ("GET", "HEAD") else 1
        resp = None
        payload = b""
        last = None
        for i in range(attempts):
            conn = http.client.HTTPSConnection(
                UPSTREAM_HOST, 443, timeout=30,
                context=ssl.create_default_context())
            try:
                conn.request(self.command, target, body=body, headers=headers)
                resp = conn.getresponse()
                payload = resp.read()
                break
            except Exception as e:
                last = e
                resp = None
                if i < attempts - 1:
                    time.sleep(0.6 * (i + 1))
            finally:
                conn.close()

        if resp is None:
            try:
                self.send_error(502, "upstream failed: %s" % last)
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                pass
            return

        payload = rewrite_payload(target, payload)

        self.send_response(resp.status)
        for k, v in resp.getheaders():
            low = k.lower()
            if low in DROP_RES:
                continue
            if low == "set-cookie":
                self.send_header(k, rewrite_set_cookie(v))
                continue
            if low in ("content-length", "content-encoding"):
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                pass   # 浏览器提前断开，正常现象，别刷 traceback

    # ---------------- 静态文件 ----------------
    def _static(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", ""):
            path = "/index.html"
        rel = urllib.parse.unquote(path).lstrip("/")
        full = os.path.normpath(os.path.join(SITE, rel))
        if not full.startswith(SITE):
            self.send_error(403, "forbidden")
            return
        if not os.path.isfile(full):
            self.send_error(404, "not found: %s" % rel)
            return
        ext = os.path.splitext(full)[1].lower()
        with open(full, "rb") as fh:
            data = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", MIME.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                pass

    def _dispatch(self):
        if self.path.startswith(PROXY_PREFIX):
            self._proxy()
        else:
            self._static()

    do_GET = _dispatch
    do_POST = _dispatch
    do_HEAD = _dispatch
    do_PUT = _dispatch
    do_DELETE = _dispatch


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    global FAKE_HIGH_SCORE

    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--fake-high-score", type=int, default=9999999, metavar="N",
                    help="把服务端响应里的 highScore/best 改写成 N（默认 9999999；"
                         "传 0 表示不改写，恢复服务端原值）")
    args = ap.parse_args()

    FAKE_HIGH_SCORE = args.fake_high_score

    if not os.path.isfile(os.path.join(SITE, "index.html")):
        sys.exit("site/ 还不存在，先跑: python fetch.py")

    token = ""
    if os.path.isfile(TOKEN_FILE):
        token = open(TOKEN_FILE, encoding="utf-8").read().strip()

    base = "http://%s:%d/" % (args.host, args.port)
    print("本地活动站: %s" % base)
    print("静态目录  : %s" % SITE)
    print("接口代理  : %s -> https://%s" % (PROXY_PREFIX, UPSTREAM_HOST))
    if FAKE_HIGH_SCORE:
        print("响应改写  : profile/score 的 highScore/best -> %d（仅本地）" % FAKE_HIGH_SCORE)
    if token:
        enc = token.replace("+", "%2B")
        print("\n打开这个地址（token 里的 + 已编码为 %%2B）：")
        print("  %s?u8_token=%s&channel=1&lang=zh-cn&platform=Windows&server=1&subChannel=1"
              % (base, enc))
    else:
        print("\n没找到 %s，请自行把 u8_token 拼到地址后。" % TOKEN_FILE)
    print("\nCtrl+C 停止。\n")

    srv = Server((args.host, args.port), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")


if __name__ == "__main__":
    main()
