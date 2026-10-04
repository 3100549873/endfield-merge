#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""回归测试：证明「改写」在两种最容易翻车的场景下都真的生效。

`check.py` 是**直连**中间人抓页面的，不带条件请求头，所以它绿了不代表游戏里绿。
这里补两个 check.py 覆盖不到的场景：

  1. **带 `If-None-Match` 打页面**（复现客户端的 304 缓存行为）
     必须仍然返回 200 + 改写过的 body。中间人要是把条件头转给上游，
     上游回 304，客户端就用自己缓存的**原始** HTML —— 里面 JS 还指向
     web.hycdn.cn，补丁永远到不了。这就是「JS 改了没生效」的真正原因。

  2. **带 `If-None-Match` 打玩法 JS**
     同上，必须 200 + 已打补丁（不能被 304 短路）。

  3. **出块补丁不能误伤 devtools 基线**
     线上 `lT` 里有一行 `spawnLevelMin:ey.spawnLevelMin,spawnLevelMax:ey.spawnLevelMax`
     （写的是 `ey.xxx` 不是数字）。出块正则只认数字，这一行必须**原样保留**。

需要一个 mock 上游在跑（见 README「本地 mock 测试」）：

    python mock_upstream.py --port 9443
    python mitm.py --port 8443 --upstream-ip 127.0.0.1 --upstream-port 9443 \
                             --cdn-ip 127.0.0.1 --cdn-port 9443
    python regress.py --port 8443
"""

import argparse
import re
import ssl
import sys
import urllib.request

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

HOST = "ef-webview.hypergryph.com"
PAGE = "/act/orbipom-merge/?u8_token=x&channel=1&lang=zh-cn&platform=Windows"

OK = "\033[32mOK\033[0m" if sys.stderr.isatty() else "OK"
NO = "\033[31m!!\033[0m" if sys.stderr.isatty() else "!!"

results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print("  [%s] %s%s" % (OK if cond else NO, name, ("  " + detail) if detail else ""))


def get(port, path, headers=None):
    """发一个请求，返回 (状态码, 小写化的响应头 dict, body)。

    头必须小写化：`dict(r.headers)` 保留的是服务端发的原始大小写
    （"Cache-Control"），直接 `.get("cache-control")` 会取不到 —— 自己踩过。
    """
    req = urllib.request.Request("https://127.0.0.1:%d%s" % (port, path),
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=20) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8443)
    a = ap.parse_args()
    port = a.port

    print("=== 1. 带 If-None-Match 打页面（必须 200 + 改写后的 body）===")
    st, hd, body = get(port, PAGE, {"If-None-Match": '"whatever"'})
    txt = body.decode("utf-8", "replace")
    n_cdn = txt.count("__cdn/")
    n_left = len(re.findall(r"https://web\.hycdn\.cn/endfield/webview/", txt))
    check("HTTP 200（没被 304 短路）", st == 200, "HTTP %d" % st)
    check("CDN 前缀已转本域", n_cdn > 0, "/__cdn/ 出现 %d 次" % n_cdn)
    check("活动 JS 已无 web.hycdn.cn 残留", n_left == 0, "残留 %d 次" % n_left)
    check("没把 etag 透给客户端", not hd.get("etag"), "etag=%s" % hd.get("etag"))
    check("已加 no-store", "no-store" in (hd.get("cache-control") or ""),
          "cache-control=%s" % hd.get("cache-control"))

    print("\n=== 2. 带 If-None-Match 打玩法 JS（必须 200 + 已打补丁）===")
    srcs = re.findall(r'<script[^>]+src="([^"]+)"', txt)
    act = [u for u in srcs if "orbipom-merge" in u and u.endswith(".js")]
    if not act:
        check("页面里有活动 JS", False, "找不到 <script src>")
        return 1
    entry_path = act[0].split(HOST, 1)[-1]
    st, _h, body = get(port, entry_path)
    entry = body.decode("utf-8", "replace")
    m = re.search(r'\.p="([^"]*?/__cdn/[^"]*)"', entry)
    check("入口 JS publicPath 转本域", bool(m), m.group(1) if m else "没找到 r.p")

    pairs = re.findall(r'(\d{1,4}):"([0-9a-f]{6,})"', entry)
    base = entry_path.rsplit("/", 1)[0] + "/"
    game = None
    for i, h in pairs:
        st, _h, body = get(port, base + "%s.%s.js" % (i, h))
        if st == 200:
            t = body.decode("utf-8", "replace")
            if "maxScore" in t:
                game = t
                break
    check("拿到玩法 chunk", game is not None, "%d 个 chunk" % len(pairs))
    if game is None:
        return 1

    # 再打一次，这次带上 ETag 条件头 —— 这是关键回归点
    st2, _h, body2 = get(port, base + "%s.%s.js" % (i, h), {"If-None-Match": '"x"'})
    g2 = body2.decode("utf-8", "replace")
    check("玩法 JS 也没被 304 短路", st2 == 200 and g2 == game, "HTTP %d" % st2)

    print()
    check("得分表已放大", not re.search(r"eS=\[1,3,6,10", g2))
    check("maxScore 已抬高", not re.search(r"maxScore:99999\b", g2))
    check("结算阈值已抬高", not re.search(r"r\.score<1500", g2))
    check("看门狗已关", '"playing"===r&&!1&&0===e&&t()' in g2)
    check("合成逻辑已改（1+1=最高级）", "h=d||1===r.level?ek:r.level+1" in g2)
    check("出块区间已钉成 1~1", "spawnLevelMin:1,spawnLevelMax:1" in g2)
    check("devtools 基线未被误改",
          "spawnLevelMin:ey.spawnLevelMin,spawnLevelMax:ey.spawnLevelMax" in g2)

    print("\n%s" % ("全部通过。" if all(results) else "有失败项，见上面 [!!]。"))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
