#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把「融合！山团团！」活动前端镜像到本地，并打好本地化补丁。

为什么要打补丁（三处，缺一不可）：

1. `index.js` 里的 `r.p`（webpack publicPath）指向 CDN 绝对地址，
   不改的话 chunk / css / 图片还是会回 CDN 拉，本地改 JS 就没意义。
2. `821.js` 里的 axios `baseURL` 是硬编码绝对地址。
   本地页面直连 `ef-webview.hypergryph.com` 属于跨域 + 第三方 cookie，
   现代浏览器会拦；改成相对路径交给 serve.py 反向代理即可。
3. 页面本身不知道自己在游戏里（浏览器没有 WVSDK），会直接判「网络异常」。
   在入口脚本前注入一个 WVSDK 垫片，把 platform 伪装成 "Qt"。

用法:
    python fetch.py             # 增量下载，已存在的文件跳过
    python fetch.py --force     # 全部重下
"""

import argparse
import concurrent.futures
import gzip
import hashlib
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SITE = os.path.join(HERE, "site")

ACT_BASE = ("https://web.hycdn.cn/endfield/webview/"
            "unn3irGqmsvyaKnFbTug/act/orbipom-merge-XaVa5Tz/")
PAGE_URL = "https://ef-webview.hypergryph.com/act/orbipom-merge/"
SDK_URL = "https://web.hycdn.cn/hg_web_sdk/lib/sdk.entry.js"
REACT_URL = "https://web.hycdn.cn/static/js/umd/react/react@18.3.1.js"
REACT_DOM_URL = "https://web.hycdn.cn/static/js/umd/react-dom/react-dom@18.3.1.js"

ENTRY = "index.3d8293.js"
CSS = "821.436dde.css"
API_BASE = "https://ef-webview.hypergryph.com/act-server/orbipom-merge"

# index.js 里的 webpack chunk 映射 {chunkId: hash}
CHUNKS = {
    22: "87916e", 66: "330956", 146: "dec021", 162: "c2d254", 180: "b634eb",
    246: "adcfa0", 257: "02f4ce", 307: "71d4c5", 325: "33831a", 398: "05c9fd",
    421: "5fc137", 442: "e458c0", 476: "7c2765", 501: "e5ec0e", 675: "d23493",
    690: "6a7afc", 740: "a3ea73", 821: "67c1cf", 939: "fca171", 965: "fc780b",
}

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")

CTX = ssl.create_default_context()

# 入口脚本前注入的 WVSDK 垫片：让页面以为自己在游戏客户端里（platform=Qt）
SHIM = """<script>
(function () {
  if (!window.WVSDK) {
    window.WVSDK = {
      ENV: {}, callback: {}, API: {},
      platform: "Qt",
      invoke: function () { return Promise.resolve({ status: 0, errorCode: 0 }); },
      invokeWithReturnValue: function () { return Promise.resolve({ status: 1, errorCode: 0 }); }
    };
  }
})();
</script>"""

ASSET_RE = re.compile(
    r'assets/[A-Za-z0-9_\-./]+\.'
    r'(?:png|jpe?g|svg|webp|gif|mp3|ogg|m4a|json|woff2?|ttf|otf|ico)', re.I)
URL_RE = re.compile(r'url\(([^)]+)\)')


def log(msg):
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def get(url, referer=PAGE_URL, attempts=5):
    """CDN（EdgeOne）会随机掐连接，所以带退避重试。"""
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={
                "user-agent": UA,
                "accept": "*/*",
                "referer": referer,
            })
            with urllib.request.urlopen(req, timeout=40, context=CTX) as r:
                body = r.read()
                enc = (r.headers.get("content-encoding") or "").lower()
            if "gzip" in enc or body[:2] == b"\x1f\x8b":
                body = gzip.decompress(body)
            return body
        except Exception as e:  # noqa: BLE001 - 网络层什么都可能抛
            last = e
            if i < attempts - 1:
                time.sleep(1.5 * (i + 1))
    raise last


def write(rel, data, force=False):
    path = os.path.join(SITE, rel.replace("/", os.sep))
    if os.path.exists(path) and not force:
        return "skip"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return "ok"


def localize(text):
    """把 CDN 绝对地址改成站点内相对地址。"""
    text = text.replace(ACT_BASE, "./")
    text = text.replace(REACT_DOM_URL, "./vendor/react-dom@18.3.1.js")
    text = text.replace(REACT_URL, "./vendor/react@18.3.1.js")
    text = text.replace(SDK_URL, "/vendor/sdk.entry.js")
    return text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="已存在的文件也重下")
    args = ap.parse_args()
    force = args.force

    os.makedirs(SITE, exist_ok=True)
    manifest = {}
    problems = []

    # ---- 1. 页面 HTML ----------------------------------------------------
    log("[1/6] 下载页面 HTML")
    page = get(PAGE_URL).decode("utf-8", "replace")
    page = localize(page)
    n_assets = len(set(re.findall(r'\{href:"([^"]+)"\}', page)))
    # 在入口脚本前注入 WVSDK 垫片
    page, n = re.subn(
        r'(<script[^>]*\bsrc="[^"]*' + re.escape(ENTRY) + r'"[^>]*></script>)',
        SHIM + r"\n" + r"\1", page)
    if n != 1:
        problems.append("入口脚本标签匹配到 %d 处，WVSDK 垫片可能没注入成功" % n)
    write("index.html", page.encode("utf-8"), True)
    log("      index.html  (%d 字节, 垫片注入 %d 处, __resource %d 条)"
        % (len(page), n, n_assets))

    # ---- 2. 入口 JS -----------------------------------------------------
    log("[2/6] 下载入口 JS 并改写 publicPath")
    entry = get(ACT_BASE + ENTRY).decode("utf-8", "replace")
    old_p = re.findall(r'\.p="([^"]*)"', entry)
    entry = re.sub(r'\.p="' + re.escape(ACT_BASE) + r'"', '.p="/"', entry)
    new_p = re.findall(r'\.p="([^"]*)"', entry)
    write(ENTRY, entry.encode("utf-8"), True)
    log("      publicPath %s -> %s" % (old_p[:1], new_p[:1]))

    # ---- 3. 全部 chunk ---------------------------------------------------
    log("[3/6] 下载 %d 个 chunk" % len(CHUNKS))
    chunk_blobs = []
    for cid, h in CHUNKS.items():
        rel = "%d.%s.js" % (cid, h)
        try:
            txt = get(ACT_BASE + rel).decode("utf-8", "replace")
        except Exception as e:
            problems.append("%s 下载失败: %s" % (rel, e))
            continue
        if cid == 821:
            txt = txt.replace('baseURL:"%s"' % API_BASE,
                              'baseURL:"/act-server/orbipom-merge"')
            txt = localize(txt)
        chunk_blobs.append(txt)
        write(rel, txt.encode("utf-8"), True)

    # ---- 4. CSS ----------------------------------------------------------
    log("[4/6] 下载 CSS 并改写 url()")
    css = get(ACT_BASE + CSS).decode("utf-8", "replace")
    css = localize(css)
    write(CSS, css.encode("utf-8"), True)

    # ---- 5. 外部依赖 -----------------------------------------------------
    log("[5/6] 下载 react / react-dom / hg web sdk")
    for url, rel in [(REACT_URL, "vendor/react@18.3.1.js"),
                     (REACT_DOM_URL, "vendor/react-dom@18.3.1.js"),
                     (SDK_URL, "vendor/sdk.entry.js")]:
        try:
            write(rel, get(url), force)
        except Exception as e:
            problems.append("%s 下载失败: %s" % (rel, e))

    # ---- 6. 素材 ---------------------------------------------------------
    rels = set()
    for href in re.findall(r'\{href:"([^"]+)"\}', page):
        if href.startswith("./"):
            rels.add(href[2:])
    # 页面 __resource 只列了预加载素材，BGM / favicon 这类要另外从代码里挖
    for blob in [css, entry, page] + chunk_blobs:
        rels |= set(ASSET_RE.findall(blob))
    rels |= {"favicon-hg.ico"}
    rels = sorted(r for r in rels if not r.startswith("http"))
    log("[6/6] 下载 %d 个素材" % len(rels))

    def grab(rel):
        path = os.path.join(SITE, rel.replace("/", os.sep))
        if os.path.exists(path) and not force:
            with open(path, "rb") as fh:
                return rel, fh.read(), None      # 已存在，直接复用，不重复下载
        try:
            return rel, get(ACT_BASE + rel), None
        except Exception as e:
            return rel, None, str(e)

    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for rel, data, err in pool.map(grab, rels):
            if err:
                problems.append("%s 下载失败: %s" % (rel, err))
                continue
            write(rel, data, True)
            manifest[rel] = hashlib.sha256(data).hexdigest()
            done += 1
            if done % 50 == 0:
                log("      已处理 %d/%d" % (done, len(rels)))
    log("      素材完成 %d/%d" % (done, len(rels)))

    with open(os.path.join(HERE, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump({"act_base": ACT_BASE, "entry": ENTRY, "css": CSS,
                   "chunks": CHUNKS, "assets": manifest},
                  fh, ensure_ascii=False, indent=2, sort_keys=True)

    log("\n完成。站点目录: %s" % SITE)
    if problems:
        log("有 %d 个问题:" % len(problems))
        for p in problems[:20]:
            log("  - " + p)
    else:
        log("无失败项。")
    log("下一步: python serve.py")


if __name__ == "__main__":
    main()
