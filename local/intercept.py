#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""路由拦截版：不下载镜像，直接在请求层改写官方 CDN 的 JS 与接口响应。

和 `fetch.py` + `serve.py` 那套（下载 460+ 文件到本地再托管）的区别：

    本地镜像                       路由拦截
    ---------------------------    ---------------------------
    要 fetch.py 下载 8.3 MB         不下载，直接打官方 CDN
    chunk 文件名带 hash，会过期      按内容判断，CDN 更新也不用改
    publicPath / baseURL 要改        不用改，URL 原样
    接口要走自建代理                 请求原样发出，只改响应
    自己的浏览器打开                 必须是本脚本拉起的浏览器

代价：只能用脚本启动的浏览器（Playwright 控制），不能是你平时那个浏览器窗口。

它在两个层面拦截：

  1. **JS**：活动的 `.js`（含 `821.*.js`）被拦下，内存里改完再交给浏览器 ——
     改的是计分表 `eS`、夹取上限 `maxScore`、单局结算阈值、10 秒看门狗、
     合成逻辑（1+1=最高级）、出块等级（固定最小级）—— 全部同 patch_score.py。
  2. **接口**：`/api/save/profile` 与 `/api/save/score` 的响应被改写，
     把服务端下发的 `highScore` / `best` 换成 `--high-score` 指定的值 ——
     首页那个「最高分」就是这么来的（它不是 maxScore，改 JS 改不动它）。

平台检测（没有 WVSDK 就显示「网络异常」）用 `add_init_script` 注入垫片解决，
和本地镜像里那份是同一个东西。

用法:
    python intercept.py                       # 有头，改写最高分 9999999 + 改计分
    python intercept.py --headless            # 无头（跑一次看看有没有报错）
    python intercept.py --high-score 0        # 不改最高分
    python intercept.py --scale 1000          # 得分放大 1000 倍
    python intercept.py --no-js-patch         # 只拦接口，JS 原样放行
    python intercept.py --url "https://.../?u8_token=..."
"""

import argparse
import os
import re
import sys

# 复用 patch_score.py 里的正则，避免两处各写一份
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from patch_score import (ORIG_SCORES, RE_CAP, RE_MERGE, RE_RUNCAP, RE_SCORES,
                         RE_SPAWN, RE_WATCHDOG, MEGA_MERGE_ON, spawn_fix)  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sys.exit("需要 playwright：pip install playwright\n"
             "（不用另外下浏览器，脚本会用系统已装的 Edge）")

HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN_FILE = os.path.join(HERE, "..", ".u8_token")

PAGE_URL = "https://ef-webview.hypergryph.com/act/orbipom-merge/"
API_BASE = "https://ef-webview.hypergryph.com/act-server/orbipom-merge"
ACT_BASE = ("https://web.hycdn.cn/endfield/webview/"
            "unn3irGqmsvyaKnFbTug/act/orbipom-merge-XaVa5Tz/")

# 平台垫片：和本地镜像 fetch.py 注入的那段一样。
# 页面里是 `window.WVSDK || (window.WVSDK = {...})`，所以先定义就不会被覆盖。
WVSDK_SHIM = """
window.WVSDK = {
  ENV: {}, callback: {}, API: {},
  platform: "Qt",
  invoke: function () { return Promise.resolve({ status: 0, errorCode: 0 }); },
  invokeWithReturnValue: function () { return Promise.resolve({ status: 1, errorCode: 0 }); }
};
"""

RE_FAKE_FIELD = re.compile(r'("(?:highScore|best)"\s*:\s*)\d+')

stats = {"js": 0, "js_patched": 0, "api": 0, "api_patched": 0}


# ---------------------------------------------------------------- JS 补丁

def patch_js(text, scale, cap, run_cap, keep_watchdog,
             mega_merge=True, spawn_level=1, keep_spawn=False):
    """按 patch_score.py 的同一套规则改，返回 (新文本, 改了哪几处)。"""
    changed = []
    new_scores = [v * scale for v in ORIG_SCORES]

    m = RE_SCORES.search(text)
    if m:
        text = RE_SCORES.sub(
            "eS=[" + ",".join(str(v) for v in new_scores) + "]", text, count=1)
        changed.append("得分表 ×%d" % scale)

    if RE_CAP.search(text):
        text = RE_CAP.sub("maxScore:%d" % cap, text, count=1)
        changed.append("maxScore->%d" % cap)

    if RE_RUNCAP.search(text):
        text = RE_RUNCAP.sub(
            "r.score<%d&&e.score>=%d" % (run_cap, run_cap), text, count=1)
        changed.append("结算阈值->%d" % run_cap)

    if not keep_watchdog and RE_WATCHDOG.search(text):
        text = RE_WATCHDOG.sub('"playing"===r&&!1&&0===e&&t()', text, count=1)
        changed.append("关掉10s看门狗")

    if mega_merge and RE_MERGE.search(text):
        text = RE_MERGE.sub(MEGA_MERGE_ON, text, count=1)
        changed.append("1+1=最高级")

    if not keep_spawn and RE_SPAWN.search(text):
        text = RE_SPAWN.sub(spawn_fix(spawn_level), text, count=1)
        changed.append("出块固定%d级" % spawn_level)

    return text, changed


# ---------------------------------------------------------------- 拦截主体

def build_router(page, args):
    def handler(route):
        req = route.request
        url = req.url

        # ---- 接口响应改写 ----
        if args.high_score and ("/api/save/profile" in url or "/api/save/score" in url):
            try:
                resp = route.fetch()
                body = resp.text()
            except Exception as e:
                route.continue_()
                return
            new = RE_FAKE_FIELD.sub(
                lambda m: m.group(1) + str(args.high_score), body)
            stats["api"] += 1
            if new != body:
                stats["api_patched"] += 1
                print("  [接口] %s  highScore/best -> %d"
                      % (url.split("/api/")[-1], args.high_score))
            route.fulfill(status=resp.status, headers=_clean(resp, new), body=new)
            return

        # ---- 活动 JS 改写 ----
        if (not args.no_js_patch) and url.startswith(ACT_BASE) and url.endswith(".js"):
            try:
                resp = route.fetch()
                body = resp.text()
            except Exception:
                route.continue_()
                return
            stats["js"] += 1
            new, changed = patch_js(body, args.scale, args.cap,
                                    args.run_cap, args.keep_watchdog,
                                    not args.no_mega_merge, args.spawn_level,
                                    args.keep_spawn)
            if changed:
                stats["js_patched"] += 1
                print("  [JS]   %s  -> %s" % (url.split("/")[-1], "、".join(changed)))
            route.fulfill(status=resp.status, headers=_clean(resp, new), body=new)
            return

        route.continue_()

    page.route("**/*", handler)


def _clean(resp, new_body):
    """拿响应头，但去掉会和新 body 打架的 content-length / content-encoding。"""
    h = {k: v for k, v in resp.headers.items()
         if k.lower() not in ("content-length", "content-encoding")}
    h["content-length"] = str(len(new_body.encode("utf-8")))
    return h


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=None, help="完整活动地址（默认用 ../.u8_token 拼）")
    ap.add_argument("--high-score", type=int, default=9999999, metavar="N",
                    help="把接口里的 highScore/best 改写成 N（0 = 不改，默认 9999999）")
    ap.add_argument("--scale", type=int, default=100, help="得分放大倍数（默认 100）")
    ap.add_argument("--cap", type=int, default=9999999, help="maxScore 硬上限")
    ap.add_argument("--run-cap", type=int, default=99999999, help="单局结算阈值")
    ap.add_argument("--keep-watchdog", action="store_true", help="保留 10 秒看门狗")
    ap.add_argument("--no-mega-merge", action="store_true",
                    help="保留原合成逻辑（1+1=2）。默认「两只最小的直接合成最高级」")
    ap.add_argument("--spawn-level", type=int, default=1,
                    help="出块等级固定为 N（默认 1）")
    ap.add_argument("--keep-spawn", action="store_true",
                    help="保留原出块区间（1~5 随机）")
    ap.add_argument("--no-js-patch", action="store_true", help="只拦接口，不动 JS")
    ap.add_argument("--headless", action="store_true", help="无头运行")
    ap.add_argument("--browser", default="msedge", help="浏览器 channel（默认 msedge）")
    ap.add_argument("--shot", default=None, help="渲染完把截图存到这个路径后退出")
    ap.add_argument("--wait", type=int, default=12, help="--shot 时等多少秒再截图")
    args = ap.parse_args()

    url = args.url
    if not url:
        if not os.path.isfile(TOKEN_FILE):
            sys.exit("没有 --url，也找不到 %s，请自行传 --url" % TOKEN_FILE)
        tok = open(TOKEN_FILE, encoding="utf-8").read().strip()
        url = (PAGE_URL + "?u8_token=" + tok.replace("+", "%2B")
               + "&channel=1&lang=zh-cn&platform=Windows&server=1&subChannel=1")

    print("路由拦截模式")
    print("  页面    : %s" % PAGE_URL)
    print("  最高分  : %s" % (args.high_score if args.high_score else "不改（服务端原值）"))
    print("  JS 补丁 : %s" % ("关" if args.no_js_patch
                              else "得分 ×%d / maxScore %d / 结算 %d / 看门狗 %s / "
                                   "合成 %s / 出块 %s"
                              % (args.scale, args.cap, args.run_cap,
                                 "保留" if args.keep_watchdog else "关",
                                 "1+1=最高级" if not args.no_mega_merge else "原样",
                                 "原样" if args.keep_spawn
                                 else "固定%d级" % args.spawn_level)))
    print()

    with sync_playwright() as p:
        browser = p.chromium.launch(channel=args.browser, headless=args.headless)
        ctx = browser.new_context()
        ctx.add_init_script(WVSDK_SHIM)
        page = ctx.new_page()
        build_router(page, args)

        page.goto(url, wait_until="domcontentloaded", timeout=60000)

        if args.shot:
            page.wait_for_timeout(args.wait * 1000)
            page.screenshot(path=args.shot)
            labels = page.eval_on_selector_all(
                "[aria-label]", "els => els.map(e => e.getAttribute('aria-label')).filter(Boolean)")
            print("截图已存: %s" % args.shot)
            print("aria-labels:", labels[:15])
            print("统计: %s" % stats)
            browser.close()
            return

        print("浏览器已打开，直接玩。关掉窗口即退出。")
        try:
            browser.wait_for_event("disconnected", timeout=0)
        except Exception:
            pass
        finally:
            print("\n统计: %s" % stats)


if __name__ == "__main__":
    main()
