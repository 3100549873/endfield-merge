#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一条命令查完中间人链路：hosts / 解析 / 证书 / 监听 / 接口改写。

mitm.py 跑起来之后**别急着开游戏** —— 先用这个确认五件事都对，
不然游戏里只会看到「网络异常」，看不出是哪一步断的。

用法:
    python check.py               # 查 443（真实劫持）
    python check.py --port 8443   # 查自检端口
    python check.py --no-net      # 只查前四项，不打网络请求
    python check.py --token XXX   # 带鉴权验证改写（见下）

第 5 项默认发一次**不带鉴权**的 POST。`/api/save/profile` 没登录会回
`401 UN_LOGIN` —— 那是**正常的**，不是改写失败：响应里没有 `best` 字段，没什么可改。
所以这一项会显示 [WARN] 而不是 [FAIL]。

想把改写验到底，给个 `u8_token`：

    python check.py --token <u8_token>

它会照活动页的做法先 `role/login` 拿会话 cookie，再带 cookie 请求 profile，
看 `best` 是不是被改成了 9999999。`--token` 也接受 `@文件路径`。
（默认会尝试读上级目录的 `.u8_token`，有就直接用。）
"""

import argparse
import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import sys
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
CA_CRT = os.path.join(HERE, "certs", "ca.crt")
HOSTS = r"C:\Windows\System32\drivers\etc\hosts"
TARGET = "ef-webview.hypergryph.com"
API = "/act-server/orbipom-merge/api"
LOGIN_PATH = API + "/role/login"
PROFILE_PATH = API + "/save/profile"
PAGE_PATH = "/act/orbipom-merge/"

OK, NO, WARN = "[OK]  ", "[FAIL]", "[WARN]"


def _dec(b):
    if b is None:
        return ""
    for enc in ("utf-8", "gbk", "mbcs"):
        try:
            return b.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return b.decode("utf-8", "replace")


def run(cmd):
    cp = subprocess.run(cmd, capture_output=True)
    return cp.returncode, _dec(cp.stdout) + _dec(cp.stderr)


# ------------------------------------------------------------------ 1. hosts

def check_hosts():
    try:
        with open(HOSTS, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        return False, "读不了 hosts：%s" % e
    hits = [ln.strip() for ln in text.splitlines()
            if ln.strip() and not ln.strip().startswith("#") and TARGET in ln]
    if not hits:
        return False, "hosts 里没有 %s 的条目" % TARGET
    good = [h for h in hits if re.search(r"^\s*127\.0\.0\.1\s+" + re.escape(TARGET), h)]
    if not good:
        return False, "有条目但没指向 127.0.0.1：%s" % " | ".join(hits)
    return True, good[0]


# ------------------------------------------------------------------ 2. 解析

def check_resolve():
    try:
        addrs = {i[4][0] for i in socket.getaddrinfo(TARGET, 443,
                                                     type=socket.SOCK_STREAM)}
    except Exception as e:
        return False, "解析失败：%s" % e
    if addrs == {"127.0.0.1"}:
        return True, "-> 127.0.0.1（已被劫持，符合预期）"
    if "127.0.0.1" in addrs:
        return True, "-> %s（含 127.0.0.1，会被劫持）" % ", ".join(sorted(addrs))
    return False, "-> %s（**没被劫持**，客户端不会走中间人）" % ", ".join(sorted(addrs))


# ------------------------------------------------------------------ 3. 证书

def check_ca():
    if not os.path.isfile(CA_CRT):
        return False, "没有 %s（先跑 python mitm.py --gencert）" % CA_CRT
    rc, out = run(["openssl", "x509", "-in", CA_CRT, "-noout", "-fingerprint", "-sha1"])
    m = re.search(r"=([0-9A-Fa-f:]{59})", out)
    if not m:
        return False, "算不出指纹：%s" % out.strip()[:120]
    tp = m.group(1).replace(":", "").lower()

    # 先看本进程能不能看到 Windows 证书存储 —— 看不到的话这一项结果不可信
    paths = ssl.get_default_verify_paths()
    if paths.cafile:
        return None, ("你这个 Python 用的是自带 CA 包（%s），**看不到 Windows 证书存储**，"
                      "本项结果不可信 —— 请换官方版 Python（python.org）跑本脚本"
                      % paths.cafile)

    for scope, args in (("当前用户", ["-user"]), ("本机", [])):
        rc, out = run(["certutil"] + args + ["-store", "Root", tp])
        if tp.upper() in out.upper() or "Orbipom" in out:
            return True, "已在「受信任的根证书颁发机构」（%s）" % scope
    return False, ("不在受信任根存储里 —— 客户端会报 unknown ca。"
                   "跑 python trust.py --install --apply")


# ------------------------------------------------------------------ 4. 监听

def check_listen(port):
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect(("127.0.0.1", port))
    except OSError as e:
        return False, "127.0.0.1:%d 连不上（%s）—— mitm.py 起了吗？" % (port, e)
    finally:
        s.close()
    return True, "127.0.0.1:%d 有人听" % port


# ------------------------------------------------------------------ 5. 接口

def request(path, port, method="GET", body=None, headers=None):
    """经中间人打一次请求。**默认证书校验，不许 -k** —— 这本身就是一项验证。"""
    ctx = ssl.create_default_context()
    hdrs = dict(headers or {})
    data = b""
    if body is not None:
        data = json.dumps(body).encode("utf-8") if not isinstance(body, bytes) else body
    if method in ("POST", "PUT"):
        hdrs.setdefault("content-length", str(len(data)))
    c = http.client.HTTPSConnection(TARGET, port, timeout=20, context=ctx)
    try:
        c.request(method, path, body=data if data else None, headers=hdrs)
        r = c.getresponse()
        return r.status, dict(r.getheaders()), r.read()
    finally:
        try:
            c.close()
        except Exception:
            pass


def _hint_502(st, body):
    """502 是中间人自己吐的 —— 说明本地这一段通了，是「到上游」那一段断了。"""
    if st != 502:
        return None
    text = _dec(body)
    ps = re.findall(r"<p>(.*?)</p>", text, re.S)
    detail = next((p.strip() for p in ps if "Message:" in p), None)
    if detail is None:
        detail = ps[0].strip() if ps else text.strip()[:160]
    return ("上游连不上（502）—— 本地这段是通的，断在「中间人 → 真实服务器」。\n"
            "             原因：%s\n"
            "             排查：① 中间人是不是老代码（自环）→ 重启 mitm.py；\n"
            "                   ② 自动解析出来的 IP 不对 → 手动指定 python mitm.py "
            "--port 443 --upstream-ip <真实IP>" % detail)


def check_page(port):
    try:
        st, _h, body = request(PAGE_PATH, port)
    except Exception as e:
        return False, "请求页面失败：%s: %s" % (type(e).__name__, e)
    if st != 200:
        return False, _hint_502(st, body) or "页面 HTTP %d（%d 字节）" % (st, len(body))
    return True, "页面 HTTP 200，%d 字节" % len(body)


def _best_of(body):
    return re.findall(r'"(?:best|highScore)"\s*:\s*(\d+)', _dec(body))


def check_profile(port, expect):
    """不带鉴权打一次。401 是预期行为，报 WARN。"""
    try:
        st, _h, body = request(PROFILE_PATH, port, method="POST", body=b"")
    except Exception as e:
        return None, "请求接口失败：%s: %s" % (type(e).__name__, e)
    text = _dec(body)
    if st == 502:
        return False, _hint_502(st, body)
    if st == 401:
        return None, ("接口 HTTP 401（%s）—— **预期行为**：匿名请求没有 cookie。\n"
                      "             响应里没有字段可改，所以这一项证明不了改写。\n"
                      "             要看改写：① 加 --token 做带鉴权验证；\n"
                      "                       ② 或者直接开游戏，看 mitm.py 控制台有没有打 "
                      "`[接口] ... ✅ 改写 best -> %d`" % (text.strip()[:80], expect))
    if st != 200:
        return False, "接口 HTTP %d：%s" % (st, text.strip()[:200])
    vals = _best_of(body)
    if not vals:
        return None, "接口 200 但没看到 best/highScore：%s" % text.strip()[:200]
    if all(int(v) == expect for v in vals):
        return True, "best/highScore = %s（已被改写成 %d ✅）" % (", ".join(vals), expect)
    if all(int(v) == 99999 for v in vals):
        return False, ("best/highScore = %s —— 还是服务器的 99999，**没改写**。"
                       "中间人没接上，或者请求没走本地" % ", ".join(vals))
    return True, "best/highScore = %s" % ", ".join(vals)


def check_profile_authed(port, token, server_id, expect):
    """照活动页的做法：先 role/login 拿 cookie，再带 cookie 请求 profile。"""
    hdrs = {"content-type": "application/json",
            "x-role-token": token, "x-role-server-id": server_id}
    try:
        st, h, body = request(LOGIN_PATH, port, method="POST",
                              body={"token": token, "serverId": server_id},
                              headers=hdrs)
    except Exception as e:
        return None, "role/login 失败：%s: %s" % (type(e).__name__, e)
    if st != 200:
        return False, "role/login HTTP %d：%s" % (st, _dec(body).strip()[:200])
    raw_ck = h.get("set-cookie") or h.get("Set-Cookie")
    if not raw_ck:
        return False, "role/login 200 但没下发 cookie：%s" % _dec(body).strip()[:200]
    cookie = raw_ck.split(";")[0]

    try:
        st, _h2, body = request(PROFILE_PATH, port, method="POST", body=b"",
                                headers={"cookie": cookie, "x-role-token": token,
                                         "x-role-server-id": server_id})
    except Exception as e:
        return None, "带 cookie 请求 profile 失败：%s: %s" % (type(e).__name__, e)
    text = _dec(body)
    if st != 200:
        return False, "profile HTTP %d：%s" % (st, text.strip()[:200])
    vals = _best_of(body)
    if not vals:
        return None, "profile 200 但没看到 best/highScore：%s" % text.strip()[:200]
    if all(int(v) == expect for v in vals):
        return True, ("带鉴权拿到 best/highScore = %s，已改写成 %d ✅ —— "
                      "游戏里看到的就会是这个值" % (", ".join(vals), expect))
    if all(int(v) == 99999 for v in vals):
        return False, ("带鉴权拿到 best/highScore = %s —— **还是 99999，没改写**。"
                       "中间人收到了响应但没匹配上字段" % ", ".join(vals))
    return True, "带鉴权拿到 best/highScore = %s" % ", ".join(vals)


# ------------------------------------------------------------------ 6. 前端 JS

# 六处补丁的「原值」，用来判断有没有被改过
ORIG_E_S = "1,3,6,10,15,21,28,36,45,55,66"
RE_E_S = re.compile(r"eS=\[([\d,]+)\]")
RE_MAXSCORE = re.compile(r"maxScore:(\d+)")
RE_RUNCAP = re.compile(r"r\.score<(\d+)&&e\.score>=(\d+)")
WATCHDOG_ON = '"playing"===r&&n>i&&0===e&&t()'
WATCHDOG_OFF = '"playing"===r&&!1&&0===e&&t()'
# 合成逻辑：processMerges() 里的新等级计算
MEGA_OFF = "h=d?ek:r.level+1"
MEGA_ON = "h=d||1===r.level?ek:r.level+1"
# 出块等级区间（1+1=最高级 的配套：只出最小的，否则没得合）
RE_SPAWN = re.compile(r"spawnLevelMin:(\d+),spawnLevelMax:(\d+)")


def _js_rules(text):
    """在 JS 文本里找六处补丁，返回 [(名字, 值, 是否已改)]。找不到的不返回。"""
    out = []
    m = RE_E_S.search(text)
    if m:
        out.append(("得分表", m.group(1)[:44], m.group(1) != ORIG_E_S))
    m = RE_MAXSCORE.search(text)
    if m:
        out.append(("maxScore", m.group(1), m.group(1) != "99999"))
    m = RE_RUNCAP.search(text)
    if m:
        out.append(("结算阈值", m.group(1), m.group(1) != "1500"))
    if WATCHDOG_OFF in text:
        out.append(("10s看门狗", "已关闭", True))
    elif WATCHDOG_ON in text:
        out.append(("10s看门狗", "仍在", False))
    if MEGA_ON in text:
        out.append(("合成逻辑", "1+1=最高级", True))
    elif MEGA_OFF in text:
        out.append(("合成逻辑", "1+1=2（原样）", False))
    m = RE_SPAWN.search(text)
    if m:
        lo, hi = m.group(1), m.group(2)
        out.append(("出块区间", "%s~%s" % (lo, hi), lo == hi))
    return out


def _fetch_many(paths, port, workers=6):
    """并发取多个路径，返回 {path: 文本}。chunk 有 20 个，串行太慢。"""
    import concurrent.futures as cf
    got = {}

    def one(p):
        try:
            st, _h, b = request(p, port)
            return p, (st, _dec(b))
        except Exception:                                  # noqa: BLE001
            return p, (0, "")

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for p, (st, txt) in ex.map(one, paths):
            if st == 200:
                got[p] = txt
    return got


def check_js(port):
    """验证前端 JS 有没有被中间人改掉。

    分两步，因为**规则不在入口 JS 里** —— 它在 webpack 懒加载的 chunk 中
    （线上是 `821.67c1cf.js`）。所以要先确认 publicPath（`r.p`）被转到了本域，
    再顺着 chunk 映射把 chunk 拉下来找那六处。
    """
    st, _h, body = request(PAGE_PATH, port)
    if st != 200:
        return None, "拿不到页面（HTTP %d），跳过" % st
    html = _dec(body)

    srcs = re.findall(r'<script[^>]+src="([^"]+)"', html)
    act = [u for u in srcs if "orbipom-merge" in u and u.endswith(".js")]
    if not act:
        return None, "页面里没有活动 JS 的 <script src>（这真是活动页吗？）"

    left = [u for u in act if "web.hycdn.cn" in u]
    if left:
        return False, ("页面**没被改写**：还有 %d 个活动 JS 指向 web.hycdn.cn。\n"
                       "             多半是客户端用了缓存（304）—— "
                       "重启 mitm.py 后**重新进一次活动**" % len(left))

    entry_path = urlsplit(act[0]).path
    st, _h, body = request(entry_path, port)
    if st != 200:
        return False, "取入口 JS 失败 HTTP %d（%s）" % (st, entry_path)
    entry = _dec(body)

    m = re.search(r'\.p="(https?://[^"]*?/__cdn/[^"]*)"', entry)
    if not m:
        mm = re.search(r'\.p="([^"]{0,120})"', entry)
        return False, ("入口 JS 的 publicPath（`r.p`）没转到本域"
                       "（当前是 %s）—— 后续 chunk 仍会从 CDN 直取，补丁到不了。"
                       % (mm.group(1) if mm else "没找到 r.p"))

    # 顺着 chunk 映射把所有 chunk 拉下来，找含规则的那个
    pairs = re.findall(r'(\d{1,4}):"([0-9a-f]{6,})"', entry)
    base = entry_path.rsplit("/", 1)[0] + "/"
    if not pairs:
        return None, ("publicPath 已转到本域 ✅，但入口 JS 里没解析出 chunk 映射，"
                      "没法确认规则有没有打上（看 mitm.py 控制台有没有 [JS] 行）")

    paths = ["%s%s.%s.js" % (base, i, h) for i, h in pairs]
    got = _fetch_many(paths, port)

    for p, txt in got.items():
        rules = _js_rules(txt)
        if not rules:
            continue
        bad = [r for r in rules if not r[2]]
        name = p.rsplit("/", 1)[-1]
        detail = "、".join("%s=%s" % (r[0], r[1]) for r in rules)
        if bad:
            return False, ("规则在 %s 里，但**没改**：%s" % (name, detail))
        return True, ("publicPath 转本域 ✅；规则在 %s 里，六处都改了：%s"
                      % (name, detail))

    return None, ("publicPath 已转到本域 ✅，但 %d 个 chunk 里都没找到那六处规则"
                  "（CDN 上换版本了？）—— 看 mitm.py 控制台有没有 [JS] 行"
                  % len(got))


# ------------------------------------------------------------------ main

def resolve_token(arg):
    if not arg:
        # 顺手看看 orbipom.py 的缓存
        for p in (os.path.join(HERE, "..", ".u8_token"), ".u8_token"):
            if os.path.isfile(p):
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    v = f.read().strip()
                if v:
                    print("      （用 %s 里的 token）" % os.path.normpath(p))
                    return v
        return None
    if arg.startswith("@"):
        with open(arg[1:], "r", encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    return arg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--expect", type=int, default=9999999,
                    help="期望被改写成的值（默认 9999999，和 mitm.py 的 --high-score 一致）")
    ap.add_argument("--no-net", action="store_true", help="跳过网络请求")
    ap.add_argument("--no-js", action="store_true", help="跳过前端 JS 检查")
    ap.add_argument("--js-scale", type=int, default=100, metavar="N",
                    help="只用于结论文字，和 mitm.py --js-scale 保持一致")
    ap.add_argument("--js-run-cap", type=int, default=99999999, metavar="N",
                    help="只用于结论文字，和 mitm.py --js-run-cap 保持一致")
    ap.add_argument("--token", default=None, metavar="TOKEN|@FILE",
                    help="u8_token，给了就做带鉴权的端到端验证（先 role/login 再 profile）")
    ap.add_argument("--server-id", default="1")
    args = ap.parse_args()

    print("中间人链路自检 —— 目标 %s，端口 %d\n" % (TARGET, args.port))

    results = []

    print("[1/6] hosts 劫持")
    ok, msg = check_hosts()
    print("      %s %s" % (OK if ok else NO, msg))
    results.append(ok)

    print("[2/6] 系统解析")
    ok, msg = check_resolve()
    print("      %s %s" % (OK if ok else NO, msg))
    results.append(ok)

    print("[3/6] CA 信任")
    ok, msg = check_ca()
    if ok is None:
        print("      %s %s" % (WARN, msg))
    else:
        print("      %s %s" % (OK if ok else NO, msg))
        results.append(ok)

    print("[4/6] 本地监听")
    ok, msg = check_listen(args.port)
    print("      %s %s" % (OK if ok else NO, msg))
    results.append(ok)

    net_ok = None
    js_ok = None
    token = resolve_token(args.token)
    if args.no_net:
        print("[5/6] 接口改写（--no-net，跳过）")
        print("[6/6] 前端 JS 补丁（--no-net，跳过）")
    elif not ok:
        print("[5/6] 接口改写")
        print("      %s 没人监听，跳过" % WARN)
        print("[6/6] 前端 JS 补丁")
        print("      %s 没人监听，跳过" % WARN)
    else:
        print("[5/6] 接口改写")
        okp, msgp = check_page(args.port)
        print("      %s %s" % (OK if okp else NO, msgp))
        if token:
            oka, msga = check_profile_authed(args.port, token, args.server_id,
                                             args.expect)
            print("      %s %s" % (WARN if oka is None else (OK if oka else NO), msga))
            net_ok = oka
        else:
            okf, msgf = check_profile(args.port, args.expect)
            print("      %s %s" % (WARN if okf is None else (OK if okf else NO), msgf))
            net_ok = okf

        print("[6/6] 前端 JS 补丁")
        if args.no_js:
            print("      %s --no-js 跳过" % WARN)
        elif not okp:
            print("      %s 页面都没拿到，跳过" % WARN)
        else:
            okj, msgj = check_js(args.port)
            print("      %s %s" % (WARN if okj is None else (OK if okj else NO), msgj))
            js_ok = okj

    print("\n" + "-" * 52)
    if not all(results):
        print("结论：上面标 [FAIL] 的项就是断点，按提示修完再跑一次。")
    elif js_ok is False or net_ok is False:
        print("结论：系统侧全对，但改写没生效 —— 看上面标 [FAIL] 的那一步。")
    elif net_ok is True and js_ok is True:
        print("结论：全绿。开游戏 → 进「融合！山团团！」。")
        print("      「最高分」= %d；一局得分 ×%d、结算阈值抬到 %d、10s看门狗关、"
              "1+1=最高级。" % (args.expect, args.js_scale, args.js_run_cap))
        print("      注意：页面是打开时拉一次 profile，**改完要重新进活动**。")
    else:
        print("结论：系统侧全对，页面也通到上游了 —— 链路是好的。")
        print("      还没验到底的部分：")
        if net_ok is None:
            print("        · 接口改写 —— 匿名请求会 401，加 --token <u8_token> 验")
        if js_ok is None:
            print("        · 前端 JS —— 看 mitm.py 控制台有没有 [JS] 行")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
