#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""中间人的系统侧改动：hosts + 受信任根证书。**默认只预览，不改任何东西。**

真正要让游戏客户端的 WebView 走 mitm.py，需要两步系统改动：

  1. hosts 里加一行   `127.0.0.1 ef-webview.hypergryph.com`
  2. 把 mitm/certs/ca.crt 装进「受信任的根证书颁发机构」

本脚本把这两步包起来，并且：

  - **默认 dry-run**，只打印会改什么；必须显式加 `--apply` 才真改
  - hosts **先备份**，改动包在带标记的块里，卸载时只删这个块
  - 证书**默认装到「当前用户」的根证书库**（`certutil -user`），不碰机器级存储；
    要装机器级再加 `--machine`
  - `--status` 随时看当前状态，`--uninstall` 一键还原

⚠️ 风险，动手前请读完：

  - 装根证书是**整机信任面**的改动（用户级只影响你这个账户）。这张 CA 的私钥就在
    `mitm/certs/ca.key`，谁能读到它，谁就能伪造**任意** HTTPS 站点。用完务必卸载。
  - 这台机器上装着 **ACE（AntiCheatExpert）内核级反作弊**（`ACE-BASE.sys` / `ACE-CORE.sys`）。
    改 hosts + 装根证书恰好是反作弊最敏感的一类系统改动，**有被判定的风险**。
  - 只劫 `ef-webview.hypergryph.com` 这一个域名，但它同时也是活动页和活动接口的域名。

用法:
    python trust.py --status                # 看当前状态（只读）
    python trust.py --install               # 预览要做什么（不改）
    python trust.py --install --apply       # 真的改
    python trust.py --uninstall --apply     # 一键还原
"""

import argparse
import ctypes
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CA_CRT = os.path.join(HERE, "certs", "ca.crt")
HOSTS = r"C:\Windows\System32\drivers\etc\hosts"
BACKUP = os.path.join(HERE, "hosts.bak")

TARGET = "ef-webview.hypergryph.com"
BEGIN = "# >>> orbipom-mitm >>>"
END = "# <<< orbipom-mitm <<<"


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _dec(b):
    if b is None:
        return ""
    for enc in ("utf-8", "gbk", "mbcs"):
        try:
            return b.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return b.decode("utf-8", "replace")


class Result:
    def __init__(self, cp):
        self.returncode = cp.returncode
        self.stdout = _dec(cp.stdout)
        self.stderr = _dec(cp.stderr)
        self.text = self.stdout + self.stderr


def run(cmd, **kw):
    # certutil 在中文 Windows 上吐 GBK，不能让 subprocess 用 utf-8 硬解
    return Result(subprocess.run(cmd, capture_output=True, **kw))


def read_hosts():
    with open(HOSTS, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def block_present(text):
    return BEGIN in text and END in text


def ca_thumbprint():
    r = run(["openssl", "x509", "-in", CA_CRT, "-noout", "-fingerprint", "-sha1"])
    out = (r.stdout or "").strip()
    return out.split("=")[-1].replace(":", "") if "=" in out else None


def orbipom_thumbprints(user=True):
    """列出根证书库里**所有** Orbipom CA 的指纹。

    为什么要「所有」而不是只删当前这张：`mitm.py --gencert --force-ca` 会换掉 CA，
    换完之后旧的那张会**留在**受信任根证书库里变成残留（它照样能签发任意站点证书）。
    只按当前 ca.crt 的指纹删，永远清不掉这些残留。

    解析要点：certutil 的输出是本地化的，但 `sha1` 这个词不翻译
    （中文版是「证书哈希(sha1)」），所以靠它定位指纹行；
    每张证书块里有两个 40 位十六进制串（序列号 + 指纹），只有 sha1 那行是指纹。
    """
    cmd = ["certutil"] + (["-user"] if user else []) + ["-store", "Root"]
    r = run(cmd)
    if r.returncode != 0:
        return []
    out = []
    for block in re.split(r"=+\s*\S*\s*\d+\s*=+", r.text):
        if "Orbipom" not in block:
            continue
        for line in block.splitlines():
            if "sha1" in line.lower():
                m = re.search(r"\b([0-9a-fA-F]{40})\b", line)
                if m:
                    out.append(m.group(1))
                break
    return out


def ca_in_store(user=True):
    """查 CA 在不在根证书库。

    两个坑（都实测踩过）：

    1. certutil 的输出是**本地化**的（中文 Windows 上是「证书哈希(sha1)」），
       所以不能用 "Cert Hash" 这种英文标记判断 —— 会误报「未装」。
       这里只依赖不随语言变的东西：rc、以及证书主体里的 "Orbipom"。
    2. 命中时输出里会带一句 `找不到解密的证书和私钥。`（只是说这张证书没有私钥，
       和「找没找到证书」无关）。**不能**用裸的 "找不到" 判断 —— 会把命中判成未命中。
    """
    tp = ca_thumbprint()
    if not tp:
        return None
    cmd = ["certutil"] + (["-user"] if user else []) + ["-store", "Root", tp]
    r = run(cmd)
    if r.returncode != 0:
        return False
    t = r.text
    if "Orbipom" in t:
        return True
    # 兜底：命中时 certutil 一定回显指纹
    return tp.lower() in t.lower()


def status():
    print("hosts      : %s" % HOSTS)
    print("  orbipom 块: %s" % ("存在" if block_present(read_hosts()) else "不存在"))
    print("  %s -> 127.0.0.1 ? %s"
          % (TARGET, "是" if ("127.0.0.1 " + TARGET) in read_hosts() else "否"))
    print("CA 证书    : %s" % ("存在" if os.path.isfile(CA_CRT) else "不存在（先跑 mitm.py --gencert）"))
    tp = ca_thumbprint()
    print("  指纹(sha1): %s" % (tp or "-"))

    # 只报「装没装」是不够的 —— 真正会翻车的是**装的是旧 CA**：
    # mitm.py --gencert --force-ca 换过 CA 之后，系统里那张就废了，
    # 客户端会直接报 unknown ca，而「已装」看起来一切正常。
    for scope, user in (("用户", True), ("机器", False)):
        tps = orbipom_thumbprints(user=user)
        if not tps:
            print("  %s根证书库: 没有 Orbipom CA" % scope)
            continue
        cur = tp and tp.lower() in [t.lower() for t in tps]
        print("  %s根证书库: 装了 %d 张%s"
              % (scope, len(tps), "（含当前 ca.crt）" if cur else " —— **都不匹配当前 ca.crt**"))
        for t in tps:
            mark = " ← 当前 ca.crt" if tp and t.lower() == tp.lower() else " ← 旧的/残留"
            print("      %s%s" % (t, mark))
        if not cur:
            print("      ⚠ 系统里装的不是当前这张 CA，客户端会报 unknown ca。"
                  "跑 python trust.py --install --apply 重新装")
    print("管理员     : %s" % ("是" if is_admin() else "否"))


def install(apply_it, machine=False):
    if not os.path.isfile(CA_CRT):
        sys.exit("没有 %s，先跑: python mitm.py --gencert" % CA_CRT)

    text = read_hosts()
    new = text
    if not block_present(text):
        if not new.endswith("\n"):
            new += "\n"
        new += "%s\n127.0.0.1 %s\n%s\n" % (BEGIN, TARGET, END)

    print("将要执行：")
    print("  1. 备份 hosts -> %s" % BACKUP)
    if new != text:
        print("  2. hosts 追加：")
        for ln in new[len(text):].strip().splitlines():
            print("       %s" % ln)
    else:
        print("  2. hosts 已含 orbipom 块，跳过")
    scope = "机器" if machine else "当前用户"
    print("  3. 把 CA 装进「%s」根证书库：certutil %s-addstore -f Root ca.crt"
          % (scope, "" if machine else "-user "))
    print("  4. 启动服务：python mitm.py --port 443   （443 需要管理员）")

    if not apply_it:
        print("\n（预览模式，什么都没改。确认后加 --apply）")
        return

    if not is_admin():
        sys.exit("\n需要管理员权限。请用管理员身份重开终端再跑。")

    if not os.path.isfile(BACKUP):
        shutil.copyfile(HOSTS, BACKUP)
        print("已备份 hosts -> %s" % BACKUP)

    if new != text:
        with open(HOSTS, "w", encoding="utf-8") as fh:
            fh.write(new)
        print("hosts 已更新")

    cmd = ["certutil"] + ([] if machine else ["-user"]) + ["-addstore", "-f", "Root", CA_CRT]
    r = run(cmd)
    print("证书安装 rc=%d" % r.returncode)
    print((r.stdout or r.stderr or "").strip()[:400])

    print("\n完成。卸载: python trust.py --uninstall --apply")


def uninstall(apply_it, machine=False):
    text = read_hosts()
    new = text
    if block_present(text):
        out, skip = [], False
        for ln in text.splitlines(keepends=True):
            if ln.strip() == BEGIN:
                skip = True
                continue
            if ln.strip() == END:
                skip = False
                continue
            if not skip:
                out.append(ln)
        new = "".join(out)
    else:
        new = "\n".join(l for l in text.splitlines(keepends=True)
                        if ("127.0.0.1 " + TARGET) not in l)

    tp = ca_thumbprint()
    # 用户库 + 机器库都清。这张 CA 是我们自己签的，从两个库里都删掉才是干净的收尾；
    # 只删一边会留下残留（实测装的时候两边都进去过），下次装/卸容易看花眼。
    scopes = [("当前用户", ["-user"]), ("机器", [])]

    # 要删的是「所有 Orbipom CA」，不只是当前这张 —— 换过 CA 的机器上会留旧的
    targets = []
    for name, args in scopes:
        tps = orbipom_thumbprints(user=("-user" in args))
        if tp and tp not in tps:
            tps = tps + [tp]
        targets.append((name, args, tps))

    print("将要执行：")
    n = 0
    n += 1
    print("  %d. 从 hosts 移除 orbipom 块%s" % (n, "" if new != text else "（本来就没有）"))
    for name, _args, tps in targets:
        n += 1
        if not tps:
            print("  %d. 「%s」根证书库：没有 Orbipom 证书，跳过" % (n, name))
        else:
            print("  %d. 从「%s」根证书库删除 %d 张 CA：%s"
                  % (n, name, len(tps), ", ".join(tps)))
    if os.path.isfile(BACKUP):
        n += 1
        print("  %d. 另有备份可整体还原：%s" % (n, BACKUP))

    if not apply_it:
        print("\n（预览模式，什么都没改。确认后加 --apply）")
        return

    if not is_admin():
        sys.exit("\n需要管理员权限。")

    if new != text:
        with open(HOSTS, "w", encoding="utf-8") as fh:
            fh.write(new)
        print("hosts 已还原")

    for name, args, tps in targets:
        if not tps:
            continue
        for t in tps:
            r = run(["certutil"] + args + ["-delstore", "Root", t])
            first = (r.stdout or r.stderr or "").strip().splitlines()
            print("  %s 库删除 %s rc=%d  %s"
                  % (name, t[:16] + "…", r.returncode,
                     first[-1].strip() if first else ""))


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--status", action="store_true", help="只看状态（只读）")
    g.add_argument("--install", action="store_true", help="装 hosts + CA")
    g.add_argument("--uninstall", action="store_true", help="还原 hosts + 删 CA")
    ap.add_argument("--apply", action="store_true", help="真的改（不加则只预览）")
    ap.add_argument("--machine", action="store_true", help="证书装到机器级存储（默认仅当前用户）")
    args = ap.parse_args()

    if args.status:
        status()
    elif args.install:
        install(args.apply, args.machine)
    else:
        uninstall(args.apply, args.machine)


if __name__ == "__main__":
    main()
