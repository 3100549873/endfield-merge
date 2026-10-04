#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""校验 local/site/821.67c1cf.js 的六处补丁（调试用，可随时删）。

做两件事：

  1. 把六处补丁的**当前值**打印出来（人眼确认）。
  2. 把规则**重新**作用到 `.orig` 上，跟 site 文件做**字节级**比对 ——
     完全一致才算「只改了这六处、别的地方一个字节都没动」。
     这是最有价值的一条：能抓住「正则匹配多了 / 文件被顺手改坏」。

规则直接从 patch_score.py 导入，避免两套正则漂移。

    python _verify_patch.py
    python _verify_patch.py --orig      # 只看原始文件长什么样
"""

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from patch_score import (MEGA_MERGE_ON, RE_CAP, RE_MERGE, RE_RUNCAP,  # noqa: E402
                         RE_SCORES, RE_SPAWN, RE_WATCHDOG, ORIG_SCORES,
                         spawn_fix)

TARGET = os.path.join(HERE, "site", "821.67c1cf.js")
BACKUP = TARGET + ".orig"

# (名字, 原值正则, 当前值正则, 期望的当前值)
RULES = [
    ("得分表 eS", r"eS=\[[\d,]*\]", r"eS=\[([\d,]+)\]", "100,300,600,1000,1500,2100,2800,3600,4500,5500,6600"),
    ("maxScore", r"maxScore:\d+", r"maxScore:(\d+)", "9999999"),
    ("结算阈值", r"r\.score<\d+&&e\.score>=\d+", r"r\.score<(\d+)", "99999999"),
    ("10s看门狗", r'"playing"===r&&[n>i!1]+&&0===e&&t\(\)',
     r'"playing"===r&&([n>i!1]+)&&0===e&&t\(\)', "!1"),
    ("合成逻辑", r"h=d\|\|1===r\.level\?ek:r\.level\+1", r"h=d(\|\|1===r\.level)\?ek", "||1===r.level"),
    ("出块区间", r"spawnLevelMin:\d+,spawnLevelMax:\d+",
     r"spawnLevelMin:(\d+),spawnLevelMax:(\d+)", "1|1"),
]

SCALE = 100
RUN_CAP = 99999999
SPAWN = 1


def rebuild(raw):
    """按 patch_score.py 的默认参数，把规则重新作用一遍。"""
    out = raw
    out = RE_SCORES.sub("eS=[" + ",".join(str(v * SCALE) for v in ORIG_SCORES) + "]",
                        out, count=1)
    out = RE_CAP.sub("maxScore:9999999", out, count=1)
    out = RE_RUNCAP.sub("r.score<%d&&e.score>=%d" % (RUN_CAP, RUN_CAP), out, count=1)
    out = RE_WATCHDOG.sub('"playing"===r&&!1&&0===e&&t()', out, count=1)
    out = RE_MERGE.sub(MEGA_MERGE_ON, out, count=1)
    out = RE_SPAWN.sub(spawn_fix(SPAWN), out, count=1)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--orig", action="store_true", help="只检查 .orig（应当全是原值）")
    a = ap.parse_args()

    if not os.path.isfile(BACKUP):
        sys.exit("没有 %s —— 先跑 python patch_score.py 生成备份" % BACKUP)

    for path, tag in ((BACKUP, "原始 .orig"), (TARGET, "补丁后 site")):
        if a.orig and path != BACKUP:
            continue
        raw = open(path, "rb").read()
        txt = raw.decode("utf-8")
        print("### %s  %d 字节  CR=%d LF=%d"
              % (tag, len(raw), raw.count(b"\r"), raw.count(b"\n")))
        for name, _origrx, cur_rx, want in RULES:
            m = re.search(cur_rx, txt)
            got = "|".join(m.groups()) if m else "(没匹配到)"
            print("    %-10s %-46s %s" % (name, got[:46],
                                          "" if a.orig else
                                          ("OK" if got == want else "!! 期望 %s" % want)))
        print()

    if a.orig:
        return 0

    # ---- 关键校验：重新打一遍，必须字节级一致 ----
    raw = open(BACKUP, encoding="utf-8", newline="").read()
    want = rebuild(raw).encode("utf-8")
    got = open(TARGET, "rb").read()
    if want == got:
        print("### 字节级复核：把规则重新作用到 .orig 上，结果与 site 文件**完全一致**")
        print("    → 确认只改了那六处，其余一个字节都没动（%d 字节）" % len(got))
        return 0
    print("### 字节级复核：**不一致**！")
    print("    want %d 字节 / got %d 字节" % (len(want), len(got)))
    n = min(len(want), len(got))
    i = 0
    while i < n and want[i] == got[i]:
        i += 1
    print("    首个不同 @%d" % i)
    print("      want ...%r" % want[max(0, i - 40):i + 60])
    print("      got  ...%r" % got[max(0, i - 40):i + 60])
    return 1


if __name__ == "__main__":
    sys.exit(main())
