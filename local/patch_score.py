#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""改本地镜像里 821.67c1cf.js 的计分与分数上限。

改的是六处（都在 webpack 模块里，全文件唯一匹配）：

  1. `eS=[1,3,6,10,15,21,28,36,45,55,66]`
     每级合成的得分，index i 对应等级 i+1（原值 = 三角形数 L(L-1)/2）。
     这是**唯一的得分来源** —— store 里的 `addScore` 只有定义、没有调用点，
     实际加分全在 `onMerge` 里走 `eM(level).score`。

  2. `ey.maxScore:99999`
     硬性夹取上限。`onMerge` 与 `addScore` 都用 `Math.min(ey.maxScore, …)`。
     注意这只是「保险丝」，真正让一局结束的是下面两条。

  3. `r.score<1500 && e.score>=1500` → 结算
     **真正的单局分数上限**：分数跨过 1500 的那一瞬间自动结算。
     1500 同时也是 highScore 奖励任务的目标值。不抬高它，一局到 1500 就结束。

  4. 10 秒看门狗：`"playing"===r && n>i && 0===e && t()`
     每 10 秒检查一次，只要「当前分 > 历史最高分」就自动结算（把新纪录入账）。
     默认会把它关掉（`--keep-autosettle` 可保留），否则抬了得分后一局只撑 10 秒。

  5. 合成等级：`h=d?ek:r.level+1` → `h=d||1===r.level?ek:r.level+1`
     **改合成逻辑本身**：两只**最小（level 1）**的撞在一起，直接变成**最高级**。
     原逻辑见 `processMerges()`：

         var d=r.level===ek,        // 已经是最上级（ek = 等级总数，实测 11）
             h=d?ek:r.level+1,      // 新等级：最上级保持 ek，否则 +1
             ...
         if(d) renderer.playMergeFadeOut(g);
         else { ... this.phys.spawn(h, x, y, ...) }   // 只有非 d 才真的生成新个体

     补上 `||1===r.level` 之后：level 1 + level 1 → `h=ek=11`，而 `d` 仍是 false，
     所以走 spawn 分支，**真的会生成一只 11 级**（`playMergeFadeOut` 那条路不会被走到）。
     `eM(h)` 内部有 `Math.min(Math.max(round(h),1),ek)` 夹取，h=11 不会越界。

     ⚠️ 两个副作用，都是**故意保留**的：
       - 加的分按**源等级**算（`onMerge(h, r.level)` → `eM(r.level-1).score`），
         所以 1+1 合成 11 级只加 level 1 的分（原值 1 分，×scale 后是 scale 分）。
         想要「合一次就爆分」就把 `--scale` 调大。
       - 生成时 `h===ek` 会触发 `onGolden` 回调（最高级的金色特效），这是正常的。
     不想要这个改动就加 `--no-mega-merge`。

  6. 出块等级：`spawnLevelMin:1,spawnLevelMax:5` → `spawnLevelMin:1,spawnLevelMax:1`
     只改 `ey` 里那两个字面量，`nextSpawnLevel()` 就永远返回 1 级。
     **这条是 5 的配套** —— 上面把 1+1 变成最高级之后，如果还按原样出 1~5 级，
     出一只 3 级就得再等一只 3 级才能合，等于没改。所以默认把出块也钉死在最小级。
     想换成「固定出 N 级」用 `--spawn-level N`；完全不改用 `--keep-spawn`。

注意：这只影响**本地这一份客户端**的显示与结算值。
服务端 `/api/save/score` 对 `score` 另有上限（实测 99999，见技术分析报告 §4.2），
所以本地刷到 100 万，提交上去也不会按 100 万记账。

用法:
    python patch_score.py                  # 得分 ×100，上限全抬高，关看门狗，1+1=最高级，只出 1 级
    python patch_score.py --scale 1000
    python patch_score.py --keep-autosettle
    python patch_score.py --no-mega-merge  # 保留原合成逻辑（1+1=2）
    python patch_score.py --keep-spawn     # 保留原出块区间（1~5 级）
    python patch_score.py --spawn-level 1  # 固定出 2 级
    python patch_score.py --start 50000    # 调试用：直接给起始分（注意会触发结算）
    python patch_score.py --restore        # 从 .orig 还原成原始文件
"""

import argparse
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(HERE, "site", "821.67c1cf.js")
BACKUP = TARGET + ".orig"

ORIG_SCORES = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 66]

RE_SCORES = re.compile(r"eS=\[" + r",".join(str(v) for v in ORIG_SCORES) + r"\]")
RE_CAP = re.compile(r"maxScore:(\d+)")
RE_RUNCAP = re.compile(r"r\.score<(\d+)&&e\.score>=(\d+)")
RE_WATCHDOG = re.compile(r'"playing"===r&&n>i&&0===e&&t\(\)')
RE_START = re.compile(r'start:\(\)=>e\(e=>\(\{state:"playing",score:(\d+)')

# ---- 合成逻辑：两只最小的直接合成最高级 ----
# 原串就是 processMerges() 里那行三元表达式，全文件唯一。
# 加 `||1===r.level` 后，源等级为 1 时新等级直接取 ek（= 等级总数 = 最高级）。
MEGA_MERGE_OFF = "h=d?ek:r.level+1"
MEGA_MERGE_ON = "h=d||1===r.level?ek:r.level+1"
RE_MERGE = re.compile(re.escape(MEGA_MERGE_OFF))

# ---- 出块等级：只出最小的（配合上面那条，否则没得合）----
# `ey` 配置里的出块等级区间，`nextSpawnLevel()` 在 [min, max] 里随机取：
#
#     nextSpawnLevel(){var{spawnLevelMin:e,spawnLevelMax:t}=ey, r=t-e+1,
#                      n=e+Math.floor(Math.random()*r), ...}
#
# 两个都钉成 1 → r = t-e+1 = 1 → n = 1+floor(random()*1) = 1，永远出 1 级；
# 而且 `r>1&&…` 那条「防三连」分支也不会生效（r 就是 1）。
#
# 注意：`lT` 里另有一处 `spawnLevelMin:ey.spawnLevelMin,spawnLevelMax:ey.spawnLevelMax`
# （devtools 面板的基线快照，写的是 ey.xxx 而不是字面量），**不同串**，不会被误改。
RE_SPAWN = re.compile(r"spawnLevelMin:(\d+),spawnLevelMax:(\d+)")


def spawn_fix(level):
    """把出块区间钉成 [level, level]。"""
    return "spawnLevelMin:%d,spawnLevelMax:%d" % (level, level)


def sub1(pattern, repl, text, label):
    """只替换唯一匹配；数量不对就直接报错，避免静默改错地方。"""
    n = len(pattern.findall(text))
    if n != 1:
        sys.exit("「%s」匹配到 %d 处（应为 1）—— 文件可能已被改过或版本变了，"
                 "先跑 fetch.py 重新下载。" % (label, n))
    return pattern.sub(repl, text, count=1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scale", type=int, default=100, help="得分放大倍数（默认 100）")
    ap.add_argument("--cap", type=int, default=9999999, help="maxScore 硬上限（默认 9999999）")
    ap.add_argument("--run-cap", type=int, default=99999999,
                    help="单局结算阈值，原值 1500（默认 99999999）")
    ap.add_argument("--keep-autosettle", action="store_true",
                    help="保留 10 秒自动结算看门狗（默认关掉它）")
    ap.add_argument("--no-mega-merge", action="store_true",
                    help="保留原合成逻辑（1+1=2）；默认改成「两只最小的直接合成最高级」")
    ap.add_argument("--spawn-level", type=int, default=1, metavar="N",
                    help="把出块等级固定为 N（默认 1）。配合 1+1=最高级用")
    ap.add_argument("--keep-spawn", action="store_true",
                    help="保留原出块区间（线上是 1~5 级）")
    ap.add_argument("--start", type=int, default=None, help="调试用：改起始分数，不传则不动")
    ap.add_argument("--restore", action="store_true", help="从 .orig 还原")
    args = ap.parse_args()

    if not os.path.isfile(TARGET):
        sys.exit("找不到 %s，先跑: python fetch.py" % TARGET)

    if args.restore:
        if not os.path.isfile(BACKUP):
            sys.exit("没有 %s，无法还原。重跑 fetch.py 也会拿到原始文件。" % BACKUP)
        shutil.copyfile(BACKUP, TARGET)
        print("已还原: %s" % TARGET)
        return

    # 第一次跑时留一份原始文件；之后所有补丁都从它出发 —— 可重复、可还原
    if not os.path.isfile(BACKUP):
        shutil.copyfile(TARGET, BACKUP)
        print("已备份原始文件 -> %s" % os.path.basename(BACKUP))

    raw = open(BACKUP, encoding="utf-8", newline="").read()
    out = raw

    new_scores = [v * args.scale for v in ORIG_SCORES]
    out = sub1(RE_SCORES, "eS=[" + ",".join(str(v) for v in new_scores) + "]", out, "eS 得分表")
    out = sub1(RE_CAP, "maxScore:%d" % args.cap, out, "maxScore")

    old_run = RE_RUNCAP.search(out).group(1)
    out = sub1(RE_RUNCAP, "r.score<%d&&e.score>=%d" % (args.run_cap, args.run_cap),
               out, "单局结算阈值")

    watchdog = "保留"
    if not args.keep_autosettle:
        out = sub1(RE_WATCHDOG, '"playing"===r&&!1&&0===e&&t()', out, "10 秒看门狗")
        watchdog = "已关闭"

    mega = "关（保留原逻辑：1+1=2）"
    if not args.no_mega_merge:
        out = sub1(RE_MERGE, MEGA_MERGE_ON, out, "合成逻辑（最小→最高级）")
        mega = "开（1+1=ek=最高级）"

    spawn = "原样（%s）" % RE_SPAWN.search(raw).group(0)
    if not args.keep_spawn:
        if not 1 <= args.spawn_level <= 11:
            sys.exit("--spawn-level 要在 1~11 之间（11 = 等级总数 ek，线上实测）")
        old_spawn = RE_SPAWN.search(out).group(0)
        out = sub1(RE_SPAWN, spawn_fix(args.spawn_level), out, "出块等级")
        spawn = "%s -> 固定 %d 级" % (old_spawn, args.spawn_level)

    if args.start is not None:
        out = sub1(RE_START,
                   lambda m: m.group(0).replace("score:" + m.group(1),
                                                "score:%d" % args.start, 1),
                   out, "起始分数")

    # newline="" 是必须的：不加的话 Windows 上文本模式会把每个 \n 写成 \r\n，
    # 于是「除补丁外逐字节一致」就不成立了（实测被坑过一次，文件凭空多出 \r）。
    with open(TARGET, "w", encoding="utf-8", newline="") as fh:
        fh.write(out)

    print("\n已写入 %s" % TARGET)
    print("  得分表    %s" % ORIG_SCORES)
    print("         ->  %s" % new_scores)
    print("  硬上限    %s -> %d" % (RE_CAP.search(raw).group(1), args.cap))
    print("  结算阈值  %s -> %d" % (old_run, args.run_cap))
    print("  10s看门狗 %s" % watchdog)
    print("  合成逻辑  %s" % mega)
    print("  出块等级  %s" % spawn)
    if args.start is not None:
        print("  起始分    -> %d（会立刻触发结算，仅调试用）" % args.start)
    print("\n刷新浏览器即可生效。还原: python patch_score.py --restore")


if __name__ == "__main__":
    main()
