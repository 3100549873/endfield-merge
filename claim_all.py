#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
《明日方舟：终末地》WebView 活动「融合！山团团！」(orbipom-merge)
一键获取奖励 —— 合成 20 次 / 战技 3 种 / 分数 1500 / 合成黄金管理员 1 次 / 分享 1 次，
最后一次性把所有可领的奖励全部领完。

用法:
    python claim_all.py              # 刷满 + 一键领取
    python claim_all.py --dry-run    # 只看还差多少，不发写请求
    python claim_all.py --selftest   # 离线自检，不联网

依赖:
    和 cli.py 放在同一目录（它直接 import cli）。
    旧版文件名也认 —— 那个文件叫 orbipom.py 时照样能跑，不用改。

五个任务与对应端点（与前端 821.67c1cf.js 的 H=[...] / API 表逐字对应）:
    merge       合成 20 次   POST /api/save/merge  {"level": 2~11}
    goldenAdmin 合成黄金管理员 1 次 POST /api/save/merge  {"level": 11}
    skill       战技 3 种    POST /api/save/skill  {"skillId": clear|wind|shake|swap}
    highScore   最高分 1500  POST /api/save/score  {"d": AES-GCM 的 base64}
    share       分享 1 次    POST /api/reward/share       （无 body）
    （领取）     POST /api/reward/claim-all （无 body）

为什么合成里一定要有 level=11:
    merge 任务的计数（mergeCountTotal）和最高级解锁（unlockedMax）是同一次响应
    一起回来的。前端拿到响应后：
        i.updateTaskProgress("merge", mergeCountTotal);
        i.updateTaskProgress("goldenAdmin", +(unlockedMax >= ek));   // ek = 11
    所以只刷次数不顶到 11，goldenAdmin 永远点不亮。脚本会保证最后一次合到 11。

服务端限流:
    密集请求会被直接断连（RemoteDisconnected，无任何响应），所以每次写请求之间
    固定停 1 秒。20 次合成大约 20 秒，属正常。
"""

import argparse
import contextlib
import importlib
import io
import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)


def _load_core():
    """找到核心模块并导入。

    主脚本改过名（orbipom.py → cli.py）。老用户目录里可能还躺着旧名字，
    所以两个都试 —— 谁在就用谁，别因为一个改名把别人的环境弄崩。
    """
    for name in ("cli", "orbipom"):
        try:
            return importlib.import_module(name)
        except ImportError:
            continue
    raise SystemExit(
        "找不到核心模块 —— 请把 cli.py 和本文件放在同一目录下。\n"
        "（旧版文件名 orbipom.py 也认，两个有一个就行。）")


ob = _load_core()

OK, NO, AR = ob.OK, ob.NO, ob.AR

# ---- 五个任务的目标值（前端 H=[...] 里的 target）----
TARGET_MERGE = 20
TARGET_SKILL = 3
TARGET_SCORE = 1500
TARGET_SHARE = 1

MAX_LEVEL = 11                 # ek：最高级，也是 goldenAdmin 的解锁条件
SKILL_ORDER = ["clear", "wind", "shake", "swap"]   # 前端 e0 表的顺序
MAX_FAILS = 3                  # 连续失败这么多次就停手，别硬撞限流
DELAY = 1.0                    # 写请求之间的间隔秒数（服务端会限流）


# ============================================================ 单次请求 ===


def _ok_data(body):
    """成功判定照抄前端：code === 0 且 data 为真值。返回 (data|None, 错误说明)。"""
    if not isinstance(body, dict):
        return None, "响应不是 JSON: %r" % (body,)
    if body.get("code") != 0 or not body.get("data"):
        return None, "code=%s %s" % (body.get("code"), body.get("msg") or "")
    return body["data"], None


def profile(call):
    """POST /api/save/profile（无 body）→ {guideDone, unlockedMax, highScore}。"""
    st, body = call("/api/save/profile", {}, "POST")
    data, _err = _ok_data(body)
    return data or {}


def progress(call):
    """GET /api/reward → ({taskId: task}, claimableCount, err)。"""
    tasks, claimable, err = ob.reward_tasks(call)
    if err:
        return None, 0, err
    return {t.get("id"): t for t in tasks}, claimable, None


def _num(task, key="current"):
    try:
        return int((task or {}).get(key) or 0)
    except (TypeError, ValueError):
        return 0


# ============================================================ 四个进度任务 ===


def do_merges(call, need, unlocked_max, delay=DELAY, raw=False):
    """刷合成。返回最终 unlockedMax（拿不到就返回入参）。

    need = 还需要发几次（20 - 当前次数）。
    unlocked_max < 11 时，把最后一次的 level 顶到 11 —— 这是 goldenAdmin 的唯一开关。
    """
    if need <= 0 and unlocked_max is not None and unlocked_max >= MAX_LEVEL:
        print("    %s 合成次数已满，最高级已解锁，跳过" % OK)
        return unlocked_max

    # 2,3,4,... 一路升到 11，之后固定 11。次数不够时最后一位强制 11。
    levels, i = [], 0
    while len(levels) < need:
        levels.append(min(2 + i, MAX_LEVEL))
        i += 1
    if unlocked_max is None or unlocked_max < MAX_LEVEL:
        if not levels:
            levels = [MAX_LEVEL]
        else:
            levels[-1] = MAX_LEVEL

    print("    %s 合成 %d 次: %s" % (AR, len(levels),
                                    ", ".join(str(x) for x in levels)))
    total, unlocked, fails = None, unlocked_max, 0
    for n, lv in enumerate(levels, 1):
        st, body = call("/api/save/merge", {"level": lv})
        if raw:
            print("        POST /api/save/merge {\"level\": %d}  ->  %s"
                  % (lv, json.dumps(body, ensure_ascii=False)))
        data, err = _ok_data(body)
        if err:
            fails += 1
            print("        %s [%2d/%2d] level=%-2d  失败 %s"
                  % (NO, n, len(levels), lv, err))
            if fails >= MAX_FAILS:
                print("        %s 连续失败 %d 次，停止合成（多半被限流，把 --delay 调大）"
                      % (NO, MAX_FAILS))
                break
        else:
            fails = 0
            total = data.get("mergeCountTotal", total)
            unlocked = data.get("unlockedMax", unlocked)
            print("        %s [%2d/%2d] level=%-2d  → 合成总数=%-3s 已解锁最高级=%s"
                  % (OK, n, len(levels), lv, total, unlocked))
            # 两个条件都满足才提前收工：次数够了、且最高级解锁了
            if (total or 0) >= TARGET_MERGE and (unlocked or 0) >= MAX_LEVEL:
                if n < len(levels):
                    print("        %s 合成 + 黄金管理员都已达成，剩余 %d 次不再发"
                          % (OK, len(levels) - n))
                break
        if n < len(levels):
            time.sleep(delay)
    return unlocked


def do_skills(call, current, delay=DELAY, raw=False):
    """刷战技。skillUseTotal 统计的是**种类数**，所以要发 3 个不同的 skillId。"""
    if current >= TARGET_SKILL:
        print("    %s 战技种类已满，跳过" % OK)
        return current
    print("    %s 战技: 需要 %d 种，按 %s 依次上报"
          % (AR, TARGET_SKILL, ", ".join(SKILL_ORDER)))
    total, fails = current, 0
    for n, sid in enumerate(SKILL_ORDER, 1):
        if (total or 0) >= TARGET_SKILL:
            break
        st, body = call("/api/save/skill", {"skillId": sid})
        if raw:
            print("        POST /api/save/skill {\"skillId\": \"%s\"}  ->  %s"
                  % (sid, json.dumps(body, ensure_ascii=False)))
        data, err = _ok_data(body)
        if err:
            fails += 1
            print("        %s [%d/%d] %-6s 失败 %s" % (NO, n, TARGET_SKILL, sid, err))
            if fails >= MAX_FAILS:
                print("        %s 连续失败 %d 次，停止上报战技" % (NO, MAX_FAILS))
                break
        else:
            fails = 0
            total = data.get("skillUseTotal", total)
            print("        %s [%d/%d] %-6s → 已用战技种类=%s"
                  % (OK, n, TARGET_SKILL, sid, total))
        time.sleep(delay)
    return total


def do_score(call, score, high_score, raw=False):
    """提交历史最高分。只增不减，所以低于当前成绩就不必发。"""
    if high_score is not None and high_score >= score:
        print("    %s 历史最高分已达标（%s >= %d），跳过" % (OK, high_score, score))
        return
    d = ob.encrypt({"score": score})
    print("    %s 提交分数 %d" % (AR, score))
    print("        d = %s" % d)
    st, body = call("/api/save/score", {"d": d})
    if raw:
        print("        POST /api/save/score {\"d\": \"...\"}  ->  %s"
              % json.dumps(body, ensure_ascii=False))
    data, err = _ok_data(body)
    if err:
        print("        %s 失败 HTTP %s %s" % (NO, st, err))
    else:
        print("        %s HTTP %s  best=%s isNewBest=%s"
              % (OK, st, data.get("best"), data.get("isNewBest")))


def do_share(call, current, raw=False):
    """上报「完成分享 1 次」。前端有节流，报过一次就不再发。"""
    if current >= TARGET_SHARE:
        print("    %s 分享任务已完成，跳过" % OK)
        return
    print("    %s 上报分享（POST /api/reward/share，无 body）" % AR)
    ok, body = ob.reward_share(call)
    if raw:
        print("        ->  %s" % json.dumps(body, ensure_ascii=False))
    if ok:
        print("        %s 成功" % OK)
    else:
        code = body.get("code") if isinstance(body, dict) else "?"
        msg = body.get("msg") if isinstance(body, dict) else body
        print("        %s 失败 code=%s %s" % (NO, code, msg))


# ============================================================ 领取 ===


def do_claim(call, claimable, raw=False):
    """一键领取 POST /api/reward/claim-all（无 body）。

    注意：一个都没得领时服务端**不是**返回空 results，而是报
    {"code":1300,"msg":"NO_REWARD_TO_CLAIM"} —— 这是正常情况，不是错误。
    """
    print("    %s 一键领取（POST /api/reward/claim-all，无 body）" % AR)
    if claimable:
        print("        服务端认为可领取: %d 个" % claimable)
    ok, body = ob.reward_claim_all(call)
    if raw:
        print("        ->  %s" % json.dumps(body, ensure_ascii=False))
    if ok:
        data = body.get("data") or {}
        got = data.get("results") or []
        if got:
            for r in got:
                print("        %s 领取 %-12s status=%s" % (OK, r.get("taskId"), r.get("status")))
        else:
            print("        %s 成功，但没有新发放的任务" % OK)
        return True
    code = body.get("code") if isinstance(body, dict) else "?"
    msg = body.get("msg") if isinstance(body, dict) else body
    if code == 1300 and str(msg).upper() == "NO_REWARD_TO_CLAIM":
        print("        %s 没有可领取的任务（服务端 code=1300 NO_REWARD_TO_CLAIM，属正常）"
              % OK)
        return True
    print("        %s 失败 code=%s %s" % (NO, code, msg))
    return False


# ============================================================ 主流程 ===


def run(dry_run=False):
    """建会话 → 跑主流程。"""
    print("=" * 62)
    print("融合！山团团！ —— 一键刷满全部任务奖励")
    print("=" * 62)

    call, _ident, err = ob._open_activity(argparse.Namespace(u8=None, role=None))
    if err:
        return 1
    return drive(call, dry_run=dry_run)


def drive(call, dry_run=False, claim=True, raw=False):
    """主流程本体。call 可注入 —— 自检就是靠这一点复用同一条路径的。"""
    # ---- 先读现状，只补差额，不重复刷 ----
    tasks, claimable, err = progress(call)
    if err:
        print("%s 拉取奖励任务失败: %s" % (NO, err))
        return 1
    prof = profile(call)
    high_score = prof.get("highScore")
    unlocked_max = prof.get("unlockedMax")

    print("\n%s 当前进度" % AR)
    print()
    ob._reward_table([tasks[k] for k in tasks])
    print("\n    可领取      : %d 个" % claimable)
    print("    profile     : highScore=%s  unlockedMax=%s  guideDone=%s"
          % (high_score, unlocked_max, prof.get("guideDone")))

    cur_merge = _num(tasks.get("merge"))
    cur_skill = _num(tasks.get("skill"))
    cur_score = _num(tasks.get("highScore"))
    cur_share = _num(tasks.get("share"))

    # 分数取「profile 的」和「任务里的」较大者 —— 两处都是同一个服务端成绩
    best = max([v for v in (high_score, cur_score) if v is not None] or [0])

    need_merge = max(0, TARGET_MERGE - cur_merge)
    need_skill = max(0, TARGET_SKILL - cur_skill)
    need_golden = (unlocked_max is None) or (unlocked_max < MAX_LEVEL)
    need_score = best < TARGET_SCORE
    need_share = cur_share < TARGET_SHARE

    print("\n%s 计划（只补差额）" % AR)
    print("    合成   : %s" % ("需要 %d 次（%d/%d）" % (need_merge, cur_merge, TARGET_MERGE)
                              if need_merge else "已满（%d/%d）" % (cur_merge, TARGET_MERGE)))
    print("    黄金管理员: %s" % ("需要顶到 %d 级（当前 unlockedMax=%s）"
                                 % (MAX_LEVEL, unlocked_max) if need_golden
                                 else "已解锁（unlockedMax=%s）" % unlocked_max))
    print("    战技   : %s" % ("需要 %d 种（%d/%d）" % (need_skill, cur_skill, TARGET_SKILL)
                              if need_skill else "已满（%d/%d）" % (cur_skill, TARGET_SKILL)))
    print("    分数   : %s" % ("需要提交 %d（当前 %d）" % (TARGET_SCORE, best) if need_score
                              else "已达标（%d >= %d）" % (best, TARGET_SCORE)))
    print("    分享   : %s" % ("需要上报 1 次" if need_share else "已完成"))
    print("    领取   : %s" % ("刷完后一键领取 claim-all" if claim else "跳过"))

    if dry_run:
        print("\n%s --dry-run：以上只是计划，没有发出任何写请求。" % AR)
        return 0

    print("\n%s 刷进度" % AR)
    unlocked_max = do_merges(call, need_merge, unlocked_max, raw=raw)
    do_skills(call, cur_skill, raw=raw)
    do_score(call, TARGET_SCORE, best, raw=raw)
    do_share(call, cur_share, raw=raw)

    # ---- 复读一次，看看刷完到底什么状态 ----
    tasks2, claimable2, err2 = progress(call)
    if err2:
        print("\n%s 复读任务列表失败: %s" % (NO, err2))
    else:
        tasks, claimable = tasks2, claimable2
        print("\n%s 刷完后" % AR)
        print()
        ob._reward_table([tasks[k] for k in tasks])
        print("\n    可领取: %d 个" % claimable)

    if not claim:
        print("=" * 62)
        return 0

    print("\n%s 领奖" % AR)
    do_claim(call, claimable, raw=raw)

    tasks3, claimable3, err3 = progress(call)
    if not err3:
        print("\n%s 最终状态" % AR)
        print()
        ob._reward_table([tasks3[k] for k in tasks3])
        print("\n    可领取: %d 个" % claimable3)
        left = [k for k, v in tasks3.items() if v.get("claimable")]
        if left:
            print("    %s 还有可领取的: %s" % (NO, ", ".join(left)))
            print("=" * 62)
            return 1
        done = [k for k, v in tasks3.items() if v.get("status")]
        print("\n%s 五个任务全部完成并领取（%d/%d）"
              % (OK, len(done), len(tasks3)))
        print("=" * 62)
        return 0

    print("=" * 62)
    return 0


# ============================================================ 离线自检 ===
# 用假 call 顶替真会话，把四个写路径的边界都跑一遍。不联网、不碰账号。
# 重点验三件容易写错的事：
#   1. 合成次数够了但 unlockedMax 没到 11 时，**不能**提前收工；
#   2. 反过来 unlockedMax 到了 11、次数也够了，必须提前收工不多发；
#   3. skillUseTotal 是「种类数」，要发不同的 skillId。


class FakeCall:
    """假的活动服务端，行为按前端 JS + 真实抓包复刻。"""

    def __init__(self, merge_total=0, unlocked=5, skill_total=0, best=0,
                 shared=False, claimed=False):
        self.merge_total = merge_total
        self.unlocked = unlocked
        self.used = set(SKILL_ORDER[:skill_total])
        self.best = best
        self.shared = shared
        self.claimed = claimed
        self.hits = []                 # 记录都打了哪些端点

    # -- 供断言用 --
    def count(self, path):
        return sum(1 for p in self.hits if p == path)

    def _tasks(self):
        return [
            {"id": "merge", "current": self.merge_total, "target": TARGET_MERGE,
             "status": 1 if self.claimed and self.merge_total >= TARGET_MERGE else None,
             "claimable": self.merge_total >= TARGET_MERGE and not self.claimed},
            {"id": "skill", "current": len(self.used), "target": TARGET_SKILL,
             "status": 1 if self.claimed and len(self.used) >= TARGET_SKILL else None,
             "claimable": len(self.used) >= TARGET_SKILL and not self.claimed},
            {"id": "highScore", "current": self.best, "target": TARGET_SCORE,
             "status": 1 if self.claimed and self.best >= TARGET_SCORE else None,
             "claimable": self.best >= TARGET_SCORE and not self.claimed},
            {"id": "share", "current": 1 if self.shared else 0, "target": TARGET_SHARE,
             "status": 1 if self.claimed and self.shared else None,
             "claimable": self.shared and not self.claimed},
            {"id": "goldenAdmin", "current": 1 if self.unlocked >= MAX_LEVEL else 0,
             "target": 1,
             "status": 1 if self.claimed and self.unlocked >= MAX_LEVEL else None,
             "claimable": self.unlocked >= MAX_LEVEL and not self.claimed},
        ]

    def __call__(self, path, payload=None, method=None):
        self.hits.append(path)
        if path == "/api/save/profile":
            return 200, {"code": 0, "msg": "", "data": {
                "guideDone": True, "unlockedMax": self.unlocked, "highScore": self.best}}
        if path == "/api/save/merge":
            lv = payload["level"]
            assert 2 <= lv <= 11, "level 越界: %r" % lv
            self.merge_total += 1
            self.unlocked = max(self.unlocked, lv)
            return 200, {"code": 0, "msg": "", "data": {
                "mergeCountTotal": self.merge_total, "unlockedMax": self.unlocked}}
        if path == "/api/save/skill":
            assert payload["skillId"] in SKILL_ORDER, payload
            self.used.add(payload["skillId"])
            return 200, {"code": 0, "msg": "", "data": {
                "skillUseTotal": len(self.used)}}
        if path == "/api/save/score":
            score = ob.decrypt(payload["d"])["score"]      # 顺手验一次加解密闭环
            new = score > self.best
            self.best = max(self.best, score)
            return 200, {"code": 0, "msg": "", "data": {
                "best": self.best, "isNewBest": new}}
        if path == "/api/reward/share":
            self.shared = True
            return 200, {"code": 0, "msg": "", "data": None}
        if path == "/api/reward":
            tasks = self._tasks()
            n = sum(1 for t in tasks if t["claimable"])
            return 200, {"code": 0, "msg": "", "data": {
                "tasks": tasks, "claimableCount": n}}
        if path == "/api/reward/claim-all":
            got = [{"taskId": t["id"], "status": 0}
                   for t in self._tasks() if t["claimable"]]
            if not got:
                return 200, {"code": 1300, "msg": "NO_REWARD_TO_CLAIM", "data": {}}
            self.claimed = True
            return 200, {"code": 0, "msg": "", "data": {"results": got}}
        raise AssertionError("未预期的端点: %s" % path)


def selftest():
    quiet = contextlib.redirect_stdout(io.StringIO())
    ok_n = bad_n = 0

    def case(name, cond, detail=""):
        nonlocal ok_n, bad_n
        if cond:
            ok_n += 1
            print("  [OK] %s%s" % (name, ("  " + detail) if detail else ""))
        else:
            bad_n += 1
            print("  [FAIL] %s  %s" % (name, detail))

    print("离线自检（假服务端，不联网）\n")
    fast = dict(delay=0)           # 自检不睡

    # --- 1. 从零开始：20 次合成，且必须顶到 11 ---
    s = FakeCall(merge_total=0, unlocked=5)
    with quiet:
        got = do_merges(s, TARGET_MERGE - 0, 5, **fast)
    case("从零刷合成：正好 20 次请求", s.count("/api/save/merge") == 20,
         "实际 %d" % s.count("/api/save/merge"))
    case("从零刷合成：unlockedMax 顶到 11", got == MAX_LEVEL, "实际 %s" % got)
    case("从零刷合成：mergeCountTotal = 20", s.merge_total == 20, "实际 %d" % s.merge_total)

    # --- 2. 次数够了但没到 11：必须继续发，不能提前收工 ---
    s = FakeCall(merge_total=20, unlocked=8)
    with quiet:
        got = do_merges(s, 0, 8, **fast)
    case("次数已满但 unlockedMax=8：仍会补一次", s.count("/api/save/merge") == 1,
         "实际 %d" % s.count("/api/save/merge"))
    case("补的那次 level 必须是 11", got == MAX_LEVEL, "实际 %s" % got)

    # --- 3. 两个条件都满足：一次都不发 ---
    s = FakeCall(merge_total=20, unlocked=11)
    with quiet:
        do_merges(s, 0, 11, **fast)
    case("已全部达成：0 次请求", s.count("/api/save/merge") == 0,
         "实际 %d" % s.count("/api/save/merge"))

    # --- 4. 差 1 次、已解锁 11：只发 1 次，且不必强行顶 11 ---
    s = FakeCall(merge_total=19, unlocked=11)
    with quiet:
        do_merges(s, 1, 11, **fast)
    case("差 1 次：只发 1 次", s.count("/api/save/merge") == 1,
         "实际 %d" % s.count("/api/save/merge"))

    # --- 5. 战技：必须 3 个不同的 skillId ---
    s = FakeCall()
    with quiet:
        total = do_skills(s, 0, **fast)
    case("战技：正好 3 次请求", s.count("/api/save/skill") == 3,
         "实际 %d" % s.count("/api/save/skill"))
    case("战技：3 个互不相同", len(s.used) == 3, "实际 %r" % sorted(s.used))
    case("战技：skillUseTotal = 3", total == 3, "实际 %s" % total)

    # --- 6. 战技已满：一次都不发 ---
    s = FakeCall(skill_total=3)
    with quiet:
        do_skills(s, 3, **fast)
    case("战技已满：0 次请求", s.count("/api/save/skill") == 0,
         "实际 %d" % s.count("/api/save/skill"))

    # --- 7. 分数：已达标不发，未达标要发且服务端能解出明文 ---
    s = FakeCall(best=99999)
    with quiet:
        do_score(s, TARGET_SCORE, 99999)
    case("分数已达标：0 次请求", s.count("/api/save/score") == 0,
         "实际 %d" % s.count("/api/save/score"))

    s = FakeCall(best=0)
    with quiet:
        do_score(s, TARGET_SCORE, 0)
    case("分数未达标：发 1 次", s.count("/api/save/score") == 1,
         "实际 %d" % s.count("/api/save/score"))
    case("分数：服务端解出的是 %d" % TARGET_SCORE, s.best == TARGET_SCORE,
         "实际 %d" % s.best)

    # --- 8. 分享：发过一次就不发 ---
    s = FakeCall(shared=False)
    with quiet:
        do_share(s, 0)
    case("分享未完成：发 1 次", s.count("/api/reward/share") == 1)
    s2 = FakeCall(shared=True)
    with quiet:
        do_share(s2, 1)
    case("分享已完成：0 次请求", s2.count("/api/reward/share") == 0)

    # --- 9. claim-all：NO_REWARD_TO_CLAIM 要当成正常，不能当失败 ---
    s = FakeCall(merge_total=20, unlocked=11, claimed=True)   # 全领过 → 服务端报 1300
    with quiet:
        r = do_claim(s, 0)
    case("claim-all 无奖可领（1300）：判为正常", r is True)

    s = FakeCall(merge_total=20, unlocked=11)                 # merge + goldenAdmin 可领
    with quiet:
        r = do_claim(s, 2)
    case("claim-all 有奖可领：判为成功", r is True)
    case("claim-all 有奖可领：确实领到了", s.claimed is True)

    # --- 10. 完整跑一遍：从全新账号到五任务全领 ---
    s = FakeCall(merge_total=0, unlocked=5, skill_total=0, best=0, shared=False)
    with quiet:
        rc = drive(s)
    tasks, _c, _e = progress(s)
    case("整轮：返回码 0", rc == 0, "实际 %s" % rc)
    case("整轮：五个任务都已完成并领取",
         all(t.get("status") for t in tasks.values()),
         str({k: v.get("status") for k, v in tasks.items()}))
    case("整轮：合成 20 次", s.merge_total == 20, "实际 %d" % s.merge_total)
    case("整轮：unlockedMax = 11", s.unlocked == 11, "实际 %d" % s.unlocked)
    case("整轮：战技 3 种", len(s.used) == 3, "实际 %d" % len(s.used))
    case("整轮：最高分 %d" % TARGET_SCORE, s.best == TARGET_SCORE, "实际 %d" % s.best)
    case("整轮：分享已上报", s.shared is True)

    # --- 11. 已经全满的账号：一个写请求都不该发 ---
    s = FakeCall(merge_total=20, unlocked=11, skill_total=3, best=99999,
                 shared=True, claimed=True)
    before = len(s.hits)
    with quiet:
        rc = drive(s)
    writes = [p for p in s.hits[before:]
              if p in ("/api/save/merge", "/api/save/skill",
                       "/api/save/score", "/api/reward/share")]
    case("全满账号：返回码 0", rc == 0, "实际 %s" % rc)
    case("全满账号：0 个写请求", not writes, "实际 %r" % writes)

    print("\n" + "-" * 52)
    print("通过 %d 项，失败 %d 项" % (ok_n, bad_n))
    return 1 if bad_n else 0


# ============================================================== CLI ===


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="claim_all.py",
        description="orbipom-merge 一键获取全部奖励（刷满五个任务 + 一键领取）",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true",
                    help="只看还差多少，不发写请求")
    ap.add_argument("--selftest", action="store_true",
                    help="离线自检：用假服务端跑 28 项，不联网")
    a = ap.parse_args(argv)

    if a.selftest:
        return selftest()

    ob.bypass_hosts()          # 活动域若被 hosts 指到本机，先绕开
    return run(dry_run=a.dry_run)


if __name__ == "__main__":
    sys.exit(main())
