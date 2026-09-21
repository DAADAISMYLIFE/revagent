#!/usr/bin/env python
"""Calibrate three content-free "stuck" detectors on revagent transcripts.

Re-run:  ~/.revagent-venv/bin/python stuck_detectors.py [--json out.json]

D1  first step with `notes add` to section facts/hypotheses ("never" if none)
D2  longest run of consecutive "scripting" steps (every tool call in the step is
    bash-with-inline-script [python3 | << | .py] or decompile/summarize) with no
    run_binary/run_gui.  Any other step (plain bash, notes, run_binary, run_gui,
    submit_flag, no tool call) breaks the run.
    D2b (variant, reported alongside): run of steps with >=1 tool call and NO
    run_binary/run_gui AND no bash cmd that executes the target binary
    ("./<bin>", "wine", gdb/strace/ltrace on it).  Broken only by such observations.
D3  consecutive bash calls (in call order, across steps) whose script text
    (heredoc body or python -c string; else whole cmd) is "similar" to the previous
    bash call: first 200 chars identical after whitespace normalisation, or
    Jaccard(line sets) > 0.6.  Streak length = number of calls in the run.

Rule-firing conventions (stated so a human can shift by one if they prefer):
 R1(N): fires at step N+1 if no facts/hypotheses note was added at steps 1..N.
 R2(K): after K consecutive scripting steps, the (K+1)-th consecutive scripting
        step is refused -> fire step = start+K.  Counter resets after a fire, so a
        maximal run of length L fires floor(L/(K+1)) times.
 R3(T): fires at the bash call that makes a similarity streak reach length T;
        counter resets after a fire -> a run of length L fires floor(L/T) times.
"""
import json, re, sys, glob, os, collections

ROOT = "/mnt/c/Users/강순우/Documents/vs/rev"
TRANSCRIPTS = [
    ("basic",            f"{ROOT}/quiz/basic/.revagent/transcript.jsonl"),
    ("relativity",       f"{ROOT}/quiz/relativity/.revagent/transcript.jsonl"),
    ("captain-hook",     f"{ROOT}/quiz/captain-hook/.revagent/transcript.jsonl"),
    ("captain-hook.arch",f"{ROOT}/quiz/captain-hook.archive-pre-ladder/transcript.jsonl"),
    ("damnida",          f"{ROOT}/quiz/damnida/.revagent/transcript.jsonl"),
    ("multipoint",       f"{ROOT}/quiz/multipoint/.revagent/transcript.jsonl"),
    ("revlogin",         f"{ROOT}/quiz/revlogin/.revagent/transcript.jsonl"),
] + [(f"mini/{os.path.basename(os.path.dirname(os.path.dirname(p)))}", p)
     for p in sorted(glob.glob(f"{ROOT}/revagent/bench/mini/*/.revagent/transcript.jsonl"))]
CONSOLE_LOGS = [("ROVM(run4,log)", f"{ROOT}/quiz/logs/ROVM.sandbox.run4.log")]  # no transcript exists for ROVM

ANSWERS = {"multipoint":"DH{Poly_m0ly_mult1pl1c4t1on_m0dular~!}","revlogin":"DH{se4rch_de3ee3p,_d1ve_int0_th3_bott0m}",
           "captain-hook":"DH{H0000KER}","relativity":"DH{1d459fbdd85803e8223c2a11604dac728aceaffbc454aedce56b1a8d4e063360}",
           "basic":"DH{Reverse__your__brain_;)}","win_console":"DH{w1ne_c0ns0le}","win_gui":"DH{gui_p41nt_0k}",
           "win_gui_key":"DH{k3y_dr1v3n_ui}","win_gui_32":"DH{w1n32_runb00k}"}
BINARIES = {"basic":["chall9.exe"],"relativity":["relativity"],"captain-hook":["CaptainHook.exe","CaptainHook_patched.exe"],
            "captain-hook.arch":["CaptainHook.exe","CaptainHook_patched.exe"],"damnida":["damnida"],"multipoint":["multipoint"],
            "revlogin":["login"],"ROVM(run4,log)":["chall"],"mini/win_console":["win_console.exe"],"mini/win_gui":["win_gui.exe"],
            "mini/win_gui_32":["win_gui_32.exe"],"mini/win_gui_key":["win_gui_key.exe"]}

SCRIPT_RE = re.compile(r"python3|<<|\.py")

def is_inline_script(cmd):  return bool(SCRIPT_RE.search(cmd or ""))

def runs_binary(cmd, bins):
    """bash cmd that executes the target binary (observation done via bash)."""
    if not cmd: return False
    if re.search(r"\bwine(64)?\b", cmd): return True
    for b in bins:
        if re.search(r"(^|[\s|;&(`])(\./|/work/\S*/)?" + re.escape(b) + r"(\s|$|;|\||&|\))", cmd) and not re.search(r"(file|strings|xxd|objdump|readelf|nm|md5sum|sha256sum|cp|ls|hexdump|od|wc|cat|stat|chmod|patchelf|checksec)\s+[^|;&]*"+re.escape(b), cmd):
            return True
        if re.search(r"\b(gdb|strace|ltrace|qemu\S*)\b[^|;&]*" + re.escape(b), cmd): return True
    return False

def script_text(cmd):
    """heredoc body, or python -c string; else None."""
    if not cmd: return None
    m = re.search(r"<<-?\s*['\"]?(\w+)['\"]?\s*\n(.*?)(?:\n\1\s*(?:\n|$)|$)", cmd, re.S)
    if m: return m.group(2)
    m = re.search(r"python3?\s+-c\s+(['\"])(.*?)\1(?:\s|$)", cmd, re.S)
    if m and len(m.group(2)) > 20: return m.group(2)
    m = re.search(r"python3?\s+-c\s+(['\"])(.*)$", cmd, re.S)   # unterminated (truncated logs)
    if m: return m.group(2)
    return None

def norm_ws(s): return re.sub(r"\s+", " ", s).strip()
def similar(a, b, P=200):
    if a is None or b is None: return False
    na, nb = norm_ws(a), norm_ws(b)
    if len(na) >= P and na[:P] == nb[:P]: return True
    if len(na) < P and na == nb: return True
    la = {l.strip() for l in a.splitlines() if l.strip()}; lb = {l.strip() for l in b.splitlines() if l.strip()}
    if not la or not lb: return False
    return len(la & lb) / len(la | lb) > 0.6

# ---------------------------------------------------------------- parsing
def parse_transcript(name, path):
    """yield sessions: dict(steps=[{step, calls=[(tool,args)], reasoning_len, has_tool}], end=..)"""
    sessions = []; cur = None; pending_reason = None
    for line in open(path, encoding="utf-8"):
        d = json.loads(line)
        r = d.get("role")
        if r == "_meta":
            ev = d.get("event")
            if ev == "session_start":
                cur = {"steps": [], "end": None, "meta": collections.Counter()}; sessions.append(cur)
            elif ev == "end": cur["end"] = d
            else: cur["meta"][ev] += 1
            continue
        if cur is None: continue
        if r == "_reasoning":
            pending_reason = (d.get("step"), len(d.get("content") or ""))
        elif r == "assistant":
            calls = []
            for t in d.get("tool_calls") or []:
                try: a = json.loads(t["function"]["arguments"])
                except Exception: a = {"_raw": t["function"]["arguments"]}
                calls.append((t["function"]["name"], a))
            step_no, rlen = pending_reason if pending_reason else (len(cur["steps"]) + 1, 0)
            pending_reason = None
            cur["steps"].append({"step": step_no, "calls": calls, "rlen": rlen, "has_tool": bool(calls),
                                 "text": (d.get("content") or "")})
    return sessions

def parse_console_log(name, path):
    txt = open(path, "rb").read().decode("utf-8", "replace")
    steps = collections.OrderedDict()
    for ln in txt.split("\n"):
        m = re.match(r"^\[(\d+)\] > (\w+) (.*)$", ln.rstrip("\r"))
        if not m: continue
        n = int(m.group(1)); raw = m.group(3)
        try: a = json.loads(raw)
        except Exception:
            mm = re.match(r'^\{"cmd": "(.*)$', raw)
            a = {"cmd": bytes(mm.group(1), "utf-8").decode("unicode_escape") if mm else raw, "_truncated": True}
        steps.setdefault(n, []).append((m.group(2), a))
    mm = re.search(r"steps=(\d+)", txt)
    sess = {"steps": [{"step": n, "calls": c, "rlen": -1, "has_tool": True, "text": ""} for n, c in steps.items()],
            "end": {"status": "unsolved", "reason": "console log only; args truncated ~120 chars; no reasoning", "steps": int(mm.group(1)) if mm else len(steps), "flag": None},
            "meta": collections.Counter(), "degraded": True}
    return [sess]

# ---------------------------------------------------------------- per-session measures
def analyse(name, sess, bins):
    steps = sess["steps"]; end = sess["end"] or {}
    status = end.get("status") or "incomplete"
    reason = end.get("reason") or ""
    if reason.startswith("error"): status = "error"
    if end.get("runbook"): status = "runbook"
    flag = end.get("flag"); challenge_key = name.split("/")[-1].replace(".arch","")
    if status == "solved" and ANSWERS.get(challenge_key) and flag != ANSWERS[challenge_key]: status = "solved(wrong)"

    # D1
    d1 = None; d1_first_any_note = None
    for s in steps:
        for tool, a in s["calls"]:
            if tool == "notes" and a.get("action") == "add":
                if d1_first_any_note is None: d1_first_any_note = s["step"]
                if a.get("section") in ("facts", "hypotheses") and d1 is None: d1 = s["step"]
    # per-step classification
    lit = []; cls = []  # (step, kind) kind in {script, observe, other, none}
    n_obs_tool = 0; n_obs_bash = 0; submit_step = None; bash_calls = []
    for s in steps:
        kinds = set()
        for tool, a in s["calls"]:
            if tool in ("run_binary", "run_gui"): kinds.add("observe"); n_obs_tool += 1
            elif tool == "bash":
                cmd = a.get("cmd", "")
                bash_calls.append((s["step"], cmd, script_text(cmd)))
                if runs_binary(cmd, bins):
                    kinds.add("observe_bash"); n_obs_bash += 1
                    if is_inline_script(cmd): kinds.add("script_lit")   # literal spec: still a scripting call
                elif is_inline_script(cmd): kinds.add("script"); kinds.add("script_lit")
                else: kinds.add("plainbash")
            elif tool in ("decompile", "summarize"): kinds.add("script"); kinds.add("script_lit")
            elif tool == "submit_flag":
                kinds.add("submit")
                if submit_step is None or True: submit_step = s["step"]
            else: kinds.add("other")   # notes etc.
        lit_script = bool(kinds) and kinds <= {"script", "script_lit", "observe_bash"} and "script_lit" in kinds and not ({"plainbash","other","submit","observe"} & kinds)
        if not kinds: kind = "none"
        elif kinds <= {"script", "script_lit"}: kind = "script"
        elif "observe" in kinds: kind = "observe"
        elif "observe_bash" in kinds: kind = "observe_bash"
        elif "submit" in kinds: kind = "submit"
        else: kind = "mixed"   # plainbash/notes/other (possibly with scripts)
        cls.append((s["step"], kind)); lit.append((s["step"], lit_script))
    # D2 strict: runs of kind=='script'
    def runs(pred):
        out = []; start = None; L = 0
        for st, k in cls:
            if pred(k):
                if start is None: start = st; L = 1
                else: L += 1
            else:
                if start is not None: out.append((L, start)); start = None
        if start is not None: out.append((L, start))
        return out
    d2_runs = runs(lambda k: k == "script")
    d2b_runs = runs(lambda k: k in ("script", "mixed"))
    d2lit_runs = []; start = None; L = 0
    for st, ok in lit:
        if ok: L, start = (L + 1, start) if start is not None else (1, st)
        else:
            if start is not None: d2lit_runs.append((L, start)); start = None
    if start is not None: d2lit_runs.append((L, start))          # anything that is a tool call but not an observation/submit
    # D3
    def d3(P):
        out = []; streak = 1; start = None; prev = None
        for st, cmd, txt in bash_calls:
            if prev is not None and similar(prev[2], txt, P):
                if streak == 1: start = prev[0]
                streak += 1
            else:
                if streak >= 2: out.append((streak, start))
                streak = 1; start = None
            prev = (st, cmd, txt)
        if streak >= 2: out.append((streak, start))
        return out
    d3_runs = d3(200); d3_100_runs = d3(100)
    big_reason = sum(1 for s in steps if s["rlen"] > 8000)
    no_tool_steps = [s["step"] for s in steps if not s["has_tool"]]
    return dict(challenge=name, status=status, reason=reason[:40], steps=len(steps), steps_declared=end.get("steps"),
                d1=d1, d1_any=d1_first_any_note, cls=cls, d2_runs=d2_runs, d2b_runs=d2b_runs, d2lit_runs=d2lit_runs, d3_100_runs=d3_100_runs, obs_tool=n_obs_tool,
                obs_bash=n_obs_bash, d3_runs=d3_runs, big_reason=big_reason, submit_step=submit_step, flag=flag,
                no_tool_steps=no_tool_steps, n_bash=len(bash_calls), n_bash_script=sum(1 for b in bash_calls if b[2] is not None),
                degraded=sess.get("degraded", False), rlens=[(s["step"], s["rlen"]) for s in steps])

def longest(rs): return max(rs, key=lambda x: (x[0], -x[1])) if rs else (0, None)
def fires_r2(rs, K): return [st + K + i*(K+1) for L, st in rs for i in range(L // (K+1))]
def fires_r3(rs, T): return [st + T - 1 + i*T for L, st in rs for i in range(L // T)]

# ---------------------------------------------------------------- main
rows = []
for name, path in TRANSCRIPTS:
    if not os.path.exists(path): print("MISSING", path); continue
    for i, sess in enumerate(parse_transcript(name, path), 1):
        r = analyse(name, sess, BINARIES.get(name, [])); r["session"] = i; rows.append(r)
for name, path in CONSOLE_LOGS:
    if os.path.exists(path):
        for i, sess in enumerate(parse_console_log(name, path), 1):
            r = analyse(name, sess, BINARIES.get(name, [])); r["session"] = i; rows.append(r)

def fmt(x): return "-" if x is None else str(x)
print("=== Per-session table  (D2/D3 as len@start; obs = run_binary+run_gui calls; obs_bash = bash cmds that execute the target binary)")
hdr = f"{'challenge':18} {'s':>2} {'status':13} {'steps':>5} {'D1':>5} {'D1any':>5} {'D2':>7} {'D2b':>7} {'obs':>3} {'obsB':>4} {'D3':>7} {'r>8k':>4} {'submit':>6} {'notool':>6}"
print(hdr)
for r in rows:
    if r["steps"] == 0 and r["status"] == "error": continue
    L2, s2 = longest(r["d2_runs"]); L2b, s2b = longest(r["d2b_runs"]); L3, s3 = longest(r["d3_runs"])
    print(f"{r['challenge']:18} {r['session']:>2} {r['status']:13} {r['steps']:>5} {fmt(r['d1'] or 'never'):>5} {fmt(r['d1_any'] or 'never'):>5} "
          f"{L2:>3}@{fmt(s2):<3} {L2b:>3}@{fmt(s2b):<3} {r['obs_tool']:>3} {r['obs_bash']:>4} {L3:>3}@{fmt(s3):<3} {r['big_reason']:>4} {fmt(r['submit_step']):>6} {len(r['no_tool_steps']):>6}"
          + ("  [DEGRADED: console log, truncated args]" if r["degraded"] else ""))
print("\n=== Variants: D2lit = literal spec (bash 'python3 ...| ./bin' counts as scripting; only run_binary/run_gui tools or non-script steps break);  D3p100 = D3 with 100-char prefix")
print(f"{'session':40} {'D2':>7} {'D2lit':>7} {'R2lit fires K=4/5/6':>22} {'D3':>7} {'D3p100':>7} {'R3p100 fires T=3/4':>20}")
for r in rows:
    if r["steps"] < 5: continue
    L2, s2 = longest(r["d2_runs"]); L2l, s2l = longest(r["d2lit_runs"]); L3, s3 = longest(r["d3_runs"]); L3b, s3b = longest(r["d3_100_runs"])
    f2 = "/".join(str(len(fires_r2(r["d2lit_runs"], K))) for K in (4,5,6)); f3 = "/".join(str(len(fires_r3(r["d3_100_runs"], T))) for T in (3,4))
    print(f"{r['challenge']+'#'+str(r['session']):40} {L2:>3}@{fmt(s2):<3} {L2l:>3}@{fmt(s2l):<3} {f2:>22} {L3:>3}@{fmt(s3):<3} {L3b:>3}@{fmt(s3b):<3} {f3:>20}")
print("\n(status 'error' rows with 0 steps omitted; 'incomplete' = session_start without end event, i.e. killed)")

live = [r for r in rows if r["steps"] >= 5]
solved = [r for r in live if r["status"] == "solved"]
unsolved = [r for r in live if r["status"] != "solved"]
def tag(r): return f"{r['challenge']}#{r['session']}({r['status'][:6]},{r['steps']}st)"

print("\n=== Q1  R1(N): block until Facts note exists after step N  (fires at N+1 if D1 > N or never)")
for N in (6, 8, 10):
    print(f"-- N={N}")
    for grp, lab in ((solved, "SOLVED  "), (unsolved, "UNSOLVED")):
        f = [r for r in grp if (r["d1"] is None or r["d1"] > N)]
        print(f"   {lab}: fires in {len(f)}/{len(grp)}: " + "; ".join(f"{tag(r)} fire@{N+1} facts@{fmt(r['d1'] or 'never')}" for r in f))
print("   D1 distribution  solved:", sorted((r['d1'] or 999) for r in solved), " unsolved:", sorted((r['d1'] or 999) for r in unsolved), "(999=never)")

print("\n=== Q2  R2(K): refuse the (K+1)-th consecutive scripting step  [strict D2: bash-inline-script/decompile/summarize only]")
for K in (4, 5, 6):
    print(f"-- K={K}")
    for r in live:
        f = fires_r2(r["d2_runs"], K)
        runs_ = [f"{L}@{st}" for L, st in r["d2_runs"] if L >= K+1]
        print(f"   {tag(r):40} fires={len(f):2} at steps {f}   qualifying runs(len@start) {runs_}")
print("\n=== Q2b R2(K) with the loose D2b (any tool step that is not run_binary/run_gui/bash-run-of-binary/submit)")
for K in (4, 5, 6):
    print(f"-- K={K}")
    for r in live:
        f = fires_r2(r["d2b_runs"], K)
        print(f"   {tag(r):40} fires={len(f):2} at steps {f[:25]}{' ...' if len(f)>25 else ''}")

print("\n=== Q3  R3(T): D3 similarity streak reaches T bash calls")
for T in (3, 4):
    print(f"-- T={T}")
    for r in live:
        f = fires_r3(r["d3_runs"], T)
        runs_ = [f"{L}@{st}" for L, st in r["d3_runs"] if L >= T]
        print(f"   {tag(r):40} fires={len(f):2} at steps {f[:20]}{' ...' if len(f)>20 else ''}   runs {runs_[:12]}")


STUCK_STATUSES = ("unsolved", "incomplete", "solved(wrong)")
stuck = [r for r in live if r["status"] in STUCK_STATUSES]
errored = [r for r in live if r["status"] == "error"]
print("\n=== Q4  asked grid (N in 6/8/10, K in 4/5/6, T in 3/4).  Groups: SOLVED(%d) | STUCK=time-limit/killed/wrong-flag(%d) | API-ERROR-terminated(%d, stuckness unknown)" % (len(solved), len(stuck), len(errored)))
print("     per cell: sessions with >=1 fire (any rule) / group, and total #fires in group.  FP = fires in SOLVED sessions.")
def cell(rs, N, K, T):
    sess = 0; fires = 0; f1 = f2 = f3 = 0
    for r in rs:
        a = 1 if (N and (r["d1"] is None or r["d1"] > N)) else 0
        b = len(fires_r2(r["d2_runs"], K)) if K else 0
        c = len(fires_r3(r["d3_runs"], T)) if T else 0
        sess += 1 if (a or b or c) else 0; fires += a + b + c; f1 += a; f2 += b; f3 += c
    return sess, fires, f1, f2, f3
print(f"   {'N':>3} {'K':>3} {'T':>3} | {'SOLVED sess':>11} {'FP fires(R1/R2/R3)':>20} | {'STUCK sess':>10} {'fires(R1/R2/R3)':>17} | {'ERR sess':>8} {'fires':>5}")
grid = []
for N in (None, 6, 8, 10):
    for K in (None, 4, 5, 6):
        for T in (None, 3, 4):
            if N is None and K is None and T is None: continue
            s_ = cell(solved, N, K, T); u_ = cell(stuck, N, K, T); e_ = cell(errored, N, K, T)
            grid.append((N, K, T, s_, u_, e_))
            print(f"   {fmt(N):>3} {fmt(K):>3} {fmt(T):>3} | {s_[0]:>4}/{len(solved):<6} {s_[1]:>5} ({s_[2]}/{s_[3]}/{s_[4]}){'':6} | {u_[0]:>4}/{len(stuck):<5} {u_[1]:>5} ({u_[2]}/{u_[3]}/{u_[4]}){'':4} | {e_[0]:>3}/{len(errored):<4} {e_[1]:>5}")
print("\n   Ranking by (stuck sessions caught) - (solved sessions flagged), tie-break fewer FP fires:")
for N, K, T, s_, u_, e_ in sorted(grid, key=lambda g: (-(g[4][0]-g[3][0]), g[3][1]))[:12]:
    print(f"     N={fmt(N):>4} K={fmt(K):>4} T={fmt(T):>4}  stuck caught {u_[0]}/{len(stuck)}  solved flagged {s_[0]}/{len(solved)}  FP fires {s_[1]}")
print("\n   Per-rule fire counts per SOLVED session (false positives), asked thresholds:")
print(f"   {'session':38} {'R1@6':>5} {'R1@8':>5} {'R1@10':>5} {'R2@4':>5} {'R2@5':>5} {'R2@6':>5} {'R3@3':>5} {'R3@4':>5}")
for r in solved + [x for x in live if x["status"]=="solved(wrong)"]:
    v = [1 if (r["d1"] is None or r["d1"] > N) else 0 for N in (6,8,10)] + [len(fires_r2(r["d2_runs"],K)) for K in (4,5,6)] + [len(fires_r3(r["d3_runs"],T)) for T in (3,4)]
    print(f"   {tag(r):38} " + " ".join(f"{x:>5}" for x in v))

print("\n=== Per-session step classification (s=script o=run_binary/run_gui b=bash-runs-binary m=plain-bash/notes/mixed S=submit .=no tool)")
sym = {"script":"s","observe":"o","observe_bash":"b","mixed":"m","submit":"S","none":"."}
for r in live:
    line = "".join(sym[k] for _, k in r["cls"])
    print(f"{tag(r):40} " + " ".join(line[i:i+10] for i in range(0, len(line), 10)))

print("\n=== Reasoning-length: steps with >8000 chars (step:len/1000)")
for r in live:
    big = [(st, rl//1000) for st, rl in r["rlens"] if rl > 8000]
    print(f"{tag(r):40} {big}")

if "--json" in sys.argv:
    out = sys.argv[sys.argv.index("--json")+1]
    json.dump(rows, open(out, "w"), indent=1, default=str); print("wrote", out)

def call_summary(c):
    tool, a = c
    if tool == "bash":
        cmd = a.get("cmd", ""); st = script_text(cmd)
        head = norm_ws(cmd)[:60]
        body = norm_ws(st)[:70] if st else ""
        return f"bash[{head}]" + (f" SCRIPT<{body}>" if body else "")
    if tool == "decompile": return f"decompile[{a.get('action')} {a.get('target') or a.get('binary')}]"
    if tool == "notes": return f"notes[{a.get('action')} {a.get('section')}]"
    if tool == "run_binary": return f"run_binary[{a.get('path')} stdin={str(a.get('stdin'))[:20]!r}]"
    if tool == "run_gui": return f"run_gui[{a.get('path')} {len(a.get('actions') or [])} actions]"
    return f"{tool}[{norm_ws(json.dumps(a))[:50]}]"

DETAIL = [r for r in live if r["status"] in ("solved", "solved(wrong)")] if "--detail-all" not in sys.argv else live
print("\n=== JUDGMENT DUMP: what each SOLVED session did inside runs that would fire R2(K=4) or R3(T=3)  (step: tool calls)")
sess_by_tag = {}
for name, path in TRANSCRIPTS:
    if os.path.exists(path):
        for i, sess in enumerate(parse_transcript(name, path), 1): sess_by_tag[(name, i)] = sess
for name, path in CONSOLE_LOGS:
    if os.path.exists(path):
        for i, sess in enumerate(parse_console_log(name, path), 1): sess_by_tag[(name, i)] = sess
for r in DETAIL:
    sess = sess_by_tag[(r["challenge"], r["session"])]; by_step = {s["step"]: s for s in sess["steps"]}
    runs2 = [(L, st) for L, st in r["d2_runs"] if L >= 5]; runs3 = [(L, st) for L, st in r["d3_runs"] if L >= 3]
    if not runs2 and not runs3: continue
    print(f"--- {tag(r)}  submit@{fmt(r['submit_step'])}  D2 runs>=5: {runs2}   D3 runs>=3: {runs3}")
    shown = set()
    for L, st in runs2:
        print(f"   D2 run {L}@{st}: R2 fires K=4@{st+4} K=5@{st+5} K=6@{st+6}")
        for k in range(L):
            stp = st + k
            if stp in by_step and stp not in shown:
                shown.add(stp); print(f"     {stp:>3}: " + " | ".join(call_summary(c) for c in by_step[stp]["calls"]))
    for L, st in runs3:
        print(f"   D3 run {L} bash calls from step {st}: R3 fires T=3 at the 3rd call, T=4 at the 4th")
        for stp in sorted({s for s in by_step if st <= s <= st + L + 2})[:L+2]:
            if stp not in shown:
                shown.add(stp); print(f"     {stp:>3}: " + " | ".join(call_summary(c) for c in by_step[stp]["calls"]))

if "--d3check" in sys.argv:
    print("\n=== D3 pair metrics for basic#1 (prefix200-equal, jaccard)")
    sess = sess_by_tag[("basic", 1)]; prev = None
    for s in sess["steps"]:
        for tool, a in s["calls"]:
            if tool != "bash": continue
            t = script_text(a.get("cmd", ""))
            if prev is not None and t is not None and prev[1] is not None:
                na, nb = norm_ws(prev[1]), norm_ws(t)
                la = {l.strip() for l in prev[1].splitlines() if l.strip()}; lb = {l.strip() for l in t.splitlines() if l.strip()}
                j = len(la & lb) / len(la | lb) if la and lb else 0
                print(f"   step {prev[0]:>3}->{s['step']:>3}: prefix200={'Y' if na[:200]==nb[:200] and len(na)>=200 else 'n'} jaccard={j:.2f} similar={similar(prev[1], t)}  lines={len(la)}/{len(lb)}")
            prev = (s["step"], t)
