# revagent

Status: solved multipoint, revlogin and relativity (Dreamhack) in the sandbox; captain-hook, damnida and ROVM are still open; the sandbox, evidence-ladder and PE stage (wine / `run_gui`) are merged. Details in the Bench table.

Autonomous reverse-engineering agent for CTF challenges (target: Dreamhack rev, level 7–8),
driven by a self-hosted Qwen3.8-27B served through vLLM.

Give it a challenge folder (binary + `desc.txt`) and it triages, decompiles with Ghidra headless,
classifies the check, solves it (z3 / angr / gdb / re-implementation), verifies the candidate by
running the binary, and submits a `DH{...}` flag — or reports how far it got.

## Setup (WSL / Linux, no sudo needed)
```bash
python3 -m venv --without-pip --system-site-packages ~/.revagent-venv   # ensurepip may be unavailable; pip comes from the system site
PYVER=$(~/.revagent-venv/bin/python -c 'import sys;print(f"python{sys.version_info[0]}.{sys.version_info[1]}")')
echo "$HOME/.local/lib/$PYVER/site-packages" > ~/.revagent-venv/lib/$PYVER/site-packages/usersite.pth   # only if angr/z3 are installed with pip --user
~/.revagent-venv/bin/python -m pip install -e .
bash scripts/install_ghidra.sh                             # JDK 21 + Ghidra under ~/tools (~600 MB)
mkdir -p ~/.revagent && cp .secure.example ~/.revagent/.secure && $EDITOR ~/.revagent/.secure   # QWEN / URL / MODEL
```
`~/.revagent/.secure` is the recommended location (it's outside any challenge directory, so it can never
be picked up or leaked from a challenge's own `.secure`/cwd search). The repo root also works
(`load_secure` first takes the `QWEN`/`URL`/`MODEL` environment variables when all three are set and no
`--secure` path was given — this is how the sandbox container gets them — and otherwise checks
`$REVAGENT_SECURE`, then `./.secure`, then the repo root, then `~/.revagent/.secure`)
but keep the key out of individual challenge directories.

There is no `pytest` shim in the venv; run tests with `~/.revagent-venv/bin/python -m pytest`.

The model server is a separate repo: [qwen3.8-vllm-runpod](https://github.com/DAADAISMYLIFE/qwen3.8-vllm-runpod)
(vLLM with `--enable-auto-tool-choice --tool-call-parser qwen3_coder --reasoning-parser qwen3`).

## Use
```bash
~/.revagent-venv/bin/revagent solve path/to/challenge            # asks you only when blocked
~/.revagent-venv/bin/revagent solve path/to/challenge --no-ask   # fully unattended
~/.revagent-venv/bin/revagent bench chal1 chal2 ...              # batch, prints a table
```
`solve` flags:
- `--desc FILE` — description file (default `<dir>/desc.txt`)
- `--max-steps N` — step budget per run (default 300)
- `--max-minutes N` — wall-clock budget per run (default 120)
- `--no-ask` — never block on `ask_user`; fail forward instead of prompting
- `--show-thinking` — print the model's reasoning as it runs
- `--secure PATH` — path to `.secure` (default: the search order above)

`bench` shares `--max-steps`, `--max-minutes`, `--show-thinking` and `--secure`; it always runs
non-interactively (as if `--no-ask`) and reads each challenge's own `<dir>/desc.txt`.
Artifacts land in `<challenge>/.revagent/`: `case.md` (the agent's notes), `transcript.jsonl`,
`out/NNN.txt` (full tool outputs), `ghidra/` (cached decompilation), `screens/NNN.png` and
`screens/NNN.diff.png` (`run_gui` captures and per-input change images), `runbook.md` (written by
`handoff_runbook`), `case.md.bak` (the pre-shrink copy of the case file, written when the context
had to be reduced twice in a row), `result.json` (latest run) and
`results.jsonl` (one line per run, never overwritten). If `<challenge>/../ANSWERS.md` has a row for the
challenge, `solve` cross-checks the flag like `bench` does and rewrites `result.json` as `wrong` on a mismatch.

## Sandbox (recommended)
Run each challenge in a disposable container with the full toolchain (Ghidra, gdb, angr/z3/unicorn,
radare2, qemu-user, libssl1.1). The agent code runs unchanged inside; artifacts land in `<challenge>/.revagent/` on the host.

```bash
bash scripts/sandbox-build.sh                                   # once; ~6.6 GB, 15–25 min
~/.revagent-venv/bin/revagent solve --sandbox path/to/challenge --no-ask
~/.revagent-venv/bin/revagent bench --sandbox chal1 chal2
~/.revagent-venv/bin/revagent solve --sandbox-dev path/to/challenge   # mounts this repo at /app: edit code, no rebuild
```
Requirements: Docker Desktop with WSL integration enabled for this distro. Credentials are passed from
`.secure` as `QWEN`/`URL`/`MODEL` env vars, passed to the docker CLI's own environment rather than as
`-e KEY=VALUE` on argv, so they never show up in the host process table (`ps`) — but they are still
visible to any local docker-group user via `docker inspect` on the running container. The container
runs as root with network access, `--cap-add SYS_PTRACE --security-opt seccomp=unconfined` (gdb must
be able to ptrace and disable ASLR, or a table that depends on the load address differs on every run);
it is removed when the run ends. Artifacts written back into
`<challenge>/.revagent/` on a native ext4 path (e.g. inside WSL) come out root-owned, since the
container runs as root. The challenge dir is mounted read-write, so a hostile binary can modify it;
never use `--sandbox-dev` with untrusted binaries (it mounts this repo). Windows PE: console programs
run under wine via `run_binary`; GUI programs via `run_gui` (Xvfb + screenshot + OCR, plus an `actions` input script: clicks, keys, typed text, with a capture and a change report (pixel count, bbox, noise-free diff PNG) per input). The image is
about 6.6 GB (wine, Xvfb, OCR and one posix-thread mingw-w64 toolchain per arch included; `gcc -m32`/`g++ -m32` work; no `git`). Editing `revagent/ghidra_scripts/*.java` no longer rebuilds the Ghidra layer: its headless verify runs as a late ~10 s step.

On networks with a TLS-inspecting proxy, pass the proxy's CA certificate with `--sandbox-ca /path/to/ca.crt`
(or set `REVAGENT_SANDBOX_CA`). It is bind-mounted read-only at run time and never stored in the image.

## How it works
Single ReAct loop, nine tools (`bash`, `decompile`, `run_binary`, `run_gui`, `notes`, `summarize`,
`ask_user`, `submit_flag`, `handoff_runbook`). The case file is the agent's external memory: when the
prompt passes 44k tokens the middle of the conversation is summarized into it and the context is
rebuilt from system prompt + task + case file + last 4 tool exchanges. Thinking stays on
(`reasoning_effort=medium`; the server accepts `low`, `medium` and `xhigh`, and `low` is a nudge, not a
cap: on a hard step it still thinks 7–12k characters). The output budget is 16384 tokens including
thinking; a step that still hits it is retried once with a hint at `low`. Tool timeouts are capped to
the time left in the run, so `--max-minutes` is a real bound. Replies are streamed: the runpod proxy
(Cloudflare) drops any request whose response has not started within ~100 s (HTTP 524), and a
non-streamed reply starts only after the whole generation, so every long-thinking step used to die
(relativity run 3 and ROVM run 3 were ended that way, 12–13 retries each). Streaming starts the reply
with the first reasoning token; verified live: a 126 s `medium` step and a 260 s `xhigh` step both
completed with zero retries. Transient failures (5xx/429/dropped stream) are retried up to 3 times,
reported on stderr and counted in `result.json` (`llm_retries`); the SDK's own silent retries are off.

Every `run_binary`/`run_gui` execution appends an observation-ledger line (`- [obs step N] ...`) to the
case file's Log; these lines are never deleted by compaction, only merged, so the run's evidence
trail survives context rebuilds. A critic reviews the transcript before each compaction and again
after 12 idle steps (no case-file progress), appending its own `- [critic step N] ...` line to the
same ledger. `submit_flag` requires an `evidence` kind — `program_accepted` (the binary showed the
success message for this input), `two_independent_readings` (the flag is displayed and was read by
two different methods that agree), or `reimplementation_matches` (a faithful re-implementation of
the check accepts it and intermediate values match) — and rejects flags that don't back up their
claimed kind. When the sandbox provably cannot execute the target (`run_binary`/`run_gui`
report `[cannot run here]` or repeated start failures set `ctx.env_blocked`), `handoff_runbook` is
the last resort: it ends the session with a numbered procedure for a human to run on a real machine.

Design: [docs/superpowers/specs/2026-09-19-revagent-design.md](docs/superpowers/specs/2026-09-19-revagent-design.md).

### Run statuses
Each run ends with one of these statuses in `result.json`: `solved` (flag accepted), `unsolved`
(step or time budget ran out, or an error), `runbook` (`handoff_runbook` was accepted because the
sandbox could not execute the target), or `wrong` — the run reported `solved` but the flag does not
match the challenge's row in `<challenge>/../ANSWERS.md`. `solve` (native or `--sandbox`) applies that
check after the run and rewrites `result.json` from `solved` to `wrong` with a `note` saying what was
expected.

`solve` (including `solve --sandbox`) turns the status into its exit code: 0 for `solved`, 1 for
`unsolved` and `wrong`, 3 for `runbook`. Exit code 2 means the run never started: a usage or
preflight error (the path is not a directory, `--sandbox-ca` without `--sandbox`, docker CLI /
daemon / image missing, `--desc` outside the challenge directory, or a `--sandbox-ca` file that does
not exist). `bench` does not map statuses to exit codes: it prints a result table and exits 0 only
when every row is `solved`, 1 otherwise. Its rows carry the same statuses, including `wrong` (the
same `ANSWERS.md` check, applied only in the table — `bench` does not rewrite `result.json`), plus
one of its own, `error`, which never appears in `result.json`: the container exited non-zero without
writing a new `result.json`, `result.json` is missing or unparsable, or the run raised an exception.

## Bench
| challenge | level | result |
|---|---|---|
| bench/mini/xor_check | plumbing test | solved (8 steps, 0.4 min) |
| quiz/multipoint (Dreamhack) | real | run1 unsolved (time limit, 62 steps); run2 with playbook v2 **solved** (30 steps, 13.4 min) |
| quiz/revlogin (Dreamhack) | real | run1 unsolved (step limit, 150 steps); run2 with playbook v2 **solved** (154 steps, 53.4 min, 5 compactions) |
| quiz/multipoint (Dreamhack) **sandbox** | real | fresh case file, `--sandbox`: **solved** (48 steps, 13.0 min, 0 compactions) |
| quiz/revlogin (Dreamhack) **sandbox** | real | fresh case file, `--sandbox`: **solved** (57+70 steps across a pod outage, 26.3 min total, 2 compactions; binary runs directly thanks to libssl1.1, no shim detour) |
| quiz/captain-hook (Dreamhack, Windows PE) | real | **unsolved by the agent** after 8 runs (~700 steps; runs 5–8 with the `actions`-capable `run_gui`). Run 8 submitted `DH{4K58900003000000}` (rejected). Reference solution by a Claude subagent: the on-screen hex stream (one char per left click, 18 432 chars) is an embedded UPX-packed PE decrypted from file offset 0x1E1F0 with a Lehmer-PRNG XOR pad; running that inner PE shows `DH{H0000KER}` (confirmed on Dreamhack). Lessons folded into the evidence-ladder spec: fix the glyph alphabet before reading, decode emitted byte streams and identify nested binaries, two independent readings before submit |
| quiz/damnida (Dreamhack, ELF PIE, custom obfuscator) | real | run1 unsolved: 238 steps, 8 compactions, killed by the host wrapper at 133 min before the 120-min limit fired (a bash tool call can take up to 15 min, so the wrapper must allow max-minutes + 15). Progress kept in the case file: self-modifying RWX region holds a tail-call VM chain (each handler transforms an accumulator, then jumps via vtable[acc>>3]); found the read(0,256) site, the Correct/Wrong dispatch and the XOR/add constants; the inversion is still open |
| quiz/captain-hook run 9 (evidence-ladder build, fresh case file) | real | **unsolved**: 191 steps, 84 min, 13 compactions; submitted `DH{8152da9f0e3b4c67}` (wrong) with evidence `reimplementation_matches` and no real re-implementation, so the two-readings rule was bypassed by self-classification. What worked: observed the program at step 2, drove it with clicks/keys by step 11, identified the hex alphabet by step 30, critic memos (8, the cap) correctly named the repeated pixel-dump and static loops. What did not: the model wrote one Fact all run (the ledger held 9 `[obs]` lines), kept re-deriving glyph values from decompiled C, and never asked what the 18 432-char stream *was*. Post-merge idea: `reimplementation_matches` should cite a matched intermediate value from a run |
| quiz/relativity (Dreamhack, ELF PIE) | real | run1 **unsolved** (time limit: 107 steps, 121.8 min, 3.36M prompt tokens, 12 output truncations). Check logic recovered by step 14 (`key[i] == (i*i + table[i]) & 0xff`, table at 0x6020), but the table is rewritten at load time by a self-modifying relocation chain: a 400-entry `.rela.tivity` section inside the `DT_RELASZ` range whose `R_X86_64_PC32` entries target the relocation table itself, so `readelf -r` shows nothing aimed at 0x6020. gdb could not disable ASLR in the sandbox and the agent's `x/xb` parser took the `0x56..:` address prefixes as data, so its model never matched. run2 (fixed build) died at 44 steps when the pod went down; run3 (fixed build): **unsolved**, 86 steps, 68 min, ended by the runpod proxy — 12 HTTP 524 retries over 7 steps, then 4 in a row at step 86 exhausted the retry budget. ASLR off now works (step 77 got a deterministic key via a watchpoint that named `ld-linux` as the writer), 59 note bullets written (run2: 0); the model still failed to match its Python check against the binary. run4 (same build, case file carried over): **solved** `DH{1d459f…3360}` in 38 steps, 20.3 min, 1.03M prompt tokens, 1 retry. Notes from step 14 (check inverted: `input[i] = (i*i+key[i]) & 0xff`, ptrace/ret-count constructors adjust `key[0]`), runtime key dumped with ASLR off by step 22, then, after three computed `key[0]` guesses failed, brute-forced the first character against the live binary at step 36 (`program_accepted`). Fixes folded in: 16k output budget, ptrace/seccomp for gdb, playbook entry for load-time-rewritten data (watchpoint → loader vs constructor) and dump parsing |
| quiz/ROVM (Dreamhack, XMAS{...}) | real | run1 unsolved (time limit): only 44 steps in 152 min because 32k truncation retries + a concurrent agent halved throughput; VM structure fully recovered (stack-based threaded VM, flag written by the 2nd syscall) — rerun pending |
| bench/mini/win_console (mingw PE, console) | plumbing test | **solved** in the sandbox (8 steps, 0.9 min; run_binary under wine) |
| bench/mini/win_gui (mingw PE, GUI) | plumbing test | **solved** in the sandbox (9 steps, 1.2 min; run_gui screenshot + OCR read the flag) |
| bench/mini/win_gui_key (mingw PE, GUI, one char per keypress) | generalization test | **solved** in the sandbox (14 steps, 2.1 min; no hint: agent saw one char, chose `actions` with clicks/keys by itself); evidence-ladder build: run 1 **wrong** flag `DH{k3y_driv3n_ui}` (read `1` from pixels, retyped it as `i` — now caught by the bench `ANSWERS.md` check and the assemble-in-code rule), run 2 solved (12 steps, 3.5 min, two readings) |
| bench/mini/win_gui_32 (mingw PE32, image has wine64 only) | runbook-path test | **solved** by static XOR decode (17 steps, 2.5 min): run_binary answered `[cannot run here]`, the gate opened and the `[env]` note was shown, but the agent recovered the flag statically, which the playbook ranks above a hand-off. The `runbook` terminal status is therefore validated only by the agent-level test and the in-container tool checks, not yet by a live run |

## Tests
```bash
~/.revagent-venv/bin/python -m pytest
```
