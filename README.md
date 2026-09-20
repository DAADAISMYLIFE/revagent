# revagent

Status: loop works end-to-end on the plumbing test; real Dreamhack level 7–8 runs are the next step and results will be added to the bench table.

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
(`load_secure` checks `$REVAGENT_SECURE`, then `./.secure`, then the repo root, then `~/.revagent/.secure`)
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
`out/NNN.txt` (full tool outputs), `ghidra/` (cached decompilation), `result.json`.

## Sandbox (recommended)
Run each challenge in a disposable container with the full toolchain (Ghidra, gdb, angr/z3/unicorn,
radare2, qemu-user, libssl1.1). The agent code runs unchanged inside; artifacts land in `<challenge>/.revagent/` on the host.

```bash
bash scripts/sandbox-build.sh                                   # once; ~8 GB, 10–20 min
~/.revagent-venv/bin/revagent solve --sandbox path/to/challenge --no-ask
~/.revagent-venv/bin/revagent bench --sandbox chal1 chal2
~/.revagent-venv/bin/revagent solve --sandbox-dev path/to/challenge   # mounts this repo at /app: edit code, no rebuild
```
Requirements: Docker Desktop with WSL integration enabled for this distro. Credentials are passed from
`.secure` as `QWEN`/`URL`/`MODEL` env vars, passed to the docker CLI's own environment rather than as
`-e KEY=VALUE` on argv, so they never show up in the host process table (`ps`) — but they are still
visible to any local docker-group user via `docker inspect` on the running container. The container
runs as root with network access; it is removed when the run ends. Artifacts written back into
`<challenge>/.revagent/` on a native ext4 path (e.g. inside WSL) come out root-owned, since the
container runs as root. The challenge dir is mounted read-write, so a hostile binary can modify it;
never use `--sandbox-dev` with untrusted binaries (it mounts this repo). Windows PE: console programs
run under wine via `run_binary`; GUI programs via `run_gui` (Xvfb + screenshot + OCR, plus an `actions` input script: clicks, keys, typed text, with a capture and a change report (pixel count, bbox, noise-free diff PNG) per input). The image is
about 8 GB (wine, Xvfb, OCR and mingw included).

On networks with a TLS-inspecting proxy, pass the proxy's CA certificate with `--sandbox-ca /path/to/ca.crt`
(or set `REVAGENT_SANDBOX_CA`). It is bind-mounted read-only at run time and never stored in the image.

## How it works
Single ReAct loop, eight tools (`bash`, `decompile`, `run_binary`, `run_gui`, `notes`, `summarize`,
`ask_user`, `submit_flag`). The case file is the agent's external memory: when the prompt passes
44k tokens the middle of the conversation is summarized into it and the context is rebuilt from
system prompt + task + case file + last 4 tool exchanges. Thinking stays on (`reasoning_effort=medium`).

Design: [docs/superpowers/specs/2026-09-19-revagent-design.md](docs/superpowers/specs/2026-09-19-revagent-design.md).

## Bench
| challenge | level | result |
|---|---|---|
| bench/mini/xor_check | plumbing test | solved (8 steps, 0.4 min) |
| quiz/multipoint (Dreamhack) | real | run1 unsolved (time limit, 62 steps); run2 with playbook v2 **solved** (30 steps, 13.4 min) |
| quiz/revlogin (Dreamhack) | real | run1 unsolved (step limit, 150 steps); run2 with playbook v2 **solved** (154 steps, 53.4 min, 5 compactions) |
| quiz/multipoint (Dreamhack) **sandbox** | real | fresh case file, `--sandbox`: **solved** (48 steps, 13.0 min, 0 compactions) |
| quiz/revlogin (Dreamhack) **sandbox** | real | fresh case file, `--sandbox`: **solved** (57+70 steps across a pod outage, 26.3 min total, 2 compactions; binary runs directly thanks to libssl1.1, no shim detour) |
| quiz/captain-hook (Dreamhack, Windows PE) | real | unsolved after 4 static runs (host ×2, sandbox ×2, ~500 steps); **solved** on sandbox run 8 (89 steps, 59.6 min, 2 compactions) once `run_gui` had an input script: the agent found the window advances per paint, wrote a mingw helper that posts WM_PAINT 16 times, logged GdipDrawLineI coordinates with its own proxy gdiplus.dll, rasterised the 16 glyphs and read `DH{4K58900003000000}` (confirmed by a 16-click screenshot probe; runs 5–7 were stopped to fix run_gui defects they exposed: no right-click, silent xdotool failures, stale wine windows, unreported blank captures) |
| quiz/ROVM (Dreamhack, XMAS{...}) | real | run1 unsolved (time limit): only 44 steps in 152 min because 32k truncation retries + a concurrent agent halved throughput; VM structure fully recovered (stack-based threaded VM, flag written by the 2nd syscall) — rerun pending |
| bench/mini/win_console (mingw PE, console) | plumbing test | **solved** in the sandbox (8 steps, 0.9 min; run_binary under wine) |
| bench/mini/win_gui (mingw PE, GUI) | plumbing test | **solved** in the sandbox (9 steps, 1.2 min; run_gui screenshot + OCR read the flag) |
| bench/mini/win_gui_key (mingw PE, GUI, one char per keypress) | generalization test | **solved** in the sandbox (14 steps, 2.1 min; no hint: agent saw one char, chose `actions` with clicks/keys by itself) |

## Tests
```bash
~/.revagent-venv/bin/python -m pytest
```
