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
echo "$HOME/.local/lib/python3.14/site-packages" > ~/.revagent-venv/lib/python3.14/site-packages/usersite.pth   # only if angr/z3 are installed with pip --user
~/.revagent-venv/bin/python -m pip install -e .
bash scripts/install_ghidra.sh                             # JDK 21 + Ghidra under ~/tools (~600 MB)
cp .secure.example .secure && $EDITOR .secure              # QWEN / URL / MODEL
```
There is no `pytest` shim in the venv; run tests with `~/.revagent-venv/bin/python -m pytest`.

The model server is a separate repo: [qwen3.8-vllm-runpod](https://github.com/DAADAISMYLIFE/qwen3.8-vllm-runpod)
(vLLM with `--enable-auto-tool-choice --tool-call-parser qwen3_coder --reasoning-parser qwen3`).

## Use
```bash
~/.revagent-venv/bin/revagent solve path/to/challenge            # asks you only when blocked
~/.revagent-venv/bin/revagent solve path/to/challenge --no-ask   # fully unattended
~/.revagent-venv/bin/revagent bench chal1 chal2 ...              # batch, prints a table
```
Artifacts land in `<challenge>/.revagent/`: `case.md` (the agent's notes), `transcript.jsonl`,
`out/NNN.txt` (full tool outputs), `ghidra/` (cached decompilation), `result.json`.

## How it works
Single ReAct loop, seven tools (`bash`, `decompile`, `run_binary`, `notes`, `summarize`,
`ask_user`, `submit_flag`). The case file is the agent's external memory: when the prompt passes
44k tokens the middle of the conversation is summarized into it and the context is rebuilt from
system prompt + task + case file + last 4 tool exchanges. Thinking stays on (`reasoning_effort=medium`).

Design: [docs/superpowers/specs/2026-09-19-revagent-design.md](docs/superpowers/specs/2026-09-19-revagent-design.md).

## Bench
| challenge | level | result |
|---|---|---|
| bench/mini/xor_check | plumbing test | solved (8 steps, 0.4 min) |

## Tests
```bash
~/.revagent-venv/bin/python -m pytest
```
