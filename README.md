# revagent

Autonomous reverse-engineering agent for CTF challenges (target: Dreamhack rev, level 7–8),
driven by a self-hosted Qwen3.8-27B served through vLLM.

Give it a challenge folder (binary + description) and it triages, decompiles (Ghidra headless),
reasons over the check logic, verifies a candidate answer by running the binary, and submits
a `DH{...}` flag — or reports how far it got.

Status: design phase. See [docs/superpowers/specs/2026-09-19-revagent-design.md](docs/superpowers/specs/2026-09-19-revagent-design.md).

Model serving scripts live in a separate repo: [qwen3.8-vllm-runpod](https://github.com/DAADAISMYLIFE/qwen3.8-vllm-runpod).
