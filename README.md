# revagent

Dreamhack 리버싱 문제를 혼자 푸는 에이전트. 모델은 직접 띄운 Qwen3.8-27B(vLLM)를 쓴다.

문제 폴더(바이너리 + `desc.txt`)를 주면 트리아지 → Ghidra 디컴파일 → 체크 분류 → 풀이(z3 / angr / gdb / 재구현) → 바이너리로 검증 → `DH{...}` 제출까지 알아서 한다. 못 풀면 어디까지 갔는지 남긴다.

**현황:** multipoint, revlogin, relativity 풀었음. captain-hook, damnida, ROVM, basic 미해결. 기록은 아래 벤치 표.

## 설치 (WSL, sudo 없이)
```bash
python3 -m venv --without-pip --system-site-packages ~/.revagent-venv
~/.revagent-venv/bin/python -m pip install -e .
mkdir -p ~/.revagent && cp .secure.example ~/.revagent/.secure && $EDITOR ~/.revagent/.secure   # QWEN / URL / MODEL
bash scripts/sandbox-build.sh          # 샌드박스 이미지. 약 6.6 GB, 15~25분, 한 번만
bash scripts/install_ghidra.sh         # --host 로 돌릴 때만 필요 (JDK 21 + Ghidra, ~/tools)
```
- `.secure`는 `~/.revagent/.secure`에 둔다. 문제 폴더에 두면 새어 나갈 수 있다. 탐색 순서: 환경변수 `QWEN`/`URL`/`MODEL` 셋 다 있으면 그것 → `$REVAGENT_SECURE` → `./.secure` → 레포 루트 → `~/.revagent/.secure`.
- 회사망 TLS 프록시면 CA 인증서를 `~/.revagent/sandbox-ca.crt`에 두면 된다. `--sandbox-ca 경로`나 `REVAGENT_SANDBOX_CA`도 됨.
- 모델 서버는 [qwen3.8-vllm-runpod](https://github.com/DAADAISMYLIFE/qwen3.8-vllm-runpod). `.secure`는 같은 파일을 쓴다.
- 테스트: `~/.revagent-venv/bin/python -m pytest` (venv에 pytest 실행파일 없음).

## 실행
```bash
~/.revagent-venv/bin/revagent solve 문제폴더                 # 샌드박스에서, 안 묻고 끝까지
~/.revagent-venv/bin/revagent solve 문제폴더 --show-thinking # 모델 생각도 같이 출력
~/.revagent-venv/bin/revagent solve 문제폴더 --dev           # 이 레포를 마운트. 코드 고친 뒤 재빌드 없이
~/.revagent-venv/bin/revagent solve 문제폴더 --ask           # 막히면 나한테 물어보게
~/.revagent-venv/bin/revagent solve 문제폴더 --host          # 도커 없이 이 머신에서 (wine 없음)
~/.revagent-venv/bin/revagent bench 문제1 문제2 ...          # 여러 개, 안 묻고, 표로
```
출력은 터미널에 나오면서 `문제폴더/.revagent/console.log`에도 쌓인다. `| tee` 필요 없음. (`--ask`를 터미널에서 쓸 때만 로그 꺼짐.)

| 옵션 | 뜻 | 기본 |
|---|---|---|
| `--host` | 샌드박스 대신 이 머신에서 | 샌드박스 |
| `--dev` | 레포를 `/app`에 마운트 | 이미지 안 코드 |
| `--ask` | `ask_user` 허용 | 안 물음 |
| `--desc FILE` | 설명 파일 | `문제폴더/desc.txt` |
| `--max-steps N` | 스텝 예산 | 300 |
| `--max-minutes N` | 시간 예산(분). 도구 타임아웃도 여기 맞춰 잘림 | 120 |
| `--show-thinking` | 생각 출력 | 끔 |
| `--secure PATH` | `.secure` 경로 | 위 탐색 순서 |
| `--sandbox-ca PATH` | 샌드박스용 CA | env → `~/.revagent/sandbox-ca.crt` |

옛 플래그 `--sandbox`, `--sandbox-dev`, `--no-ask`도 먹지만 이제 기본 동작이라 쓸 일 없다.

`--dev`는 레포를 컨테이너에 쓰기 가능으로 마운트한다. 믿을 수 없는 바이너리엔 쓰지 마라.

루프가 막는 것 두 가지. 같은 스크립트를 4번째 고치면 그 호출은 실행 안 되고 `[blocked by G3]`가 돌아온다(프로그램을 돌리거나, `solve_check`에 넘기거나, 노트에 실패를 적으면 풀림). 8천 자 넘게 생각하는 스텝이 5번째 나오면 `[gate]` 경고 한 번 주고 남은 실행은 생각 예산을 낮춘다. 둘 다 과거 transcript 전부에 리플레이해서 푼 실행에선 한 번도 안 울리는 값으로 잡았다: `python scripts/replay_detectors.py 문제폴더/.revagent/transcript.jsonl`.

### 산출물 (`문제폴더/.revagent/`)
| 파일 | 내용 |
|---|---|
| `console.log` | 콘솔 출력 전체, 실행마다 헤더 붙여 누적 |
| `case.md` | 에이전트 노트. Facts / Hypotheses / Todo / Log. 컨텍스트가 리셋돼도 남는 유일한 메모리 |
| `transcript.jsonl` | 메시지, 도구 호출, 생각, 메타 이벤트 전부 |
| `out/NNN.txt` | 12,000자 넘어 잘린 도구 출력 원본 |
| `ghidra/` | 디컴파일 캐시 |
| `screens/` | `run_gui` 캡처와 입력별 diff PNG |
| `runbook.md` | 샌드박스가 실행 못 하는 대상일 때 사람용 절차 |
| `case.md.bak` | 케이스 파일 강제 축소 직전 백업 |
| `result.json` | 마지막 실행 결과 (+ `signals`: 게이트 발동, 긴 생각 횟수, 첫 Facts 스텝) |
| `results.jsonl` | 실행마다 한 줄 누적 |

`문제폴더/../ANSWERS.md`에 `| 폴더이름 | 플래그 |` 행이 있으면 대조해서 틀리면 `result.json`을 `wrong`으로 고친다.

### 상태와 종료 코드
- `result.json` 상태: `solved` / `unsolved`(예산 소진, 오류) / `runbook`(실행 못 해서 절차만 남김) / `wrong`(ANSWERS.md와 불일치).
- `solve` 종료 코드: `solved` 0, `unsolved`·`wrong` 1, `runbook` 3, 시작도 못 함 2(폴더 아님, `--host`+`--dev`, 도커·이미지 없음, `.secure` 없음 등).
- `bench`: 표 찍고 전부 `solved`면 0, 아니면 1. 표엔 `error`(컨테이너 비정상 종료, result.json 없음/깨짐)도 나온다.

## 샌드박스 (기본)
`--host` 없으면 문제마다 일회용 컨테이너에서 돈다. 안에 Ghidra, gdb, gcc(`-m32` 포함), radare2, qemu-user 전 아키텍처, libssl1.1, angr/z3/unicorn/capstone/pwntools/pefile/pycryptodome/pillow, wine64 + Xvfb + xdotool + ImageMagick + tesseract, mingw-w64(i686/x86_64 posix) 다 들어 있다. 산출물은 호스트의 `문제폴더/.revagent/`에 남는다.

- Docker Desktop에서 이 WSL 배포판 통합 켜 둘 것.
- 자격증명은 docker CLI 환경변수로 넘긴다. `ps`엔 안 보이지만 `docker inspect`엔 보인다.
- 컨테이너는 root, 네트워크 허용, `--cap-add SYS_PTRACE --security-opt seccomp=unconfined`(gdb가 ASLR 끄려면 필요). 끝나면 삭제.
- Windows PE: 콘솔은 `run_binary`가 wine으로, GUI는 `run_gui`가 Xvfb에서 띄워 스크린샷 + OCR, `actions`로 클릭·키 입력. 32비트 PE는 못 돌림(wine64만).
- 에이전트 코드 고치면 `--dev`로 바로 돌리거나 `bash scripts/sandbox-build.sh`로 마지막 레이어만 재빌드(몇 분). Ghidra 스크립트를 고쳐도 Ghidra 레이어는 안 다시 빌드한다.

## 동작 원리
- ReAct 루프 하나, 도구 열 개: `bash`, `decompile`, `run_binary`, `run_gui`, `solve_check`, `notes`, `summarize`, `ask_user`, `submit_flag`, `handoff_runbook`.
- `solve_check`: 모델이 forward 변환만 파이썬으로 쓰면 z3가 입력을 찾아 준다. 바이트 단위 체크용.
- 메모리는 `case.md`. 프롬프트가 44k 토큰 넘으면 대화 중간을 요약해 여기 넣고, 시스템 프롬프트 + 작업 + case.md + 최근 도구 교환 4개로 컨텍스트를 다시 만든다.
- thinking 켜 둠(`medium`). 출력 예산 16k 토큰, 넘치면 힌트 붙여 `low`로 한 번 재시도.
- 응답은 스트리밍. RunPod 프록시가 100초 안에 응답 안 시작하면 524로 끊기 때문. 일시 장애는 3번 재시도하고 `llm_retries`에 센다.
- `run_binary`/`run_gui` 결과는 `[obs step N]` 줄로 케이스 파일에 자동 기록되고 압축에도 안 지워진다.
- 비평가: 압축 직전과 12스텝 무진전 때 transcript 보고 `[critic step N]` 메모를 남긴다. 조언일 뿐 강제는 아님.
- `submit_flag`는 근거 종류를 요구한다. `program_accepted`(바이너리가 성공 출력), `two_independent_readings`(화면의 플래그를 두 방법으로 읽어 일치), `reimplementation_matches`(재구현이 통과하고 중간값 일치).
- 샌드박스가 대상을 못 돌리는 게 확실할 때만 `handoff_runbook`으로 사람용 절차를 남기고 끝낸다.

설계 문서: [docs/superpowers/specs/](docs/superpowers/specs/) (각 스펙 끝에 수정 이력 있음).

## 벤치 (실행 기록, 원문 유지)
| 문제 | 구분 | 결과 |
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
| quiz/basic (Dreamhack Reversing Basic #9, PE32+ console) | real | run1 **unsolved** (15 min, 32 steps): decompiled the check by step 5, then 11 steps fighting pefile offsets and 16 steps of hand-derived inversions ("AMBIG"/TypeError), 0 notes, 1 run_binary. Solved by hand in one inversion loop: `DH{Reverse__your__brain_;)}` (in quiz/ANSWERS.md). run2 under the gates (fresh case file, `--max-minutes 15`): **unsolved**, 32 steps, signals gate_blocks 0 / max_script_streak 3 / long_reasoning_steps 4 — both gates one short of their thresholds; the model wrote 10 z3 scripts of its own (all unsat: its forward model was wrong) and never called `solve_check`. No false positive; no threshold catches this run without a false positive on multipoint (spec §8) |
| bench/mini/win_console (mingw PE, console) | plumbing test | **solved** in the sandbox (8 steps, 0.9 min; run_binary under wine) |
| bench/mini/win_gui (mingw PE, GUI) | plumbing test | **solved** in the sandbox (9 steps, 1.2 min; run_gui screenshot + OCR read the flag) |
| bench/mini/win_gui_key (mingw PE, GUI, one char per keypress) | generalization test | **solved** in the sandbox (14 steps, 2.1 min; no hint: agent saw one char, chose `actions` with clicks/keys by itself); evidence-ladder build: run 1 **wrong** flag `DH{k3y_driv3n_ui}` (read `1` from pixels, retyped it as `i` — now caught by the bench `ANSWERS.md` check and the assemble-in-code rule), run 2 solved (12 steps, 3.5 min, two readings) |
| bench/mini/win_gui_32 (mingw PE32, image has wine64 only) | runbook-path test | **solved** by static XOR decode (17 steps, 2.5 min): run_binary answered `[cannot run here]`, the gate opened and the `[env]` note was shown, but the agent recovered the flag statically, which the playbook ranks above a hand-off. The `runbook` terminal status is therefore validated only by the agent-level test and the in-container tool checks, not yet by a live run |

## 테스트
```bash
~/.revagent-venv/bin/python -m pytest
```
