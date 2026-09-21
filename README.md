# revagent

**상태:** Dreamhack의 multipoint, revlogin, relativity를 샌드박스에서 풀었습니다. captain-hook, damnida, ROVM은 아직 미해결입니다. 샌드박스, 증거 사다리, PE 단계(wine / `run_gui`)가 모두 머지되어 있습니다. 실행 기록은 아래 벤치 표에 있습니다.

CTF 리버싱 문제(목표: Dreamhack rev level 7~8)를 자율로 푸는 에이전트입니다. 모델은 직접 띄운 Qwen3.8-27B를 vLLM으로 서빙해서 씁니다.

문제 폴더(바이너리 + `desc.txt`)를 주면 트리아지 → Ghidra headless 디컴파일 → 체크 방식 분류 → 풀이(z3 / angr / gdb / 재구현) → 바이너리를 실제로 돌려 후보 검증 → `DH{...}` 플래그 제출까지 스스로 합니다. 못 풀면 어디까지 갔는지 보고합니다.

## 설치 (WSL / Linux, sudo 불필요)
```bash
python3 -m venv --without-pip --system-site-packages ~/.revagent-venv   # ensurepip 가 없을 수 있음; pip 은 시스템 것을 씀
PYVER=$(~/.revagent-venv/bin/python -c 'import sys;print(f"python{sys.version_info[0]}.{sys.version_info[1]}")')
echo "$HOME/.local/lib/$PYVER/site-packages" > ~/.revagent-venv/lib/$PYVER/site-packages/usersite.pth   # angr/z3 를 pip --user 로 깔았을 때만
~/.revagent-venv/bin/python -m pip install -e .
bash scripts/install_ghidra.sh                             # JDK 21 + Ghidra 를 ~/tools 아래에 (약 600 MB) — --host 로 돌릴 때만 필요
mkdir -p ~/.revagent && cp .secure.example ~/.revagent/.secure && $EDITOR ~/.revagent/.secure   # QWEN / URL / MODEL
bash scripts/sandbox-build.sh                              # 샌드박스 이미지 (약 6.6 GB, 15~25 분, 한 번만)
```

**`.secure` 위치:** `~/.revagent/.secure`를 권장합니다. 문제 폴더 밖이라 문제 자체의 `.secure`나 cwd 검색에 걸려 새어 나갈 일이 없습니다. `load_secure`의 탐색 순서는 다음과 같습니다. `QWEN`/`URL`/`MODEL` 환경변수 세 개가 모두 있고 `--secure`가 없으면 그것을 먼저 씁니다(샌드박스 컨테이너가 값을 받는 방식). 그다음 `$REVAGENT_SECURE` → `./.secure` → 레포 루트 → `~/.revagent/.secure` 순입니다. 키는 개별 문제 폴더에 두지 마세요.

**회사망 TLS 검사 프록시:** 프록시 CA 인증서를 `~/.revagent/sandbox-ca.crt`에 두면 자동으로 씁니다. `--sandbox-ca 경로`나 환경변수 `REVAGENT_SANDBOX_CA`도 됩니다(우선순위는 플래그 → 환경변수 → 파일). 실행 시 읽기 전용으로 마운트되고 이미지에는 남지 않습니다.

venv에 `pytest` 실행 파일이 없으므로 테스트는 `~/.revagent-venv/bin/python -m pytest`로 돌립니다.

모델 서버는 별도 레포입니다: [qwen3.8-vllm-runpod](https://github.com/DAADAISMYLIFE/qwen3.8-vllm-runpod) (vLLM, `--enable-auto-tool-choice --tool-call-parser qwen3_coder --reasoning-parser qwen3`). 같은 `.secure` 파일을 양쪽에서 씁니다.

## 실행
```bash
~/.revagent-venv/bin/revagent solve 문제폴더            # 기본: 샌드박스에서, 묻지 않고 끝까지
~/.revagent-venv/bin/revagent solve 문제폴더 --ask      # 막히면 나에게 질문하게 (터미널에서만 의미 있음)
~/.revagent-venv/bin/revagent solve 문제폴더 --dev      # 이 레포를 /app 에 마운트: 코드 고친 뒤 이미지 재빌드 없이 실행
~/.revagent-venv/bin/revagent solve 문제폴더 --host     # 도커 없이 이 머신에서 (Ghidra 호스트 설치 필요, wine 없음)
~/.revagent-venv/bin/revagent bench 문제1 문제2 ...     # 여러 개를 순서대로, 질문 없이, 표로 출력
```
실행 중 출력(stdout, stderr 모두)은 터미널에 나오면서 `문제폴더/.revagent/console.log`에도 붙습니다. 실행마다 `=== run <UTC 시각> argv: ... ===` 헤더가 한 줄 들어가므로 `2>&1 | tee`는 필요 없습니다. 예외는 `--ask`를 터미널에서 쓸 때뿐입니다(컨테이너가 터미널을 직접 잡아야 해서 로그를 끕니다).

`solve` 옵션:
| 옵션 | 뜻 | 기본값 |
|---|---|---|
| `--host` | 샌드박스 대신 이 머신에서 실행 | 샌드박스 |
| `--dev` | 샌드박스에 이 레포를 `/app`으로 마운트 (재빌드 없이 코드 반영) | 이미지 안의 코드 |
| `--ask` | `ask_user` 허용. 없으면 막혀도 스스로 가정하고 진행 | 묻지 않음 |
| `--desc FILE` | 문제 설명 파일 | `문제폴더/desc.txt` |
| `--max-steps N` | 실행당 스텝 예산 | 300 |
| `--max-minutes N` | 실행당 시간 예산(분). 도구 타임아웃도 여기에 맞춰 잘림 | 120 |
| `--show-thinking` | 모델의 생각을 실시간으로 출력 | 끔 |
| `--secure PATH` | `.secure` 경로 | 위 탐색 순서 |
| `--sandbox-ca PATH` | 샌드박스 안에서 신뢰할 CA 인증서 | env → `~/.revagent/sandbox-ca.crt` |

`bench`는 `--host`, `--dev`, `--max-steps`, `--max-minutes`, `--show-thinking`, `--secure`를 같이 쓰고, 절대 묻지 않으며, 각 문제의 `desc.txt`를 읽습니다. 옛 플래그 `--sandbox`, `--sandbox-dev`, `--no-ask`도 아직 받아 주지만 이제 기본 동작이라 쓸 필요가 없습니다.

**신뢰할 수 없는 바이너리에는 `--dev`를 쓰지 마세요.** 문제 폴더는 읽기·쓰기로 마운트되고 컨테이너는 root로 돌기 때문에, 악성 바이너리가 `--dev`로 마운트된 이 레포까지 건드릴 수 있습니다.

### 산출물 (`문제폴더/.revagent/`)
| 파일 | 내용 |
|---|---|
| `console.log` | 실행 콘솔 출력 전체 (누적) |
| `case.md` | 에이전트의 노트. Facts / Hypotheses / Todo / Log 네 섹션. 컨텍스트가 리셋돼도 살아남는 유일한 메모리 |
| `transcript.jsonl` | 모든 메시지, 도구 호출, 모델의 생각, 메타 이벤트 |
| `out/NNN.txt` | 12,000자를 넘어 잘린 도구 출력의 전체본 |
| `ghidra/` | 디컴파일 캐시 (`<바이너리>.<해시>.functions.json`) |
| `screens/NNN.png`, `NNN.diff.png` | `run_gui` 캡처와 입력별 변화 이미지 |
| `runbook.md` | `handoff_runbook`이 쓴 사람용 절차 (샌드박스가 실행 못 하는 대상일 때) |
| `case.md.bak` | 케이스 파일을 강제로 줄이기 직전의 백업 |
| `result.json` | 마지막 실행 결과 (상태, 플래그, 스텝, 토큰, `llm_retries`, 분) |
| `results.jsonl` | 실행마다 한 줄씩 누적, 덮어쓰지 않음 |

`문제폴더/../ANSWERS.md`에 그 문제의 행(`| 폴더이름 | 플래그 |`)이 있으면 `solve`도 `bench`처럼 플래그를 대조하고, 틀리면 `result.json`을 `wrong`으로 고쳐 씁니다.

### 실행 상태와 종료 코드
`result.json`의 상태는 넷 중 하나입니다. `solved`(플래그 수락), `unsolved`(스텝·시간 소진 또는 오류), `runbook`(샌드박스가 대상을 실행할 수 없어 `handoff_runbook`이 수락됨), `wrong`(`solved`로 보고했지만 `ANSWERS.md`와 불일치).

`solve`의 종료 코드: `solved` 0, `unsolved`·`wrong` 1, `runbook` 3. 2는 실행이 시작도 못 한 경우입니다(폴더가 아님, `--host`와 `--dev`/`--sandbox-ca` 동시 사용, docker CLI·데몬·이미지 없음, `--desc`가 문제 폴더 밖, CA 파일 없음, `.secure` 없음). `bench`는 표를 찍고 모든 행이 `solved`일 때만 0, 아니면 1입니다. 표에는 `wrong`(같은 대조, 표에서만 적용하고 `result.json`은 안 고침)과 `error`(컨테이너가 비정상 종료했는데 새 `result.json`이 없음, `result.json`이 없거나 깨짐, 예외)가 추가로 나올 수 있습니다.

## 샌드박스 (기본)
`--host`가 없으면 모든 `solve`/`bench`는 문제마다 일회용 컨테이너에서 돕니다. 이미지에는 전체 툴체인이 들어 있습니다. Ghidra + JDK 21, gdb, gcc/g++(`-m32` 포함), binutils, radare2, qemu-user(전 아키텍처), libssl1.1, angr/z3/unicorn/capstone/pwntools/pefile/pycryptodome/pillow, wine64 + Xvfb + xdotool + ImageMagick + tesseract(GUI PE용), mingw-w64(i686, x86_64 posix 스레드 모델 각 하나). 에이전트 코드는 그대로 안에서 돌고 산출물은 호스트의 `문제폴더/.revagent/`에 남습니다.

- 요구사항: Docker Desktop에서 이 WSL 배포판의 통합을 켜 둘 것.
- 자격증명은 `.secure`에서 읽어 `QWEN`/`URL`/`MODEL` 환경변수로 docker CLI 자체 환경에 넘깁니다. argv에 `-e KEY=VALUE`로 넣지 않으므로 `ps`에는 안 보이지만, 같은 머신의 docker 그룹 사용자는 `docker inspect`로 볼 수 있습니다.
- 컨테이너는 root, 네트워크 허용, `--cap-add SYS_PTRACE --security-opt seccomp=unconfined`로 돕니다. gdb가 ptrace와 ASLR 해제를 할 수 있어야 하기 때문입니다(로드 주소에 따라 값이 바뀌는 테이블은 이게 없으면 실행마다 달라집니다). 실행이 끝나면 컨테이너는 삭제됩니다.
- WSL 안의 ext4 경로에 문제 폴더가 있으면 산출물이 root 소유로 나옵니다.
- Windows PE: 콘솔 프로그램은 `run_binary`가 wine으로 실행하고, GUI 프로그램은 `run_gui`가 Xvfb 위에서 띄워 스크린샷 + OCR을 하며 `actions`(클릭, 키, 문자 입력)로 조작하고 입력마다 캡처와 변화 보고(픽셀 수, bbox, 잡음 제거 diff PNG)를 냅니다. 32비트 PE는 실행 못 합니다(wine64만 있음).
- 이미지는 약 6.6 GB입니다. `revagent/ghidra_scripts/*.java`를 고쳐도 Ghidra 레이어는 재빌드되지 않고 마지막의 약 10초짜리 검증 단계만 다시 돕니다. 에이전트 Python 코드를 고쳤을 때는 `--dev`로 바로 돌리거나 `bash scripts/sandbox-build.sh`로 마지막 레이어만 다시 빌드하면 됩니다(몇 분).

## 동작 원리
ReAct 루프 하나에 도구 아홉 개(`bash`, `decompile`, `run_binary`, `run_gui`, `notes`, `summarize`, `ask_user`, `submit_flag`, `handoff_runbook`)입니다. 케이스 파일이 외부 메모리입니다. 프롬프트가 44k 토큰을 넘으면 대화 중간을 요약해 케이스 파일에 넣고, 컨텍스트를 시스템 프롬프트 + 작업 + 케이스 파일 + 최근 도구 교환 4개로 다시 만듭니다. thinking은 켜 둡니다(`reasoning_effort=medium`. 서버는 `low`, `medium`, `xhigh`를 받고, `low`는 상한이 아니라 경향이라 어려운 스텝에선 여전히 7~12k자를 생각합니다). 출력 예산은 thinking 포함 16,384 토큰이고, 그래도 넘치면 힌트를 붙여 `low`로 한 번 재시도합니다. 도구 타임아웃은 실행에 남은 시간으로 잘리므로 `--max-minutes`가 실제 상한입니다.

응답은 스트리밍으로 받습니다. RunPod 프록시(Cloudflare)는 응답이 100초 안에 시작되지 않으면 끊고 HTTP 524를 돌려주는데, 비스트리밍 응답은 생성이 다 끝나야 시작되므로 오래 생각하는 스텝이 전부 죽었습니다(relativity 3회차와 ROVM 3회차가 그렇게 끝났고 각각 12~13번 재시도). 스트리밍은 첫 reasoning 토큰부터 흘려보내므로 실측으로 126초짜리 `medium` 스텝과 260초짜리 `xhigh` 스텝이 재시도 0으로 완료됐습니다. 일시 장애(5xx/429/스트림 중단)는 최대 3번 재시도하며 stderr에 찍히고 `result.json`의 `llm_retries`에 합산됩니다. SDK 자체의 조용한 재시도는 꺼 두었습니다.

`run_binary`/`run_gui`가 실행될 때마다 관찰 원장 한 줄(`- [obs step N] ...`)이 케이스 파일 Log에 붙습니다. 이 줄은 압축 때 삭제되지 않고 병합만 되므로 증거의 흔적이 컨텍스트 리셋을 넘어 살아남습니다. 비평가가 압축 직전과 12스텝 무진전(케이스 파일에 변화 없음) 시점에 transcript를 검토해 `- [critic step N] ...` 줄을 같은 원장에 남깁니다. `submit_flag`는 `evidence` 종류를 요구합니다. `program_accepted`(바이너리가 이 입력에 성공 메시지를 냈음), `two_independent_readings`(화면에 표시된 플래그를 서로 다른 두 방법으로 읽어 일치), `reimplementation_matches`(체크의 충실한 재구현이 받아들이고 중간값이 일치). 주장한 종류를 뒷받침하지 못하는 제출은 거부됩니다. 샌드박스가 대상을 실행할 수 없는 것이 확실할 때(`run_binary`/`run_gui`가 `[cannot run here]`를 내거나 시작 실패가 반복돼 `ctx.env_blocked`가 켜짐) `handoff_runbook`이 최후 수단입니다. 사람이 실제 머신에서 따라 할 번호 매긴 절차를 남기고 세션을 끝냅니다.

설계 문서: [docs/superpowers/specs/2026-09-19-revagent-design.md](docs/superpowers/specs/2026-09-19-revagent-design.md) (변경 이력은 각 스펙 끝의 수정 이력 절 참고).

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
| bench/mini/win_console (mingw PE, console) | plumbing test | **solved** in the sandbox (8 steps, 0.9 min; run_binary under wine) |
| bench/mini/win_gui (mingw PE, GUI) | plumbing test | **solved** in the sandbox (9 steps, 1.2 min; run_gui screenshot + OCR read the flag) |
| bench/mini/win_gui_key (mingw PE, GUI, one char per keypress) | generalization test | **solved** in the sandbox (14 steps, 2.1 min; no hint: agent saw one char, chose `actions` with clicks/keys by itself); evidence-ladder build: run 1 **wrong** flag `DH{k3y_driv3n_ui}` (read `1` from pixels, retyped it as `i` — now caught by the bench `ANSWERS.md` check and the assemble-in-code rule), run 2 solved (12 steps, 3.5 min, two readings) |
| bench/mini/win_gui_32 (mingw PE32, image has wine64 only) | runbook-path test | **solved** by static XOR decode (17 steps, 2.5 min): run_binary answered `[cannot run here]`, the gate opened and the `[env]` note was shown, but the agent recovered the flag statically, which the playbook ranks above a hand-off. The `runbook` terminal status is therefore validated only by the agent-level test and the in-container tool checks, not yet by a live run |

## 테스트
```bash
~/.revagent-venv/bin/python -m pytest
```
