# revagent 설계 스펙

- 날짜: 2026-09-19
- 상태: 승인됨 (2026-09-19)
- 대상 독자: 이 프로젝트를 구현할 사람(또는 에이전트). 구현 계획은 이 문서를 근거로 별도 작성한다.

## 1. 목표

로컬(WSL)에서 도는 Python 에이전트가 RunPod의 Qwen3.8-27B(vLLM, OpenAI 호환 API)를 두뇌로 삼아
**드림핵(Dreamhack) 리버싱 레벨 7~8 문제를 자율적으로 푼다.**

성공 기준:
- 입력은 문제 파일과 문제 설명 텍스트뿐이다. 정답을 모르는 미해결 문제가 대상이다.
- 출력은 `DH{...}` 포맷의 플래그이거나, 상한 도달 시 "어디까지 분석했고 왜 막혔는지" 보고서다.
- 답을 제출하기 전에 반드시 자체 검증(바이너리 실행 또는 재현 모델)을 거친다.

비목표:
- 모델 학습(파인튜닝, RL)은 하지 않는다.
- 웹/pwn/crypto 카테고리는 다루지 않는다. 리버싱만.
- 샌드박스 격리는 하지 않는다. 문제 바이너리는 WSL에서 그대로 실행한다(사용자가 수용한 위험).

## 2. 결정 사항 (이미 합의됨)

| 항목 | 결정 | 이유 |
|---|---|---|
| 에이전트 형태 | 자체 Python 루프 (ReAct + tool calling) | 프롬프트·툴·워크플로우 전부 통제 |
| 실행 환경 | 로컬 WSL, `~/.ctf-venv` 재사용 | objdump/gdb/angr/capstone/pwntools/unicorn 이미 있음 |
| 디컴파일러 | Ghidra headless (`~/tools/`, sudo 불필요) | 레벨 7~8은 디컴파일 없이는 27B가 못 버팀 |
| 자율성 | 완전 자율, 막힐 때만 `ask_user` | 사용자는 파일과 설명만 던짐 |
| thinking | 유지, 매 요청에 `reasoning_effort=medium` 전달 (서버 기본값 xhigh는 안 건드림) | 끄지 않는다. 사용자 결정 |
| 컨텍스트 | 64k. 44k 초과 시 자동 컴팩션 | 서버 `--max-model-len 65536` |
| 저장소 | `qwen3.8-vllm-runpod`와 별도 public 저장소 `revagent` | 각각 독립 관리 |
| 아키텍처 | 단일 루프 + 케이스 파일 + 컴팩션 + `summarize` 안전밸브 | 고정 파이프라인은 레벨 7~8의 되돌아가기를 못 따라감 |

## 3. 구조

```
revagent/
├── revagent/
│   ├── __main__.py        # CLI: revagent solve <dir> [--desc FILE] [--max-steps N] [--max-minutes M]
│   ├── agent.py           # 루프 본체
│   ├── llm.py             # vLLM 클라이언트 (.secure 로드, 재시도, usage 추적)
│   ├── context.py         # 컴팩션
│   ├── ghidra.py          # headless 분석 + 함수 JSON 캐시 + 조회
│   ├── casefile.py        # case.md 읽기/쓰기, 섹션 강제
│   ├── truncate.py        # 툴 출력 절단 + 원본 저장
│   ├── ghidra_scripts/
│   │   └── DumpFunctions.java  # headless 후처리: 전 함수 디컴파일 → functions.json
│   └── tools/
│       ├── __init__.py    # 레지스트리: 폴더 안 모듈을 모아 스키마 목록 생성
│       ├── bash.py
│       ├── decompile.py
│       ├── run_binary.py
│       ├── notes.py
│       ├── summarize.py
│       ├── ask_user.py
│       └── submit_flag.py
├── prompts/
│   └── system.md          # 리버싱 플레이북 (아래 6절)
├── bench/
│   ├── run.py             # 여러 문제 폴더 일괄 실행, 결과 표
│   └── mini/xor_check/    # 배관 테스트용 자작 crackme (소스 + 빌드 스크립트 + 정답)
├── tests/                 # pytest
├── scripts/
│   └── install_ghidra.sh  # Ghidra 11.x + JDK 21 을 ~/tools 에 설치, /bin/ls 로 검증
├── docs/superpowers/specs/
├── .secure.example        # QWEN/URL/MODEL 형식 안내 (.secure 자체는 git-ignore)
├── .gitignore
└── README.md
```

문제 폴더 산출물:
```
<문제폴더>/.revagent/
├── case.md            # 케이스 파일 (외부 메모리)
├── transcript.jsonl   # 전체 메시지 로그 (컴팩션 전 원본 포함)
├── out/NNN.txt        # 절단된 툴 출력의 원본
├── ghidra/            # Ghidra 프로젝트 + functions.json
└── result.json        # 최종 결과: flag | unsolved, 스텝 수, 토큰 사용량, 소요 시간
```

## 4. 컴포넌트 상세

### 4.1 llm.py
- `.secure`(`REVAGENT_SECURE` 환경변수 → 현재 작업 디렉터리 → 저장소 루트 → `~/.revagent/.secure` 순으로 탐색)에서 `QWEN`, `URL`, `MODEL`을 읽는다. URL 끝 슬래시는 제거한다.
- `openai` 클라이언트로 `chat.completions.create(messages, tools, tool_choice="auto", max_tokens=8192, temperature=0.6, reasoning_effort="medium")`.
- 응답에서 `reasoning_content`는 transcript에만 남기고 다음 턴 메시지에는 넣지 않는다(템플릿이 이전 턴 thinking을 버리므로 토큰 낭비 방지).
- 재시도: 연결 오류/5xx는 지수 백오프 3회. 400 + "maximum context length" 문구는 `ContextOverflow` 예외로 올려 agent가 강제 컴팩션하게 한다.
- 매 응답의 `usage.prompt_tokens`를 `last_prompt_tokens`로 보관한다. 컴팩션 판단의 유일한 근거다.
- 라이브러리 `urllib`는 쓰지 않는다(RunPod 프록시가 기본 UA를 403 처리).

### 4.2 tools/ 와 레지스트리
- 각 툴 모듈은 `SCHEMA`(OpenAI function 스키마 dict)와 `run(ctx, **args) -> str`을 노출한다.
- `ctx`는 문제 폴더, `.revagent` 경로, casefile, llm 클라이언트, 출력 카운터를 담은 객체.
- 레지스트리는 폴더 안 모듈을 import해서 `[SCHEMA...]`와 `{name: run}`을 만든다. 툴 추가는 파일 추가로 끝난다.
- 모든 툴의 반환값은 `truncate.py`를 거친다. 12,000자 초과 시 앞 12,000자만 남기고 원본을 `out/NNN.txt`에 저장한 뒤 `"[truncated: N chars total. full output: .revagent/out/NNN.txt — use bash: sed -n 'A,Bp' or grep]"` 를 붙인다.

툴 명세:

| 툴 | 인자 | 동작 |
|---|---|---|
| `bash` | `cmd: str`, `timeout: int = 120` | cwd=문제 폴더, `bash -c`, stdout+stderr 합침, 종료 코드 첫 줄에 표기. 타임아웃 시 kill 후 `[timeout after Ns]`. |
| `decompile` | `action: "list"\|"get"\|"xrefs"`, `target: str = ""` | `list`: 함수 목록(이름, 주소, 크기, 문자열 참조 수, 호출 수)을 크기 내림차순으로. `get`: 이름 또는 `0x` 주소로 C 코드. `xrefs`: 해당 함수의 callers/callees. 첫 호출 시 `ghidra.py`가 분석을 돌린다. 분석 실패 시 사유를 반환하고 objdump 폴백을 권한다. |
| `run_binary` | `path: str`, `args: list[str] = []`, `stdin: str = ""`, `timeout: int = 10` | 실행 후 exit code, stdout, stderr 반환. `file`로 PE/비-x86-64 ELF를 감지하면 실행하지 않고 "이 환경에서 실행 불가, 정적/에뮬레이션으로" 반환. |
| `notes` | `action: "read"\|"add"`, `section: "facts"\|"hypotheses"\|"todo"\|"log" = "facts"`, `text: str = ""` | case.md 조작. `add`는 해당 섹션 끝에 불릿 추가. |
| `summarize` | `file: str`, `question: str` | 파일(최대 40k자, 초과 시 앞부분)을 별도 Qwen 호출(툴 없음, thinking medium)에 넘겨 `question`에 답만 받는다. 본 대화에는 답만 들어간다. |
| `ask_user` | `question: str` | 터미널에 굵게 출력, stdin 한 줄 대기. 비대화형(`--no-ask`)이면 "user unavailable" 반환. |
| `submit_flag` | `flag: str`, `how_verified: str` | `^DH\{.+\}$` 검사. 불일치면 에러 반환(종료 안 함). 일치하면 result.json 기록 후 루프 종료. |

### 4.3 ghidra.py
- 설치 경로는 `~/tools/ghidra_*/support/analyzeHeadless`를 glob으로 찾고, `JAVA_HOME=~/tools/jdk-21*`를 잡는다. 없으면 `decompile` 툴이 설치 안내 메시지를 반환한다.
- 분석: `analyzeHeadless <proj_dir> proj -import <bin> -postScript DumpFunctions.java -scriptPath <revagent/ghidra_scripts>`. 후처리 스크립트는 모든 함수에 대해 `{name, entry, size, decompiled_c, callers, callees, string_refs}`를 `functions.json`으로 덤프한다.
- 타임아웃 20분. 바이너리 해시별로 캐시해 재실행을 피한다.
- 조회 함수: `list_functions(sort="size")`, `get_function(name_or_addr)`, `xrefs(name_or_addr)`.

### 4.4 casefile.py
case.md 고정 구조:
```
# Case: <문제 이름>
## Facts        확인된 사실 (주소, 상수, 함수 역할, 체크 방식)
## Hypotheses   검증 안 된 가설
## Todo         다음 할 일
## Log          컴팩션 시 자동 추가되는 진행 요약 + 실패한 시도
```
파일이 없으면 문제 설명을 헤더 아래 인용으로 넣어 생성한다.

### 4.5 context.py (컴팩션)
발동 조건: `llm.last_prompt_tokens > 44_000` 또는 `ContextOverflow` 예외.

절차:
1. 유지 대상 결정: `system`, 최초 `user`(과제 메시지), 마지막 4개 툴 교환(assistant tool_call + tool result 쌍).
2. 버려질 구간(그 사이 전부)을 텍스트로 직렬화해 별도 Qwen 호출: "다음 분석 로그에서 (a) 확인된 사실 (b) 실패한 시도와 이유 (c) 미완 작업을 불릿으로 뽑아라." 결과를 case.md `## Log`에 `### compaction N` 헤더로 추가한다.
3. 새 메시지 목록 = `[system, 최초 user, {"role":"user","content":"[CONTEXT RESET] 컨텍스트가 압축됐다. 아래 케이스 파일이 지금까지의 전부다. 이어서 진행해라.\n\n<case.md 전문>"}, 최근 4개 툴 교환...]`.
4. 압축 전 원본 메시지는 transcript.jsonl에 이미 있으므로 버린다.
5. 컴팩션 직후 응답에서도 44k를 넘으면(케이스 파일이 비대) case.md 자체를 `summarize`로 절반으로 줄이고 재시도한다. 2회 연속 실패 시 중단하고 보고서 출력.

### 4.6 agent.py (루프)
```
messages = [system, user(과제: 설명 + 파일 목록 + 규칙)]
for step in range(max_steps):
    if 시간 초과: break
    resp = llm.chat(messages, tools)
    transcript 기록
    if resp.tool_calls 없음:
        messages.append(user("툴을 호출하거나 submit_flag 로 끝내라. 서술만 하지 마라."))  # 최대 3회, 이후 중단
        continue
    for call in resp.tool_calls:
        result = registry[call.name](ctx, **args)      # 예외는 "[tool error] ..." 문자열로
        messages.append(tool_result)
        if call.name == "submit_flag" and 성공: return FLAG
    루프 감지: 최근 3개 tool_call 이 (name, args) 동일하면 user("같은 호출을 반복 중이다. 케이스 파일을 읽고 다른 접근을 골라라.") 추가
    if llm.last_prompt_tokens > 44_000: messages = compact(messages)
보고서 출력 (case.md + 마지막 assistant 메시지), result.json 에 unsolved 기록
```
- 기본 상한: `max_steps=300`, `max_minutes=120`. CLI로 변경.
- 병렬 tool_calls는 순서대로 실행한다(동시 실행 없음).
- 터미널 출력: 스텝 번호, 툴 이름과 인자 요약(한 줄), 결과 앞 3줄, 토큰 사용량. thinking은 `--show-thinking`일 때만.

### 4.7 CLI
```
revagent solve <문제폴더> [--desc desc.txt] [--max-steps 300] [--max-minutes 120] [--no-ask] [--show-thinking]
revagent bench <폴더1> <폴더2> ...     # 순차 실행, 결과 표
```
`--desc` 생략 시 `<문제폴더>/desc.txt`를 찾고, 없으면 "설명 없음"으로 진행한다.

## 5. 데이터 흐름

```
문제 폴더 ──► agent: 과제 메시지 구성 (설명 + `ls` + 규칙)
   │
   ▼
Qwen ◄──► tools (bash / decompile / run_binary / notes / summarize / ask_user)
   │              │
   │              ├─ 큰 출력 → out/NNN.txt (절단본만 컨텍스트로)
   │              └─ decompile → ghidra/functions.json (1회 분석, 캐시)
   │
   ├─ 44k 초과 → context.compact: 버릴 구간 요약 → case.md Log → 재구성
   │
   ▼
submit_flag(DH{...}, 검증 근거) ──► result.json, 종료
```

## 6. 플레이북 (prompts/system.md 골자)

정체성: "너는 CTF 리버싱 전문가다. 도구를 직접 실행해 증거를 모으고, 추측이 아니라 실행 결과로 답을 검증한다."

작업 규칙:
1. **노트 우선.** 툴 출력을 기억하려 하지 말고 결론만 `notes`에 써라. 컨텍스트는 예고 없이 리셋된다.
2. **검증 없이 제출 금지.** `run_binary`로 "Correct" 류 출력을 확인하거나, 체크 로직을 Python으로 재현해 통과를 확인한 뒤 `submit_flag`.
3. **큰 출력은 summarize.** 함수가 200줄 넘으면 `get` 결과를 통째로 읽지 말고 `summarize`에 질문을 던져라.
4. 한 접근이 3회 실패하면 가설을 바꿔라.

절차:
- 트리아지: `file`, `strings -n 6`, 섹션/엔트리, 패커 흔적(UPX, 높은 엔트로피 섹션, 작은 .text), 안티디버깅 문자열(ptrace, IsDebuggerPresent), 언어 흔적(Rust/Go/C++/.NET/Python 번들).
- 진입: `decompile list`로 큰 함수와 문자열 참조 많은 함수부터. main → 입력 읽기 → 변환 → 비교 → 성공/실패 분기.
- 분류와 처방:
  - 제약식(바이트별 산술/xor/테이블): 체크를 Python으로 재현하고 z3 또는 직접 역산.
  - 해시/암호 비교(MD5/SHA/AES/RC4/커스텀): 상수·S-box로 알고리즘 식별. 표준이면 라이브러리, 커스텀이면 역함수 유도 또는 소입력 브루트포스.
  - VM/인터프리터: 오피코드 디스패치 루프 찾기 → 오피코드 테이블과 바이트코드 덤프 → Python 디스어셈블러 작성 → 바이트코드 수준에서 다시 분류.
  - 안티디버깅/자기변조: gdb 배치로 우회하거나(`catch syscall ptrace`, 반환값 패치) unicorn으로 해당 구간만 에뮬레이션.
  - 패킹: UPX면 `upx -d`(없으면 Python으로 언패킹 시도), 아니면 gdb로 OEP까지 실행 후 메모리 덤프.
  - 심볼릭 실행: 입력 길이가 확정되고 분기가 유한하면 angr로 성공 출력 주소를 찾아라.
- 동적: ELF x86-64면 `run_binary`와 gdb 배치(`-batch -ex`)로 중간값을 직접 뽑아라. 정적 추론보다 빠르다.
- 드림핵 규칙: 플래그 `DH{...}`. 문제 설명에 서버(host:port)가 필요하다고 되어 있으면 `ask_user`로 접속 정보를 받아라. 바이너리 안 문자열이 플래그처럼 보여도 검증 없이 제출하지 마라.

## 7. 에러 처리

| 상황 | 처리 |
|---|---|
| 툴 예외 | `"[tool error] <type>: <msg>"` 를 툴 결과로 반환. 루프는 계속. |
| bash/run_binary 타임아웃 | 프로세스 그룹 kill, `[timeout after Ns]` + 그때까지의 출력 반환. |
| vLLM 연결/5xx | 백오프 3회. 실패 시 중단하고 보고서. |
| vLLM 400 컨텍스트 초과 | 강제 컴팩션 후 재시도. |
| Ghidra 실패 | 사유 반환 + "objdump -d -M intel 로 폴백" 안내. |
| 툴 호출 없는 응답 3회 연속 | 중단하고 보고서. |
| 스텝/시간 상한 | 보고서 + result.json `unsolved`. |
| submit_flag 포맷 불일치 | 에러 반환, 계속 진행. |

## 8. 검증

1. **단위 (pytest, 서버 불필요)**
   - `truncate`: 12,000자 경계, 원본 파일 저장, 안내 문구.
   - `casefile`: 생성, 섹션별 add, 파싱.
   - `context.compact`: 유지 대상 선택(system/최초 user/최근 4 교환), 요약 호출은 mock.
   - `ghidra`: `functions.json` 픽스처로 list/get/xrefs 조회.
   - `submit_flag`: 포맷 검사.
   - `tools/__init__`: 레지스트리가 7개 툴 스키마를 만든다.
2. **배관 (서버 필요)**: `bench/mini/xor_check` — 입력을 xor 후 상수 배열과 비교해 "Correct"를 찍는 C 프로그램. `revagent solve`가 트리아지 → 디컴파일 → 풀이 → `run_binary` 검증 → `submit_flag`까지 사람 개입 없이 닫히는지 본다. 정답은 `DH{...}` 형태로 박아둔다.
3. **실전**: 사용자가 던지는 드림핵 레벨 7~8 문제. 실패마다 `case.md`와 `transcript.jsonl`을 읽고 플레이북/툴을 고친다. 결과는 README의 벤치 표에 누적한다.

## 9. 범위 밖 (나중에)

- 여러 워커 Qwen 병렬(오케스트레이터). 단일 루프가 한계에 부딪히면 그때.
- Docker 샌드박스.
- Windows PE 동적 실행(wine).
- APK/.NET/pyc 전용 툴(jadx, ilspy, pycdc). 문제로 만나면 `bash`에서 설치해 쓰고, 반복되면 툴로 승격.

## 10. Amendments (2026-09-19)

Implementation deviated from (or refined) this spec in a few places during the fix wave that closed
out the branch review:

- **Bench entry point.** There is no `bench/run.py` script; batch solving is `revagent bench chal1
  chal2 ...` (see `revagent/__main__.py`), sharing the same `Agent` as `solve` but forcing
  `interactive=False` per challenge and isolating exceptions per challenge (one bad challenge does not
  abort the batch).
- **Ghidra project directory.** The ephemeral Ghidra project passed to `analyzeHeadless` lives in a
  plain system tempdir (`tempfile.TemporaryDirectory`), not under `.revagent/ghidra/`: Ghidra's
  `ProjectLocator` rejects any path with a dot-prefixed component, and the cache dir is normally
  `<challenge>/.revagent/ghidra`. The cached `functions.json` (and per-run `headless_<hash>.log`)
  still land in `.revagent/ghidra/` as designed; only the throwaway project directory moved out.
- **venv recipe (ruling R6).** `python3 -m venv --without-pip --system-site-packages`, with pip coming
  from the system site and a `usersite.pth` added only when `angr`/`z3` were installed with
  `pip install --user`. The Python version embedded in that `.pth` path is derived at setup time
  (`python -c 'import sys; print(f"python{sys.version_info[0]}.{sys.version_info[1]}")'`) rather than
  hardcoded, so the recipe doesn't silently target the wrong interpreter version.
- **Tool timeouts.** Model-supplied `timeout` arguments to `bash` and `run_binary` are clamped to
  `max(1, min(timeout, 900))` (`MAX_TIMEOUT = 900` in `revagent/tools/bash.py`) so a runaway or
  adversarial timeout value from the model can't wedge a run indefinitely.
- **`decompile list` paging.** `list_text()` takes `limit` (default 200) and `filter` (substring,
  case-insensitive) so the model can page past the 200-largest-functions default or narrow to a
  name pattern instead of being hard-capped with no escape hatch; falling back to grepping the cached
  `.revagent/ghidra/<binary>.<hash>.functions.json` directly via `bash` remains available either way.

## 11. 수정 이력 추가 (2026-09-21)

§10 이후 코드가 이 스펙과 달라진 지점(각 항목은 현재 소스에서 확인함):

- **범위 확장**: §1 비목표/§9 범위 밖으로 둔 Docker 샌드박스(`revagent/sandbox.py`, `--sandbox`), Windows PE 실행(wine, `run_binary`), GUI PE 관찰(`tools/run_gui.py`), 런북 종료(`tools/handoff_runbook.py`)가 모두 구현·병합됨. 각각 `2026-09-19-sandbox-design.md`, `2026-09-20-evidence-ladder-design.md`, `2026-09-20-pe-stage-design.md` 참조.
- **툴 수 9개**(§8의 "7개"가 아님): `ask_user`, `bash`, `decompile`, `handoff_runbook`, `notes`, `run_binary`, `run_gui`, `submit_flag`, `summarize`.
- **플레이북 위치**: `prompts/system.md`가 아니라 패키지 안 `revagent/prompts/system.md`. 규칙은 4개가 아니라 11개(증거 사다리, 그래픽 플래그, 중간 결과 보존, Win64 인자 누락 등 추가).
- **`bench/run.py` 없음** — §10 첫 항목 그대로(`revagent bench`).
- **산출물 추가**(§3 목록 외): `results.jsonl`(run마다 한 줄 누적), `screens/NNN.png`·`NNN.diff.png`(run_gui), `runbook.md`(handoff_runbook), `case.md.bak`(shrink_casefile 백업).
- **llm.py**: `max_tokens` 기본값 8192 → **16384**(`DEFAULT_MAX_TOKENS`; thinking 토큰이 포함되므로). 응답은 **스트리밍**으로 받아 `collect_stream`으로 접는다(runpod 프록시의 100 s 524 회피). SDK 자체 재시도는 `max_retries=0`으로 끄고, 눈에 보이는 재시도 3회(`retries=3`, stderr 출력, `total_retries` → result.json `llm_retries`).
- **`load_secure`**: 파일 탐색 전에 `QWEN`/`URL`/`MODEL` 환경변수 세 개가 모두 있으면(그리고 `--secure`가 없으면) 그 값을 쓴다. 이후 순서는 §4.1과 동일.
- **`submit_flag`**: `FLAG_RE`는 `^DH\{.+\}$`가 아니라 `^[A-Za-z0-9_]+\{.+\}$`(어떤 PREFIX{...}든 허용; 접두어는 문제 설명이 정함). 필수 인자 `evidence`(`program_accepted` | `two_independent_readings` | `reimplementation_matches`) 추가, `how_verified` 비어 있으면 거부.
- **`run_binary`**: PE(MZ)는 "실행 불가"가 아니라 샌드박스 안에서 `WINEDEBUG=-all wine`으로 실행. 32-bit PE(PE32/80386)는 이미지에 wine64만 있어 `[cannot run here]`로 거부. 호스트에 wine이 없을 때도 `[cannot run here]`.
- **`decompile`**: 인자 `binary`(첫 호출 시 필수), `limit`(기본 200), `filter` 추가 — §10 마지막 항목 참조.
- **truncate 안내 문구**: `[truncated: N chars total. full output: .revagent/out/NNN.txt — page it with bash: sed -n 'A,Bp' … or grep -n PATTERN …]`(§4.2의 문구와 다름). 끝에 `[env] …` 환경 노트가 있으면 잘라내지 않고 보존.
- **컴팩션 실패 처리**(§4.5 5항): 연속 초과 **2회째**에 `shrink_casefile`(case.md 축약, `.bak` 보존), **3회째**에 중단(`_reduce_context`가 False 반환). "2회 연속 실패 시 중단"이 아님.
- **루프 추가 동작**(§4.6 의사코드 외): `finish_reason == "length"`이고 tool call이 없으면 힌트와 `reasoning_effort=low`로 1회 재시도(`output_truncated` 이벤트); 12스텝 무진전 시 비평가 호출(idle critic); 케이스 파일을 못 읽어도 run을 계속(`casefile_unreadable` 이벤트); `handoff_runbook` 수락 시 상태 `runbook`으로 종료.
- **CLI 플래그 추가**(§4.7): `--secure PATH`, `--sandbox`, `--sandbox-dev`, `--sandbox-ca PATH`(`REVAGENT_SANDBOX_CA`). 종료 코드: solved 0 / unsolved·wrong 1 / usage·preflight 2 / runbook 3.
- **툴 타임아웃 상한**: §10의 900 s 클램프에 더해 `ToolContext.clamp_timeout`이 run의 남은 시간(`deadline`)으로 다시 잘라 `--max-minutes`가 실제 상한이 되게 한다(하한 `MIN_TOOL_SECONDS = 5`).
