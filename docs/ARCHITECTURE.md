# revagent 아키텍처

이 문서는 코드를 직접 쓰지 않은 사람이 혼자 유지보수하고 남에게 설명할 수 있도록 쓴 지도다. 파일명·함수명·상수·숫자는 2026-09-22 기준 `feat/trace-run` 브랜치의 소스, `README.md` 벤치 표, `docs/superpowers/specs/`에서 읽은 것이다. 코드와 이 문서가 다르면 코드가 맞다.

## 1. 한 문단 요약

revagent는 Dreamhack 리버싱 문제 폴더(바이너리 + `desc.txt`)를 받아 플래그를 스스로 찾는 에이전트다. 두뇌는 직접 띄운 Qwen3.8-27B(vLLM, OpenAI 호환 API)이고, 구조는 ReAct 루프 하나(`revagent/agent.py`)에 도구 열두 개(`revagent/tools/*.py`)를 붙인 것이다. 실행은 기본적으로 Docker 샌드박스(`docker/Dockerfile`, `revagent/sandbox.py`) 안에서 일어나고, 산출물은 문제 폴더의 `.revagent/`에 남는다. 범용 에이전트 프레임워크가 아니다. 문제 유형은 리버싱만, 모델은 Qwen 하나, 플래그 포맷은 `PREFIX{...}`로 고정돼 있고, 프롬프트(`revagent/prompts/system.md`)는 Dreamhack 관례를 직접 언급한다. 설계 논지는 하나다. 27B 모델이 반복해서 못 하는 일(자기 재구현이 맞는지 확인하기, 바이트 단위 체크 역산, 인터프리터가 실제로 실행한 순서 읽기)은 **문제 내용을 모르는 도구**(`emulate`, `solve_check`, `trace_run`)로 대신하고, 모델이 빠지는 습관(같은 스크립트 재수정, 머릿속 장기 추론)은 **과거 transcript 전부에 리플레이해 풀린 실행에서 오탐 0인 값으로 캘리브레이션한 개입**(G3, G4)으로 끊는다. 도구와 게이트는 특정 문제·함수 이름·문자열을 참조하지 않는다(`docs/superpowers/specs/2026-09-21-transition-rules-design.md` §2.1).

## 2. 데이터 흐름 그림

한 스텝과 종료 처리. 괄호는 담당 파일·함수다.

```
revagent solve <dir>                                  (__main__.main → _preflight → _run_one)
  │  기본: docker run revagent-sandbox solve /work/<dir> --host   (sandbox.build_sandbox_cmd)
  │  자격증명은 -e QWEN -e URL -e MODEL 이름만 argv에, 값은 docker CLI 환경으로 (sandbox.run_sandbox)
  ▼
Agent.run()                                           (agent.py; 컨테이너 안에서도 같은 코드)
  │  messages = [system.md, 과제 메시지(desc + ls -la)]
  ▼
llm.chat(messages, schemas) ── 스트리밍 ──► collect_stream ──► ChatResponse   (llm.py)
  │  _create: 일시 장애 3회 재시도, 400 "context length" → ContextOverflow
  │  finish_reason == "length" 이고 tool_calls 없음 → 힌트를 붙여 effort=low 로 1회 재시도
  ▼
resp.tool_calls ──► Gate.check(step, calls)           (gate.py: G3 차단 판정 + 이벤트)
  │                 reasoning 길이 > 8,000자 카운트     (detectors.LONG_REASONING_*: G4)
  ▼
_run_tools ──► handler(ctx, **args) ──► truncate()    (tools/*.py; truncate.py: 12,000자 초과 → out/NNN.txt)
  │   run_binary/run_gui/emulate/trace_run 은 ctx.observe() 로 case.md Log 에 "- [obs step N]" 기록
  │   게이트 이벤트는 "- [gate step N]", 비평가 메모는 "- [critic step N]"
  ▼
tool 결과를 messages 에 추가 → 진행 판정 progress_marker(Facts 수, [obs] 수)   (critic.py)
  │  12스텝 무진전 → run_critic → "[critic] ..." user 메시지
  │  last_prompt_tokens > 44,000 → agent._reduce_context:
  │      critic → context.compact(중간 구간 요약 → case.md Log "### compaction N", Todo 갱신, prune_log)
  │      → messages = [system, task, "[CONTEXT RESET] + case.md + [WORK FILES]", 최근 4개 도구 교환]
  │      2회 연속 초과 → shrink_casefile(case.md 절반으로, .bak 보존); 3회 → run 종료
  ▼
다음 스텝 … submit_flag 수락(ctx.flag) / handoff_runbook 수락(ctx.runbook_path) / 예산 소진
  ▼
agent._finish: result.json(덮어씀) + results.jsonl(한 줄 누적) + transcript "end" 이벤트
  ▼
호스트: __main__._read_result → check_answer(<dir>/../ANSWERS.md)
        플래그 불일치면 result.json 을 status "wrong" 으로 고쳐 씀 (_mark_wrong_if_answer_mismatch)
        종료 코드: solved 0 / unsolved·wrong 1 / 시작 실패 2 / runbook 3
```

## 3. 다섯 층

### 3.1 루프 — `revagent/agent.py`

`Agent.run()`이 전부다. 스텝마다 시간 예산(`max_minutes`, 기본 120)을 확인하고 `llm.chat`을 부른다. 응답에 도구 호출이 없으면 "Call a tool" 넌지를 넣되 3회 연속이면 끝낸다. 도구 호출이 있으면 `_run_tools`가 게이트 판정을 받아 순서대로 실행한다. 한 턴 안에서 플래그나 런북이 세워지면 남은 호출은 `skipped: session ended`로 답한다. 같은 (도구, 인자) 호출이 3회 반복되면(`self.recent`, `deque(maxlen=3)`) 다른 접근을 고르라는 user 메시지를 넣는다. 예외는 어떤 경우에도 run을 죽이지 않는다. 도구 예외는 `_execute`에서 `[tool error]` 문자열이 되고, 루프 자체의 예외도 `result.json`을 쓴 뒤 보고한다. 케이스 파일을 모델이 지워도 `casefile_unreadable` 이벤트만 남기고 계속한다. `signals`(게이트 차단 수, 최대 스크립트 스트릭, 긴 생각 스텝 수, 첫 Facts 스텝)는 `run()` 끝에서 조립한다.

| 파일 | 줄 수 | 역할 한 줄 | 들어가야 할 때 |
|---|---|---|---|
| `revagent/agent.py` | 369 | ReAct 루프, 예산, 넌지, 게이트·비평가·압축 배선, result 기록 | 종료 조건·재시도 문구·`signals` 항목을 바꿀 때 |

상수: `TRUNCATED_RETRY_EFFORT = "low"`, `TRUNCATED_RETRY_HINT`/`TRUNCATED_NUDGE`(출력 예산 초과 시 문구), `G4_TEXT`(게이트 경고 문구), `TASK_TEMPLATE`(과제 메시지). 기본 `max_steps=300`.

### 3.2 모델 연결 — `revagent/llm.py`

`LLM`은 `openai` SDK로 vLLM의 `/v1/chat/completions`를 부른다. 세 가지가 핵심이다. (1) **스트리밍**: RunPod 프록시는 응답이 약 100초 안에 시작되지 않으면 HTTP 524로 끊는다. 비스트리밍이면 생성이 끝나야 응답이 시작되는데 어려운 스텝은 그보다 오래 생각한다. 그래서 `stream=True`로 받아 `collect_stream`이 청크를 응답 하나로 접는다(`parse_assistant`와 usage 집계는 스트리밍 여부를 모른다). (2) **재시도는 직접**: `OpenAI(..., max_retries=0)`으로 SDK의 조용한 재시도를 끄고 `_create`가 지수 백오프(2초부터 2배)로 `retries=3`회 재시도하며 stderr에 찍고 `total_retries`에 센다(result.json의 `llm_retries`). 끊긴 스트림은 `APIConnectionError`가 아니라 httpx 전송 예외로 오기 때문에 `_retryable`이 `httpx.TransportError`도 잡고, 401/403/404 같은 상태 오류는 재시도하지 않는다. (3) **httpx2**: openai 3.x는 자체 포크 `httpx2`를 쓰므로 `import httpx2 as httpx`를 먼저 시도한다. 그 밖에 `DEFAULT_MAX_TOKENS = 16384`(thinking 토큰 포함; relativity run1에서 8192에 잘린 12스텝이 전부 16k엔 들어갔다), `temperature=0.6`, `reasoning_effort="medium"`(요청마다 `extra_body`로 전달, `chat()`/`complete()`에서 호출별 override 가능), `timeout=600`. 400 응답에 "context length"/"maximum context"/"too long"이 있으면 `ContextOverflow`로 올린다.

| 파일 | 줄 수 | 역할 한 줄 | 들어가야 할 때 |
|---|---|---|---|
| `revagent/llm.py` | 278 | `.secure` 로드, 스트리밍 클라이언트, 재시도, usage 집계, `complete()` 단발 호출 | 서버·모델·토큰 예산·재시도 정책을 바꿀 때 |

`load_secure`의 탐색 순서: `--secure` 없이 환경변수 `QWEN`/`URL`/`MODEL` 셋이 모두 있으면 그것 → `--secure` 경로 → `$REVAGENT_SECURE` → `./.secure` → 레포 루트 `.secure` → `~/.revagent/.secure`. 파일 형식은 `KEY=value` 줄이며 `.secure.example`에 있다.

### 3.3 기억 — `revagent/context.py`, `revagent/casefile.py`, `revagent/truncate.py`

컨텍스트는 64k(서버 `max_model_len 65536`)다. 프롬프트 토큰이 `THRESHOLD = 44_000`을 넘으면 `compact`가 동작한다. `split_messages`가 `[system, task]`를 머리, 마지막 `KEEP_RECENT = 4`개의 도구 교환을 꼬리로 남기고, 그 사이를 `serialize`(메시지당 `PER_MSG_CAP = 1_500`자, 전체 `TOTAL_CAP = 90_000`자)해서 `SUMMARY_PROMPT`로 요약시킨다. 요약은 (a) 확인된 사실 (b) 실패 (c) 미완 (d) 산출물 네 항목이고, case.md Log에 `### compaction N` 블록으로 붙고 (c)는 Todo 섹션을 덮어쓴다(`extract_unfinished`). `prune_log`는 오래된 블록(최근 3개 제외)에서 (b)(c)를 지워 리셋 비용이 계속 커지는 것을 막는다. 리셋 메시지는 `RESET_TEXT + case.md 전문 + [WORK FILES]`(run 시작 이후 수정된 파일 목록, 최대 40개, 4,000자)다. 압축 뒤에도 넘치면 2회째에 `shrink_casefile`이 case.md를 절반으로 다시 쓰게 하고(`.bak` 보존; 헤더가 빠졌거나 `finish_reason == "length"`면 거부), 3회째에 run을 끝낸다.

`CaseFile`(case.md)은 고정 4섹션 `## Facts / ## Hypotheses / ## Todo / ## Log`다. 모델은 `notes` 도구로 불릿을 추가하고, 도구·게이트·비평가는 Log에 `- [obs step N]`, `- [gate step N]`, `- [critic step N]` 줄을 직접 쓴다. 이 세 접두어는 `context._is_ledger_line`이 인식해 `prune_log`가 지우지 않고 `SHRINK_PROMPT`도 병합만 허용한다. 모델이 노트를 안 써도 실행 관찰은 남는다(evidence-ladder spec §3.2 "관찰 원장").

`truncate`는 모든 도구 결과에 적용된다. `LIMIT = 12_000`자를 넘으면 원문을 `.revagent/out/NNN.txt`에 저장하고 `sed -n`/`grep` 안내를 붙인다. 끝에 `ENV_NOTE_PREFIX`로 시작하는 `FOOTER_MAX = 512`자 이하 꼬리말(`ToolContext.env_note`)이 있으면 그것만은 잘라내지 않는다.

| 파일 | 줄 수 | 역할 한 줄 | 들어가야 할 때 |
|---|---|---|---|
| `revagent/context.py` | 289 | 압축 임계값, 요약 프롬프트, 리셋 메시지, Log 정리, case.md 축약 | 리셋이 너무 잦거나 요약이 사실을 잃을 때 |
| `revagent/casefile.py` | 72 | case.md 생성·섹션 추가·교체, `section_span` | 섹션 구조를 바꿀 때(prompts·critic·context 전부 영향) |
| `revagent/truncate.py` | 39 | 도구 출력 12,000자 캡 + 원본 저장 + `[env]` 꼬리말 보존 | 캡 크기나 안내 문구를 바꿀 때 |

### 3.4 도구 — `revagent/tools/*.py`

`tools/__init__.py:load_tools`가 패키지 안 모듈을 이름순으로 import해 `SCHEMA`(OpenAI function 스키마)와 `run(ctx, **args) -> str`을 둘 다 가진 것만 등록한다. 파일 하나가 도구 하나다. `tools/base.py`의 `ToolContext`는 모든 도구가 공유하는 상태다: 문제 폴더·작업 폴더·`CaseFile`·`llm`, 현재 `step`, `flag`/`how_verified`, `runbook_path`, `env_blocked`와 `env_blocked_paths`(샌드박스가 대상을 못 돌린다는 도구 증거), Ghidra 함수 DB 캐시(`function_dbs`), emulate 이미지 캐시, trace_run 베이스·영역 캐시, `tools_used`(핸들러가 실제로 실행된 호출 수). 헬퍼 `resolve_inside`는 모델이 준 경로가 문제 폴더를 벗어나면 `PathError`를 던지고, `clamp_timeout`은 도구 대기 시간을 run의 남은 시간으로 자른다(하한 `MIN_TOOL_SECONDS = 5`; damnida run1이 120분 상한을 넘겨 외부 래퍼에 죽은 뒤 추가). `observe`는 원장 줄을 쓰고 예외를 삼키며, `note_start_failure`는 시작 실패 `START_FAILURES_TO_BLOCK = 2`회에 `env_blocked`를 세운다. `bash.run_cmd`는 자식 프로세스 환경에서 `QWEN`/`URL`/`MODEL`/`REVAGENT_SECURE`를 지운다(`SCRUB_ENV`).

열두 도구를 역할로 묶으면 다음과 같다(괄호는 줄 수).

**관찰(observe)**
- `run_binary.py` (129): x86-64 ELF·스크립트 실행, PE는 `WINEDEBUG=-all wine`(64비트만; PE32는 `[cannot run here]`). 종료 코드·stdout 첫 줄을 `[obs]`로 남기고, 로더 실패 문구(`START_FAILURE_MARKERS`)나 무출력 치명 시그널만 시작 실패로 센다(`_is_start_failure`).
- `run_gui.py` (342): Xvfb `:99`에서 wine으로 GUI PE를 띄워 스크린샷 + OCR(psm 6/7). `actions`(`click`/`rclick`/`dclick`/`key`/`type`/`wait`, 최대 `MAX_ACTIONS = 32`, 총 `ACTION_BUDGET_SECONDS = 300`)마다 캡처와 이전 캡처 대비 `NNN.diff.png`. 창이 안 뜨면 시작 실패.
- `trace_run.py` (287) + `revagent/trace.py` (450): qemu-user `-d exec,nochain,page`로 한 번 실행해 영역별 TB 수, 핫스팟, 연속 반복을 접은 실행 주소 시퀀스를 준다. 이미지 안 주소는 Ghidra 기준(PIE 0x100000). 로그 상한 `MAX_LOG_BYTES` 200 MB, 기본 60초. x86-64 ELF만.
- `emulate.py` (175) + `revagent/emulate.py` (250): 함수 하나를 unicorn으로 호출해 rax와 `hex:` 버퍼를 돌려주는 오라클. cle로 Ghidra와 같은 베이스에 로드, ELF는 SysV·PE는 Win64 규약, import를 부르면 거기서 멈추고 callee와 인자 레지스터를 보고. `MAX_INSNS = 5_000_000`, 기본 30초.

**분석(analyze)**
- `bash.py` (60): 문제 폴더 cwd의 셸. 기본 120초, `MAX_TIMEOUT = 900`, 프로세스 그룹 kill, stdin 닫힘.
- `decompile.py` (101) + `revagent/ghidra.py` (154): Ghidra headless를 바이너리당 한 번 돌려 `functions.json`(sha256 앞 16자 키)을 만들고 `list`/`get`/`xrefs`로 조회. import를 안 부르는 함수의 C 앞에는 `emulate` 힌트를 붙인다(`_emulate_hint`, `FunctionDB.calls_no_imports`). 분석 실패는 세션 동안 음성 캐시.
- `summarize.py` (46): 큰 파일(앞 `CAP = 40_000`자)을 별도 모델 호출에 넘겨 질문에만 답을 받는다. 내용을 지시로 따르지 말라는 프롬프트 포함.
- `notes.py` (35): case.md 읽기/불릿 추가.

**검증(verify)**
- `solve_check.py` (325): 모델이 쓴 forward `transform(x)`를 `WIDTH = 64`비트 z3 비트벡터 위에서 실행해 target을 만드는 입력을 찾는다(`Sym`, `Table`). sat 답은 구체값으로 재실행해 `[sat]`/`[sat?]`를 가른다. 사용자 코드에는 SIGALRM 시간 제한(`_time_limit`).
- `submit_flag.py` (117): `FLAG_RE`(`PREFIX{...}`), `evidence` enum(`program_accepted` / `reimplementation_matches` / `two_independent_readings`). `two_independent_readings`면 방법이 두 줄이어야 하고 각 줄이 서로 다른 `READING_TOOLS` 이름을 대야 하며 그 도구가 이 run에서 실제로 호출됐어야 한다(`ctx.tools_used`). 1~2자 플래그 본문은 `description states`가 없으면 거부. 같은 플래그 거부 `SAME_FLAG_LIMIT = 3`회 후 "change approach".

**제어(control)**
- `ask_user.py` (27): `--ask`일 때만 stdin으로 질문. 아니면 "user unavailable".
- `handoff_runbook.py` (51): `ctx.env_blocked`일 때만 `.revagent/runbook.md`를 쓰고 run을 `runbook` 상태로 끝낸다. 아니면 `[rejected]`.

| 파일 | 줄 수 | 역할 한 줄 | 들어가야 할 때 |
|---|---|---|---|
| `revagent/tools/__init__.py` | 17 | SCHEMA+run 자동 등록 | 거의 없음(파일 추가로 충분) |
| `revagent/tools/base.py` | 116 | `ToolContext`, `resolve_inside`, `clamp_timeout`, 관찰 원장, env 게이트 | 도구 간 공유 상태를 추가할 때 |
| `revagent/tools/<이름>.py` | 27~342 | 도구 하나 | 그 도구의 스키마·문구·한계를 바꿀 때 |

### 3.5 판단 보조 — `revagent/gate.py`, `revagent/detectors.py`, `revagent/critic.py`

**G3(표현 전환 게이트)**. `detectors.script_body`가 `bash` 명령에서 heredoc 본문이나 `python3 -c` 문자열을 뽑고, `similar`가 두 스크립트를 "같은 산출물"로 본다: 공백 정규화 후 앞 `PREFIX_CHARS = 200`자가 같거나 줄 집합 Jaccard > `JACCARD_MIN = 0.6`. `Gate.check`는 연속 유사 스크립트가 `STREAK_LIMIT = 4`번째가 되면 그 호출을 실행하지 않고 `G3_TEXT`(`[blocked by G3] ...`: emulate로 비교, run_binary로 확인, solve_check로 넘기기, notes에 실패 기록 중 하나를 요구)를 결과로 넣는다. 스크립트가 아닌 호출만 있는 스텝은 스트릭을 리셋하고 `gate_open`을 남긴다. 연속 `RELEASE_AFTER = 3`스텝 차단되면 스스로 풀리고 `COOLDOWN_STEPS = 10`스텝 조용하다. 게이트는 방향을 조언하지 않고 막기만 한다(모듈 docstring: 잘못된 조언은 run 하나를, 잘못된 차단은 최대 3스텝을 잃는다). 예외는 전부 허용 + `gate_error` 이벤트로 흡수된다. 같은 `Gate` 클래스를 리플레이 스크립트가 쓰므로 리플레이 결과가 곧 루프 동작이다.

**G4(생각 예산 경고)**. 스텝의 reasoning이 `LONG_REASONING_CHARS = 8000`자를 넘으면 카운트하고, `LONG_REASONING_LIMIT = 5`번째에 `agent._g4_warn`이 `G4_TEXT`를 user 메시지로 한 번 넣는다. 원래 설계는 이후 `reasoning_effort`를 `low`로 내리는 것이었지만 2026-09-22 ROVM·damnida 라이브에서 경고 뒤 생각이 오히려 길어져(중앙값 2,201 → 15,631자, 720 → 5,382자) 하향은 제거했다(`_g4_warn` 주석, transition-rules spec §3.2).

**왜 이 둘인가**. transition-rules spec §8의 리플레이 표. 보유 transcript(해결 7세션, 미해결 15세션)에 후보 신호를 계산했다. "N스텝 안에 Facts 기록"은 해결 세션에서도 울려 탈락, "관찰 없는 스크립트 연속 K개"는 K=4에서 해결 6/7 오탐으로 탈락. "같은 스크립트 재수정 T=3"은 multipoint에서 1회 오탐, T=4는 해결 0/7·미해결 4/15로 채택. "8천 자 초과 생각 횟수"는 해결 최대 4회·미해결 5~25회로 5회째 채택. 탈락한 `first_facts_step`은 `signals`에 기록만 한다.

**비평가**. `critic.run_critic`은 같은 Qwen에 `reasoning_effort="low"`, `CRITIC_MAX_TOKENS = 4096`으로 case.md 전문과 최근 12개 도구 교환(인자 `RECENT_ARG_CHARS = 200`, 결과 `RECENT_RESULT_CHARS = 300`)을 주고 고정 질문 4개(계획과 모순되는 관찰, 반복되는 접근, 가장 싼 다음 실험, 환경이 실행 못 한다는 증거)에 답을 받는다. 압축 직전마다, 그리고 `CRITIC_IDLE_STEPS = 12`스텝 동안 Facts·`[obs]` 줄이 안 늘면 호출하며 run당 `CRITIC_MAX = 8`회. 메모는 `CRITIC_MAX_LINES = 6`줄로 잘라 `[critic]` user 메시지와 원장 줄로 남긴다. 조언일 뿐 루프가 강제하지 않는다.

| 파일 | 줄 수 | 역할 한 줄 | 들어가야 할 때 |
|---|---|---|---|
| `revagent/detectors.py` | 50 | 스크립트 추출·유사도·임계값 상수 | 임계값을 바꿀 때(반드시 리플레이 후) |
| `revagent/gate.py` | 109 | G3 상태 기계, 차단 문구, 이벤트 | 새 게이트를 추가할 때 |
| `revagent/critic.py` | 90 | 비평가 프롬프트·트리거 상수·원장 기록 | 비평가 질문을 바꿀 때 |

### 3.6 바깥 껍질

- `revagent/sandbox.py` (102) + `docker/Dockerfile` (102) + `docker/entrypoint.sh`: 이미지는 `python:3.12-slim-bookworm` 위에 binutils/gdb/gcc·g++(`-m32` 포함)/strace/ltrace/qemu-user-static, bullseye의 libssl1.1(revlogin처럼 구형 OpenSSL을 요구하는 바이너리용), radare2 6.2.2, Temurin JDK 21과 Ghidra 12.1.3(`/root/tools`), 고정 버전 Python 스택(angr 10.0.0, z3 5.1.0.0, unicorn 2.1.2, capstone 5.0.9, pwntools 4.15.0, pefile, pycryptodome, pillow 12.3.0, openai 3.16.2), wine/wine64 + Xvfb + xdotool + ImageMagick + tesseract, mingw-w64(i686/x86_64)를 담는다. wine prefix는 빌드 시 미리 만든다(시작마다 17~22초 절약). 앱 코드는 `pip install --no-deps -e /app`이라 `--dev`로 레포를 `/app`에 마운트하면 재빌드 없이 반영된다. 컨테이너는 `--rm --init`, `--cap-add SYS_PTRACE --security-opt seccomp=unconfined`(docker 기본 seccomp가 gdb의 ptrace와 ASLR 해제를 막아 relativity run1이 매번 다른 값을 봤다), 문제 폴더는 `/work/<이름>`에 마운트, `PYTHONUNBUFFERED=1`과 `REVAGENT_IN_SANDBOX=1`을 넘긴다. `check_docker`는 CLI·데몬·이미지 부재를 각각 다른 문구로 알린다. 이미지 크기는 README 기준 약 6.6 GB.
- `revagent/__main__.py` (272): `solve <dir>`와 `bench <dirs...>`. 기본은 샌드박스, `--host`는 이 머신, `--dev`는 레포 마운트, `--ask`는 `ask_user` 허용(solve만), `--desc`, `--max-steps`, `--max-minutes`, `--secure`, `--show-thinking`, `--sandbox-ca`(env `REVAGENT_SANDBOX_CA` → `~/.revagent/sandbox-ca.crt`). 옛 플래그 `--sandbox`/`--sandbox-dev`/`--no-ask`는 숨겨진 채 동작한다. `_preflight`가 docker·`--desc` 위치·CA 파일·`.secure`를 순서대로 검사하고, `_run_one`이 한 폴더를 돌린다. 컨테이너가 실패했는데 `result.json`이 갱신되지 않았으면 이전 결과를 이번 것으로 보고하지 않는다.
- `revagent/console.py` (61): stdout/stderr를 `<dir>/.revagent/console.log`에 `=== run <UTC> argv: ... ===` 헤더와 함께 tee한다. 컨테이너 안에서는 열지 않고 호스트가 스트림을 받아 기록한다.
- `revagent/ghidra.py` (154) + `revagent/ghidra_scripts/DumpFunctions.java`: `analyzeHeadless`를 임시 프로젝트 디렉터리(Ghidra가 `.`으로 시작하는 경로를 거부해 `.revagent/` 밖)로 돌리고 모든 함수의 `{name, entry, size, decompiled_c, callers, callees, string_refs, is_thunk}`를 JSON으로 덤프한다. 기본 타임아웃 1200초(run 마감으로 다시 잘림), 타임아웃 시 프로세스 그룹 kill.
- `scripts/replay_detectors.py` (112): transcript.jsonl 경로들을 받아 세션마다 실제 `Gate`로 G3 차단 스텝·해제 스텝·G4 경고 스텝을 표로 낸다. `check_answer`로 상태를 교차 검증해 오답 제출은 `wrong`으로, 게이트가 켜진 세션은 `(gated)`로 표시한다. 해결 세션에서 게이트가 울렸으면 종료 코드 1.

## 4. 왜 이렇게 만들었나

이 프로젝트의 기능은 거의 전부 실패한 실행 하나에서 나왔다. 순서는 항상 같다. 실행이 실패한다 → 트랜스크립트에서 원인을 하나로 좁힌다 → 문제 이름이 들어가지 않는 도구나 규칙으로 바꾼다 → 다음 실행으로 확인한다. 상세 동기는 각 스펙의 "1. 배경과 문제" 절에, 실행 기록은 `README.md` 벤치 표에 있다.

| 실패한 실행 | 관찰된 원인 | 만든 것 | 확인 |
|---|---|---|---|
| relativity run1, ROVM run1 (출력 잘림 12회, HTTP 524) | 프록시가 100초 안에 시작 안 된 응답을 끊음. 출력 예산 부족 | `llm.py` 스트리밍 클라이언트 + 재시도, `DEFAULT_MAX_TOKENS` 16k | relativity run4 이후 524 사망 0회 |
| relativity run1~3 | 샌드박스에서 ASLR을 못 꺼 덤프 주소가 매번 달랐음. 로더가 다시 쓰는 데이터를 파일 값으로 모델링 | `sandbox.py` ptrace/seccomp 옵션, 플레이북 "Data rewritten before main" 항목 | relativity run4·5 해결 |
| basic run1·2 | forward 변환을 검증할 오라클이 없어 틀린 모델 위에 역산을 쌓음 | `emulate` (함수 하나를 unicorn으로 실행) | basic run3 해결. emulate 3회 호출 후 모델이 오라클과 일치 |
| basic run2, captain-hook run9 | 같은 스크립트를 고치며 맴돎 | G3 (같은 스크립트 4번째 재편집 차단), 리플레이로 오탐 0 확인 | basic run3에서 4회 차단, 매번 접근이 바뀜 |
| ROVM run2, damnida run2 | G4가 effort를 낮추자 추론이 더 길어짐 | G4 effort 하향 제거, 경고만 유지 | 스펙 §3.2 주석 |
| captain-hook run9·10 | 증거 종류를 모델이 스스로 분류해 규칙을 형식만 만족 | `submit_flag` 두 독립 판독 = 실제 호출된 서로 다른 도구 2개 | 리플레이 통과. 라이브 확인 대기 |
| ROVM run1~5, damnida run1·2 | 인터프리터 구조는 복원하나 해석되는 프로그램을 끝내 못 읽음 | `trace_run` (qemu 실행 추적 집계) + 인터프리터 클래스 규칙 | ROVM run6에서 확인 중 |

기각된 후보도 기록한다. "Facts를 N스텝 안에 안 쓰면 개입", "스크립트 연속 N회면 개입"은 풀린 실행에서도 발화해 리플레이에서 기각됐다(`scripts/replay_detectors.py`, 스펙 2026-09-21-transition-rules §8). 기준은 하나다. 풀린 실행에서 한 번도 안 울리는 규칙만 넣는다.

## 5. 실행과 결과 읽기

**한 문제**: `~/.revagent-venv/bin/revagent solve <문제폴더>`. 기본은 샌드박스이고 묻지 않는다. `--show-thinking`으로 모델 생각을 함께 출력하고, `--dev`로 이 레포를 컨테이너에 마운트해 코드 수정을 재빌드 없이 시험하며, `--host`는 도커 없이 돌린다(wine 없음). 문제 설명은 `<문제폴더>/desc.txt`가 기본이고 `--desc FILE`로 바꾼다(샌드박스에서는 문제 폴더 안 파일이어야 한다).

**벤치**: `~/.revagent-venv/bin/revagent bench <폴더1> <폴더2> ...`. 폴더마다 컨테이너 하나씩 순서대로 돌리고, 끝에 `| challenge | status | flag/reason | steps | min |` 표를 찍는다(`__main__._print_bench_table`). 한 폴더의 예외는 그 행만 `error`로 만들고 나머지는 계속한다. 전부 `solved`면 종료 코드 0.

**산출물** (`<문제폴더>/.revagent/`):

| 파일 | 내용 | 만드는 곳 |
|---|---|---|
| `console.log` | 터미널 출력 전체, 실행마다 `=== run ... ===` 헤더로 누적 | `console.tee_console` |
| `case.md` | 에이전트 노트. Facts / Hypotheses / Todo / Log(compaction 블록과 `[obs]`/`[gate]`/`[critic]` 원장) | `casefile.CaseFile`, `notes`, `ToolContext.observe` |
| `case.md.bak` | `shrink_casefile` 직전 백업 | `context.shrink_casefile` |
| `transcript.jsonl` | 모든 메시지, 도구 호출, `_reasoning` 줄, `_meta` 이벤트(`session_start`, `compaction`, `gate_*`, `critic`, `output_truncated`, `end`) | `agent._log` |
| `out/NNN.txt` | 12,000자를 넘어 잘린 도구 출력의 원본 | `truncate.truncate` |
| `out/trace-N.log`, `out/trace-N.txt` | `trace_run`의 qemu 원본 로그와 접은 전체 시퀀스 | `tools/trace_run.py` |
| `ghidra/<bin>.<hash>.functions.json`, `headless_<hash>.log` | 디컴파일 캐시와 Ghidra 로그 | `ghidra.analyze` |
| `screens/NNN.png`, `NNN.diff.png` | `run_gui` 캡처와 입력별 변화 픽셀 | `tools/run_gui.py` |
| `runbook.md` | 샌드박스가 실행 못 하는 대상일 때 사람용 절차 | `tools/handoff_runbook.py` |
| `result.json` | 마지막 실행 결과(다음 실행이 덮어씀) | `agent._finish` |
| `results.jsonl` | 실행마다 한 줄 누적(`time` 필드 추가) | `agent._finish` |

**`result.json` 읽는 법**: `status`는 `solved` / `unsolved`(예산 소진, 오류; `reason`에 사유) / `runbook` / `wrong`(ANSWERS.md 불일치, `note`에 기대값). `steps`, `compactions`, `prompt_tokens`, `completion_tokens`, `llm_retries`, `minutes`가 있고 `signals`에 네 값이 있다. `gate_blocks`는 G3가 실행을 막은 호출 수, `max_script_streak`는 같은 스크립트 연속 재수정의 최대 길이(4 이상이면 차단이 있었다), `long_reasoning_steps`는 8,000자를 넘긴 생각 스텝 수(5 이상이면 G4 경고가 나갔다), `first_facts_step`은 Facts 불릿이 처음 생긴 스텝(`null`이면 노트를 한 번도 안 썼다). 풀린 실행의 기준선은 README 벤치 표의 relativity run5(`gate_blocks 0, max_script_streak 2, long_reasoning_steps 3, first_facts_step 1`)다.

**ANSWERS.md**: `<문제폴더>/../ANSWERS.md`에 `| <폴더이름> | <플래그> |` 행이 있으면 `__main__.check_answer`가 대조한다. `solved`인데 플래그가 다르면 `wrong`으로 바꾸고 `solve`는 `result.json`을 고쳐 쓰며 종료 코드 1을 낸다. `bench` 표에도 같은 규칙이 적용된다. 행이 없거나 파일이 없으면 그대로 통과한다. 플래그 셀은 그대로 비교하므로 셀 안에 주석을 쓰면 안 된다(`bench/mini/ANSWERS.md` 하단 주석 참조).

**리플레이**: `~/.revagent-venv/bin/python scripts/replay_detectors.py <문제폴더>/.revagent/transcript.jsonl [...]`. 세션마다 G3 차단 스텝, 해제 스텝, 최대 스트릭, 긴 생각 스텝 수, G4 스텝을 표로 찍는다. 풀린 세션(게이트가 없던 옛 세션)에서 하나라도 울리면 `FALSE POSITIVE`로 표시하고 종료 코드 1이다. 새 실행이 끝날 때마다 돌려서 오탐이 생기면 `detectors.py` 임계값을 올리는 것이 규칙이다(transition-rules spec §3.4).

## 6. 바꾸는 법 (레시피)

### (a) 도구 하나 추가
1. `revagent/tools/<이름>.py`를 만들고 `SCHEMA`(`{"type": "function", "function": {"name", "description", "parameters"}}`)와 `run(ctx, **kwargs) -> str`을 둔다. `tools/__init__.py:load_tools`가 자동으로 등록하므로 다른 등록 코드는 없다. 이름은 `SCHEMA["function"]["name"]`이 기준이다.
2. 모델이 준 경로는 반드시 `base.resolve_inside(ctx, rel)`로 풀고, 대기 시간은 `ctx.clamp_timeout(...)`으로 자른다. 자식 프로세스는 `bash.scrubbed_env()`를 환경으로 쓴다. 실행 관찰이면 `ctx.observe("<도구> <대상>: ...")` 한 줄을 남긴다. 예외는 도구 안에서 잡아 `[tool error] ...` 문자열로 돌려준다(`agent._execute`가 잡기는 하지만 문구를 도구가 정하는 것이 낫다).
3. `tests/test_tools.py`에 `tests/conftest.py`의 `make_ctx(tmp_path)`/`FakeLLM`으로 테스트를 쓴다. 기존 `test_registry_has_all_tools`가 도구 수를 세므로 갱신한다.
4. `revagent/prompts/system.md`의 `# Environment`에 한 줄, 필요하면 `## 3.` 분류 항목에 사용 시점을 적는다. 문구 회귀는 `tests/test_agent.py`의 `test_playbook_*` 테스트 패턴으로 고정한다.
5. 새 시스템 패키지가 필요하면 `docker/Dockerfile`에 넣고 `bash scripts/sandbox-build.sh`로 재빌드한다(스모크 테스트가 같은 스크립트에 있다). 코드만 바뀌었으면 `--dev`로 먼저 시험한다.
6. `README.md`의 "동작 원리" 도구 목록과 산출물 표를 갱신한다.

### (b) 게이트 하나 추가
1. `revagent/detectors.py`에 신호를 **transcript에서 관측 가능한 값의 순수 함수**로 쓴다(도구 이름, 인자 텍스트, reasoning 길이, 스텝 수). 문제 이름·바이너리 성질·특정 문자열은 금지다(transition-rules spec §2.1).
2. `revagent/gate.py`에 판정과 차단 문구를 넣는다. 게이트는 요구 행동을 말하고 방향은 조언하지 않는다. 교착 방지(연속 차단 N회 후 자동 해제)를 넣고, 예외는 `gate_error`로 흡수한다.
3. `revagent/agent.py`에 배선한다: `_run_tools`의 `Gate.check` 호출 뒤 이벤트를 `_log`와 `_ledger`에 남기고, `_ledger`의 이벤트→문구 표에 새 이벤트를 추가하고, `signals`에 카운터를 넣는다.
4. `scripts/replay_detectors.py`가 같은 클래스를 쓰는지 확인하고, 보유한 transcript 전부에 리플레이한다. 풀린 세션에서 한 번이라도 울리면 임계값을 올린다(오탐 0 규칙). 결과 표를 스펙에 남긴다.
5. `tests/test_detectors.py`, `tests/test_gate.py`, `tests/test_agent.py`(ScriptedLLM 흐름), `tests/test_replay.py`(픽스처 transcript)에 테스트를 쓴다.
6. `README.md`의 "루프가 막는 것" 단락과 `signals` 설명을 갱신한다.

### (c) 플레이북 문구 수정
1. `revagent/prompts/system.md`만 고친다. 모델에게 그대로 보이는 텍스트이므로 규칙 번호와 절 구조를 유지한다. 문제 이름을 쓰지 않는다(내용 무관 원칙은 프롬프트에도 적용된다; 스펙은 "클래스 규칙"으로 쓴다).
2. `tests/test_agent.py`의 `test_playbook_*` 테스트가 특정 문구를 확인한다. 바꾼 문구가 걸리면 테스트를 함께 고친다.
3. 이미지 안 코드로 돌리려면 `bash scripts/sandbox-build.sh`(마지막 레이어만 다시 빌드). 먼저 `--dev`로 시험한다.
4. 스펙 파일 끝의 "수정 이력" 절에 무엇을 왜 바꿨는지 한 줄 남긴다.

### (d) 모델/서버 바꾸기
1. `~/.revagent/.secure`의 `QWEN`(API 키), `URL`(서버 루트; `/v1`은 `llm.py`가 붙인다), `MODEL`(모델 ID)을 바꾼다. 환경변수 셋으로도 된다.
2. 컨텍스트 창이 달라지면 `context.THRESHOLD`(44,000)와 `llm.DEFAULT_MAX_TOKENS`(16,384)의 합이 서버 `max_model_len` 아래여야 한다.
3. thinking을 다르게 쓰려면 `LLM.__init__`의 `reasoning_effort`, `temperature`, `retries`, `stream`을 본다. 서버가 `reasoning_effort`를 `extra_body`로 받지 않으면 `_create`를 고쳐야 한다. 응답의 reasoning 키가 다르면 `parse_assistant`/`collect_stream`이 `reasoning_content`와 `reasoning` 둘을 이미 본다.
4. 프록시가 없어 스트리밍이 필요 없으면 `stream=False`도 동작한다(테스트용 경로).
5. `tests/test_llm.py`를 돌린다(서버 불필요).

### (e) 이미지 다이어트 / 패키지 추가
1. `docker/Dockerfile`은 레이어 순서가 캐시를 결정한다: apt 도구 → libssl1.1 → radare2 → JDK → Ghidra → pip 스택 → wine/Xvfb/OCR/mingw → Ghidra 검증 → `COPY . /app`. 앱 코드는 마지막이라 코드 수정은 마지막 레이어만 다시 빈다.
2. 패키지를 더하려면 해당 apt 줄이나 pip 줄에 버전을 고정해서 넣는다. 그 뒤 레이어는 전부 재빌드된다.
3. 줄이려면 Dockerfile 주석의 결정을 먼저 읽는다: jmods/man 제거, Ghidra docs/GhidraServer/dbgeng/`*-src.zip` 제거, mingw는 posix 모델만, wine prefix는 빌드 시 생성(시작 시간 때문). 32-bit wine은 비용(~1 GB) 때문에 넣지 않았다(`.superpowers/sdd/2026-09-20-pe-stage/progress.md`).
4. `bash scripts/sandbox-build.sh`가 빌드 후 스모크 테스트(Python 스택 import, gcc -m32, wine 콘솔 PE, run_gui OCR, PE32 거부)를 돌리고 이미지 크기를 찍는다.

## 7. 테스트 지도

`~/.revagent-venv/bin/python -m pytest`. 서버·도커·Ghidra 없이 돈다(`tests/conftest.py`의 `FakeLLM`, `test_agent.py`의 `ScriptedLLM`, subprocess monkeypatch). `tests/test_trace_vm_loop.py`만 `bench/mini/vm_loop`이 빌드돼 있고 qemu가 있을 때 돈다. 테스트 함수는 16개 파일에 389개다.

| 파일 | 지키는 것 |
|---|---|
| `tests/test_agent.py` | 루프 종료 조건(스텝·시간·무도구 3회), 압축 발동과 WORK FILES, 출력 잘림 재시도, 비평가 트리거, G3 차단→해제 흐름, G4 1회 경고, `signals`, runbook 종료, CLI 모드(`--host`/`--dev`/`--ask`/CA), console.log, ANSWERS.md 강등, 플레이북 필수 문구 |
| `tests/test_bench.py` | `check_answer`: 일치·불일치·행 없음·파일 없음 |
| `tests/test_casefile.py` | case.md 생성, 섹션 추가·교체, 가짜 헤더가 경계를 깨지 않음 |
| `tests/test_context.py` | 머리/꼬리 분할, 직렬화 캡, 요약→Log/Todo, `prune_log`가 원장 줄을 보존, `shrink_casefile`의 거부 조건, WORK FILES 목록 |
| `tests/test_critic.py` | 진행 마커, 최근 교환 렌더, low effort·4096 토큰, 6줄 캡, 원장 한 줄씩, 실패 시 None |
| `tests/test_detectors.py` | heredoc/`python3 -c` 추출, 정규화, 200자 접두·Jaccard 0.6, 임계값 상수가 스펙 값 |
| `tests/test_emulate.py` | SysV/Win64 인자, hex 버퍼 반환, out_lens, 스택 인자, FS/GS 0, import 정지 보고, 명령 상한, PIE ELF 0x100000 로드, 버퍼 넘침이 다음 버퍼로 새지 않음 |
| `tests/test_gate.py` | 4번째 차단, 다른 도구가 스트릭 리셋, 3스텝 자동 해제 + 냉각, 한 스텝 안 부분 차단, 예외 시 전부 허용 |
| `tests/test_ghidra.py` | FunctionDB 조회·정렬·필터, 캐시 원자성·손상 캐시 무효화, 타임아웃 시 프로세스 그룹 kill, 프로젝트 경로에 `.` 없음, `calls_no_imports` |
| `tests/test_llm.py` | `.secure` 탐색 순서, 스트림 접기, 끊긴 스트림 재시도, 401 비재시도, ContextOverflow, usage 집계, SDK 재시도 0, `complete()` 예산 일회성 |
| `tests/test_replay.py` | 픽스처 transcript(basic pefile 루프 9·10·11 차단, multipoint 변형은 0회), 오탐 시 종료 코드 1, `(gated)` 면제 |
| `tests/test_sandbox.py` | docker 명령 조립(마운트·env 이름만·caps·dev·CA), `check_docker` 문구, entrypoint 문법, 스트리밍 출력 |
| `tests/test_tools.py` | 열두 도구 각각의 스키마·정상 경로·오류 문구·경로 탈출 거부·원장 줄·타임아웃 클램프; `submit_flag` 증거 규칙; `solve_check` sat/unsat/비기호 줄/시간 제한; `emulate`/`trace_run` 도구 텍스트 |
| `tests/test_trace.py` | qemu 로그 파서, 베이스 판별, Ghidra 환산, 영역 분류, 반복 접기, 요약 형식 |
| `tests/test_trace_vm_loop.py` | 실제 qemu로 `vm_loop`을 추적해 핸들러가 바이트코드 순서로 나오고 반복이 접히는지 |
| `tests/test_truncate.py` | 12,000자 경계, `[env]` 꼬리말 보존, 가짜 `[env]` 줄은 보존 대상이 아님 |

## 8. 알려진 한계와 다음 일

**못 푼 문제 유형** (README 벤치 표 기준, 실전 7문제 중 4문제 해결):
- captain-hook(Windows GUI, 화면에 한 글자씩 그리는 스트림): 10회 실행 모두 실패. run9·run10은 검증 규칙을 형식으로만 채운 오답 제출이었고 ANSWERS.md 대조로 잡았다. 스트림이 무엇인지(중첩 바이너리) 묻는 단계가 없었다. trace-run spec §7은 이 유형을 별도 `carve` 도구(중첩 바이너리 탐지)로 다루겠다고만 적었다.
- ROVM·damnida(인터프리터/VM): 구조는 복원하지만 해석되는 프로그램을 끝내 못 읽었다. `trace_run`이 이 지점을 겨냥하며, `bench/mini/vm_loop`에서만 검증됐다. 두 문제의 `trace_run` 라이브 결과는 이 문서 시점에 README 벤치 표에 없다.
- basic run2 유형: 매번 다르게 쓴 z3 스크립트가 전부 unsat인 실패는 G3(유사 스크립트)에 잡히지 않고, 잡는 임계값은 multipoint에서 오탐을 낸다. 다음 후보 신호는 "연속 스크립트가 같은 결과 문자열로 끝남"(transition-rules spec §8).

**모델 크기의 천장**: 27B AWQ INT4, 64k 컨텍스트. G4의 effort 하향은 생각을 줄이지 못했다. 해결 세션 7개 중 4개가 20스텝 미만의 mini 벤치라 게이트 임계값의 표본이 작다(spec §2.8).

**범위 밖으로 남긴 것** (각 스펙 §7/§9):
- 오케스트레이터/워커 분리, 비평가 모델 교체, 비평가 프롬프트 재설계.
- `emulate`의 libc 스텁·syscall, 다른 아키텍처(ARM/MIPS) 함수 단위 에뮬레이션.
- `trace_run`의 레지스터/메모리 값 추적, PE 추적(wine 밑 qemu 불가), 두 trace의 diff(모델이 `bash diff`로 한다).
- 사람이 실행하고 관찰을 돌려주는 대화형 런북.
- 32-bit PE 실행(wine64만; PE32는 `[cannot run here]`), Windows 드라이버·.NET·DirectX, 강한 안티디버깅.
- APK/.NET/pyc 전용 도구.

**보류(Parked) 항목** (`.superpowers/sdd/*/progress.md`):
- wine32 레이어(~1 GB): 32비트 문제가 나타나면.
- `file`이 실패하면 64비트 PE를 32비트로 오판할 수 있음: MZ 헤더의 machine 필드로 게이트하는 수정은 미룸.
- `decompile`의 `limit`이 int로 강제 변환되지 않음(`[tool error] bad arguments`로 한 스텝 소모).
- `list_text` 헤더가 필터된 개수를 보고함(외관).
- Ghidra 미설치 같은 환경 오류도 세션 동안 음성 캐시됨.
- `find_image_base`가 가장 낮은 일치 매핑을 택함; `lib?` 판별이 정확한 (start, end) 키; 잘린 마지막 layout 블록은 `[other]`; `top=0` 헤더.
- `trace_run`은 `submit_flag.READING_TOOLS`에 넣지 않았다(주소를 주는 도구이고 표시된 플래그의 읽기가 아니라는 판결).

## 9. 포트폴리오로 말할 때

- 자체 호스팅 27B 모델 하나로 Dreamhack 실전 리버싱 7문제 중 4문제(multipoint, revlogin, relativity, basic)를 사람 개입 없이 풀었다. 근거: `README.md` 벤치 표의 해당 행(스텝 수, 분, 토큰이 함께 있다).
- 개입 규칙을 감으로 정하지 않고 보유 transcript(해결 7세션, 미해결 15세션)에 리플레이해 풀린 실행에서 오탐 0인 임계값만 채택했고, 탈락한 후보와 그 수치도 남겼다. 근거: `docs/superpowers/specs/2026-09-21-transition-rules-design.md` §8, `scripts/replay_detectors.py`, `revagent/detectors.py`의 상수.
- 도구는 실패한 실행 하나하나에 대응한다: `emulate`는 basic 두 번의 실패(forward 모델을 확인할 오라클 부재), `trace_run`은 ROVM·damnida(핸들러를 읽어도 실행 순서를 모름), `run_gui`는 captain-hook(PE를 돌릴 수 없음). 근거: 각 스펙의 "1. 배경과 문제"와 README 벤치 표의 basic run3 행(`emulate` 호출 스텝과 일치 스텝이 적혀 있다).
- 결과를 스스로 채점한다: `ANSWERS.md` 대조가 오답 제출을 `wrong`으로 강등하고(captain-hook run10, win_gui_key run1이 이렇게 잡혔다), `results.jsonl`이 모든 실행을 남기며, README 벤치 표는 실패 행을 지우지 않았다. 근거: `revagent/__main__.py:check_answer`, `agent._finish`.
- 재현 가능한 실행 환경: 버전을 고정한 `docker/Dockerfile`, 자격증명을 argv에 싣지 않는 `sandbox.run_sandbox`, 자식 프로세스에서 비밀을 지우는 `bash.SCRUB_ENV`, 서버 없이 도는 389개 테스트. 근거: `docker/Dockerfile` 주석, `tests/`.
