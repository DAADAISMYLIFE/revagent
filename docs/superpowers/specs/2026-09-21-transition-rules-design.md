# 전환 규칙 설계 (결정적 감지기 + 차단형 개입 + solve_check)

## 1. 배경과 문제

실패한 실행의 transcript를 추상화하면 지식 부족이 아니라 **전환 실패**가 반복된다. 같은 산출물을 조금씩 고치며 맴돌고(ROVM 에뮬레이터 7회, relativity gdb 덤프 7회, basic 역변환 스크립트 16회), 머릿속에서 긴 추론을 하며(reasoning 2만 자 스텝), 관찰이나 다른 표현으로 넘어가지 않는다. relativity 4회차의 결정타는 "미지수 하나로 줄인 뒤 실제 바이너리에 물어본 것"이었다.

처음 가설은 셋이었다. (a) 노트를 안 써서, (b) 관찰 없이 스크립트만 써서, (c) 같은 스크립트를 반복 수정해서. 이걸 보유한 transcript 전부(해결 7세션, 미해결 15세션, 서버 오류로 죽은 3세션)에 대해 리플레이해 보니 **(a)와 (b)는 해결된 실행에서도 똑같이 나타났다.** multipoint와 mini 벤치 넷은 Facts 0줄로 풀었고, revlogin은 제출 직전 17스텝 연속 스크립트였다. 둘은 실패의 원인이 아니라 이 모델의 평소 습관이다. (c)만 해결/미해결을 갈랐고, 측정 중에 하나가 더 나왔다. 8천 자 넘는 reasoning 스텝의 **횟수**다(해결 최대 4회, 미해결 5~25회). 자세한 수치는 §8.

## 2. 결정 사항

1. **내용 무관 원칙.** 감지기와 개입은 문제 이름·바이너리 성질·특정 문자열을 언급하지 않는다. 입력은 transcript에서 관측 가능한 것뿐이다: 도구 이름, 스크립트 본문 유사도, reasoning 길이, 스텝 수.
2. **결정적·리플레이 가능.** 감지기는 메시지 목록의 순수 함수다. 채택 전에 과거 transcript 전부에 대해 "어느 스텝에서 울렸을지"를 계산한다. LLM 판단(비평가)은 리플레이가 안 되므로 이 스펙의 대상이 아니다.
3. **채택 기준.** 해결된 실행에서 오탐 0(또는 실행당 1회 이하)이면서 서로 다른 문제 셋 이상의 미해결 실행에서 울려야 한다. 이 기준으로 (a)(b)는 탈락, (c)와 긴 생각 횟수만 채택.
4. **개입 강도.** 차단형을 기본으로 한다. 감지되면 그 호출을 실행하지 않고 `[blocked by G3] ...`로 이유와 요구 행동을 돌려준다. 생각 길이는 차단할 대상이 없으므로 예외적으로 "한 번 경고 + 남은 실행의 reasoning_effort 하향"으로 개입한다. 강제형(루프가 대신 도구 호출)은 쓰지 않는다.
5. **교착 방지.** 같은 게이트가 연속 3스텝 차단하면 스스로 열리고 이벤트를 남긴다. 차단이 실행을 죽이는 일은 없다.
6. **도구로 메우는 능력 결손.** "C를 z3 제약으로 옮겨 뒤집기"는 모델이 반복해서 못 하는 단일 작업이라 규칙이 아니라 도구(`solve_check`)로 준다.
7. **탈락한 신호도 지표로는 남긴다.** Facts 첫 기록 스텝은 result.json `signals.first_facts_step`에 기록만 한다. 관찰 없는 스크립트 연속 길이는 "bash가 대상 바이너리를 실행했는지"의 판정이 정의되지 않아 지금은 기록하지 않고 보류한다(§3.1). 데이터가 쌓여 판단이 바뀌면 그때 게이트로 올린다.
8. **검증 데이터의 한계를 명시한다.** 해결 세션 7개 중 4개가 20스텝 미만의 mini 벤치다. 임계값은 이 작은 표본에서 오탐 0인 값이지 일반 진리가 아니다. 새 실행이 끝날 때마다 리플레이를 다시 돌려 오탐이 생기면 임계값을 올린다(§3.4).

## 3. 구성 요소

### 3.1 감지기 (`revagent/detectors.py`, 순수 함수)

- **D3 `artifact_streak(messages) -> (length, start_step)`** — 연속된 `bash` 호출 중 스크립트 본문(heredoc 본문 또는 `python3 -c` 문자열, 공백 정규화)이 직전 것과 유사한 것의 연속 길이. 유사 = 앞 200자 동일 또는 줄 집합 Jaccard > 0.6. 유사하지 않은 bash, 다른 도구, notes는 스트릭을 끊는다.
- **D4 `long_reasoning_count(transcript) -> int`** — 이 세션에서 reasoning이 8,000자를 넘은 스텝의 누적 수. 루프는 매 스텝 `resp.reasoning` 길이로 갱신한다.
- **지표 전용** (§2.7): `first_facts_step` — result.json에 `signals` 항목으로 기록. `scripting_streak`(관찰 = run_binary/run_gui **또는** 대상 바이너리를 실행하는 bash)은 "대상 바이너리를 실행하는 bash"의 판정 기준이 정의되지 않아 **보류**하고 현재 기록하지 않는다(`signals`에는 gate_blocks·max_script_streak·long_reasoning_steps·first_facts_step만 있다).

### 3.2 게이트 (`revagent/gate.py`)

| 게이트 | 조건 | 개입 | 열리는 조건 |
|---|---|---|---|
| **G3 표현 전환** | D3 ≥ 4 | 유사한 `bash` 호출을 차단: `[blocked by G3] 같은 스크립트를 4번째 고치고 있다. 접근을 바꿔라: (1) 지금 모델의 출력을 실제 바이너리 출력과 비교, (2) forward 변환을 파이썬으로 쓰고 solve_check로 뒤집기, (3) 실패 이유를 notes에 적고 다른 가설.` | 유사하지 않은 스크립트, 다른 도구, `solve_check`, `notes` 중 하나 |
| **G4 생각 예산** | D4가 5에 도달 | 차단 없음. 사용자 메시지 한 번: `[gate] 8천 자 넘는 생각이 5번째다. 푼 실행은 4번을 넘긴 적이 없다. 머릿속 추적을 멈추고 스크립트로 옮겨라.` 이후 남은 스텝의 `reasoning_effort`를 `low`로 고정 | 실행 끝까지 유지 |

- 차단된 호출은 실행되지 않고 결과가 `[blocked by G3] ...`로 들어간다. 같은 스텝의 다른 호출은 정상 실행.
- 교착 방지: G3가 연속 3스텝 차단하면 자동 해제, 이후 10스텝 냉각기.
- 모든 발동·해제는 `_meta` 이벤트(`gate_block`, `gate_open`, `gate_released`, `gate_warn`)로 transcript에, `- [gate step N] ...` 원장 줄로 케이스 파일 Log에 남는다(비평가 줄과 같은 규칙으로 압축을 견딘다).
- G4의 effort 하향은 이 스펙에서 유일하게 모델 출력의 질에 손대는 개입이다. 리플레이로는 효과를 잴 수 없으므로(과거 실행은 medium이었다) 라이브 검증에서만 확인한다(§6). 효과가 없거나 나쁘면 경고만 남기고 하향은 뺀다.

### 3.3 `solve_check` 도구 (`revagent/tools/solve_check.py`)

- 입력: `file`(문제 폴더 기준 파이썬 파일), `target`(hex), `length`(입력 바이트 수), 선택 `charset`(정규식 문자 클래스, 예 `[ -~]`), 선택 `timeout`(기본 60초, `clamp_timeout` 적용).
- 파일은 `transform(x: list) -> list`를 정의한다. `x`는 길이 `length`의 리스트, 함수는 원소별 정수 연산(`+ - ^ & | << >>`, `% 256`, `& 0xff`), 리스트 인덱싱, 상수 테이블 조회만 쓴다.
- 도구는 `x`를 z3 `BitVec(8)` 리스트로 넣어 `transform`을 그대로 실행한다(연산자 오버로딩으로 제약이 쌓인다). 상수 테이블 조회는 도구가 주입하는 `Table(list)`이 ITE 체인으로 바꾼다. `transform(x) == target`과 charset 제약을 넣고 z3를 돌린다.
- 출력: 해가 있으면 hex와 printable, 없으면 `unsat`, 시간 초과면 그 사실. 기호 실행이 안 되는 코드(데이터 의존 분기, `int()` 캐스트, 심볼릭 값 위의 `range`)는 예외 줄 번호와 함께 "이 줄을 산술로 바꿔라"를 돌려준다.
- 적용 범위는 플레이북 3단계의 "Constraint / byte-wise"와 "Sequential / stateful" 클래스다. 해시·표준 암호에는 무의미하며 도구 설명에 그렇게 적는다.
- 검증 fixture: bench/mini/xor_check와 basic(chall9.exe)의 변환을 forward로 옮긴 파이썬. 도구가 정답 입력을 복원해야 한다.

### 3.4 리플레이 검증 (`scripts/replay_detectors.py`)

- transcript.jsonl 경로들을 받아 세션마다 D3/D4와 지표를 계산하고, 각 게이트가 울렸을 스텝을 표로 낸다. 감지기 코드는 루프와 같은 함수를 import한다(복제 금지). 현재 프로토타입은 `scripts/replay_detectors_prototype.py`(측정에 쓴 스크립트 원본)이며 구현 때 detectors.py를 쓰도록 교체한다.
- 기준 표본: quiz/*/.revagent/transcript.jsonl 전부 + bench/mini/*/.revagent/transcript.jsonl. 해결 세션의 발동 수가 0이어야 통과.
- 대표 구간(basic 6~11스텝의 pefile 재수정, multipoint 32~34스텝의 정상 추출 변형)을 `tests/fixtures/transcripts/`에 발췌해 회귀 테스트로 고정한다.
- 새 실행이 끝날 때마다 리플레이를 돌린다. 해결 실행에서 오탐이 생기면 임계값을 올리고 §8에 기록한다.

### 3.5 플레이북 변경 (`prompts/system.md`)

- Environment에 한 단락: `[blocked by G3]`는 도구 오류가 아니라 요구 행동이라는 것, `[gate]` 경고의 뜻, `solve_check`의 용도.
- 3단계 Constraint/Sequential 항목에 "forward 변환을 파이썬으로 옮긴 뒤 `solve_check`로 뒤집는다"를 첫 선택지로.
- 규칙 4("3번 실패하면 가설 변경")에 "같은 스크립트 4번째 수정은 루프가 막는다" 한 문장.

## 4. 데이터 흐름

```
스텝 시작 → LLM 응답(reasoning, tool_calls)
  → D4 갱신; 5 도달 시 경고 메시지 추가 + effort=low 고정
  → Gate.check(step, calls, messages)                # 순수 함수, 예외 시 전부 허용
  → 허용 호출 실행 / 차단 호출은 [blocked by G3] 텍스트
  → 결과 추가, _meta 이벤트, 원장 줄
  → (기존) 진행 판정, 비평가, 압축
```

## 5. 오류 처리

- 감지기·게이트는 예외를 밖으로 내지 않는다. 내부 예외는 `_meta gate_error`로 남기고 그 스텝은 전부 허용.
- `solve_check`: z3 없음 → `[tool error]`와 안내; 경로 오류 → 기존 `resolve_inside` 텍스트; 시간은 `ctx.clamp_timeout`으로 잘림.
- 게이트 오탐의 최대 비용은 3스텝(자동 해제). 게이트는 조언을 하지 않으므로 잘못된 방향을 제시할 수 없다.

## 6. 테스트

- `tests/test_detectors.py`: D3 경계(200자 접두, Jaccard, 끊는 조건), D4 누적.
- `tests/test_gate.py`: 차단 텍스트, 열림 조건, 3스텝 자동 해제와 냉각기, 예외 시 전부 허용, G4 한 번만 경고.
- `tests/test_agent.py`: ScriptedLLM으로 G3 차단→해제 흐름, G4 경고 후 effort=low가 chat에 전달되는지, `_meta`와 원장 줄, 차단 스텝은 진행 없음으로 세는지.
- `tests/test_tools.py`: `solve_check` 성공(xor_check, basic 변환)·unsat·기호 실행 불가 줄 번호·타임아웃·charset.
- `tests/test_replay.py`: fixture 발췌에 대한 리플레이 표 고정.
- 라이브: basic 1회(목표: G3가 pefile 루프에서 울리고 solve_check로 풀리는지), relativity 1회(회귀: 4회차와 같은 케이스 파일로 시작해 게이트가 울리지 않고 풀리는지).

## 7. 범위 밖

- 관찰만 반복하며 막히는 GUI/프록시 DLL 세션(captain-hook archive 4개). 이번 감지기 셋은 이 실패 모드를 못 본다.
- 비평가 프롬프트 재설계(basic, relativity 4회차에서 틀린 조언).
- 압축 스래싱, 12스텝 넘은 도구 결과 스텁, 강제형 개입.

## 8. 리플레이 결과와 확정 임계값

표본: 해결 7세션(relativity 4회차, multipoint, revlogin 2회차, mini 4개), 미해결 15세션(basic, relativity 1회차, captain-hook 현재 + archive 9개 중 유효분, damnida, ROVM 콘솔 로그), 서버 오류 종료 3세션. captain-hook의 "solved" 두 세션은 오답 제출이라 미해결로 분류.

| 규칙 | 임계값 | 해결 세션 오탐 | 미해결 세션 검출 | 판정 |
|---|---|---|---|---|
| Facts 강제 (N스텝) | 6 / 8 / 10 | 7/7 · 6/7 · 6/7 세션 | 13/15 | **탈락** — 갈라내지 못함 |
| 스크립트 연속 (K) | 4 / 5 / 6 | 6/7 · 3/7 · 2/7 세션, 10 · 5 · 4회 | 12 · 11 · 10 /15 | **탈락** — 오탐이 전부 풀이 구간 |
| 같은 스크립트 재수정 (T) | 3 | 1/7 (multipoint 34스텝, 1회) | 8/15 | 보류 |
| 같은 스크립트 재수정 (T) | **4** | **0/7** | 4/15 (basic, captain-hook archive 1·2, damnida) | **채택** |
| 긴 생각 횟수 (8천 자 초과 스텝) | **5회째** | **0/7** (해결 최대 4회) | basic 5, captain-hook 16, relativity 1회차 25, damnida 14, archive 9~17 | **채택** |

확정값: D3 유사도 = 앞 200자 동일 또는 Jaccard > 0.6, T = 4. D4 = 8,000자, 5회째. 자동 해제 3스텝, 냉각 10스텝. 200자 접두를 100자로 줄이면 basic 검출이 16스텝 연속으로 늘지만 T=3에서 오탐 3회가 생기므로 이번엔 200자로 두고 다음 리플레이에서 재검토한다.

### 구현 후 리플레이 (실제 Gate 코드)

`scripts/replay_detectors.py`가 루프와 같은 `Gate`(revagent/gate.py)와 `LONG_REASONING_*`(revagent/detectors.py)를 import해 계산한 결과. 세션 상태는 bench와 같은 `check_answer`(revagent/__main__.py)로 교차 검증한다: `end.status`가 `solved`인데 flag가 `<챌린지 디렉터리>/../ANSWERS.md`의 행과 다르면 `wrong`. 리플레이는 답 대조를 챌린지 디렉터리 이름으로 찾기 때문에, 아래 표는 `quiz/ANSWERS.md`에 `| captain-hook.archive-pre-ladder | DH{H0000KER} |` 행(2026-09-21 추가)이 있어야 그대로 재현된다. 실행:

```bash
~/.revagent-venv/bin/python scripts/replay_detectors.py /mnt/c/Users/강순우/Documents/vs/rev/quiz/*/.revagent/transcript.jsonl /mnt/c/Users/강순우/Documents/vs/rev/quiz/captain-hook.archive-pre-ladder/transcript.jsonl bench/mini/*/.revagent/transcript.jsonl
```

| transcript | session | status | steps | G3 blocks at | released at | max streak | long-thinking steps | G4 at |
|---|---|---|---|---|---|---|---|---|
| basic | 1 | unsolved | 32 | [9, 10, 11, 32] | [11] | 6 | 5 | 30 |
| captain-hook | 1 | wrong | 191 | - | - | 3 | 16 | 99 |
| damnida | 1 | incomplete | 237 | [49, 107, 108, 145, 146, 203] | - | 5 | 14 | 118 |
| multipoint | 1 | solved | 48 | - | - | 3 | 4 | - |
| relativity | 1 | unsolved | 0 | - | - | 0 | 0 | - |
| relativity | 2 | unsolved | 0 | - | - | 0 | 0 | - |
| relativity | 3 | unsolved | 107 | - | - | 3 | 25 | 37 |
| relativity | 4 | incomplete | 3 | - | - | 0 | 0 | - |
| relativity | 5 | unsolved | 43 | - | - | 2 | 4 | - |
| relativity | 6 | unsolved | 85 | - | - | 3 | 16 | 38 |
| relativity | 7 | solved | 38 | - | - | 1 | 4 | - |
| revlogin | 1 | unsolved | 56 | - | - | 3 | 0 | - |
| revlogin | 2 | solved | 70 | - | - | 2 | 3 | - |
| captain-hook.archive-pre-ladder | 1 | unsolved | 95 | [24, 29, 30, 48, 49, 55] | - | 5 | 14 | 70 |
| captain-hook.archive-pre-ladder | 2 | incomplete | 197 | [48] | - | 4 | 16 | 90 |
| captain-hook.archive-pre-ladder | 3 | incomplete | 120 | - | - | 3 | 12 | 70 |
| captain-hook.archive-pre-ladder | 4 | unsolved | 138 | - | - | 2 | 17 | 54 |
| captain-hook.archive-pre-ladder | 5 | incomplete | 36 | - | - | 1 | 2 | - |
| captain-hook.archive-pre-ladder | 6 | incomplete | 62 | - | - | 2 | 4 | - |
| captain-hook.archive-pre-ladder | 7 | incomplete | 103 | - | - | 2 | 9 | 88 |
| captain-hook.archive-pre-ladder | 8 | incomplete | 75 | - | - | 2 | 6 | 70 |
| captain-hook.archive-pre-ladder | 9 | incomplete | 25 | - | - | 1 | 2 | - |
| captain-hook.archive-pre-ladder | 10 | wrong | 89 | - | - | 2 | 9 | 54 |
| win_console | 1 | solved | 8 | - | - | 1 | 0 | - |
| win_gui | 1 | solved | 9 | - | - | 1 | 0 | - |
| win_gui_32 | 1 | solved | 17 | - | - | 1 | 0 | - |
| win_gui_key | 1 | solved | 12 | - | - | 1 | 0 | - |

- 종료 코드 **0**. 해결 7세션(multipoint, relativity 7회차, revlogin 2회차, mini 4개)은 G3·G4 모두 0회 — 측정 표와 일치. 상수는 바꾸지 않았다.
- `wrong` 두 행(captain-hook 현재 1세션, archive 10세션)은 transcript의 `end.status`가 `solved`이지만 ANSWERS.md와 flag가 다른 오답 제출로, 위 측정 표에서 미해결에 분류한 그 두 세션이다. 둘 다 G3가 아니라 G4(긴 생각 5회째, 99·54스텝)만 울렸다.
- 미해결 검출: G3는 basic(9·10·11 차단 → 11에서 해제, 냉각 21까지, 32에서 재차단), damnida, archive 1·2세션; G4는 basic 30, damnida 118, relativity 3·6회차, archive 다수.
- 회귀 고정: `tests/fixtures/transcripts/pefile_loop.jsonl`(basic 1~16스텝: 9·10·11 차단, 11 해제)과 `extractor_variants.jsonl`(multipoint 28~36스텝: 차단 0, G4 없음), `tests/test_replay.py`.

### 라이브 검증 (2026-09-21 저녁, 이미지 재빌드 후)

| 실행 | 결과 | 스텝 / 분 | signals | 비고 |
|---|---|---|---|---|
| basic 2회차 (케이스 파일 새로, `--max-minutes 15`) | **unsolved** | 32 / 15.5 | gate_blocks 0, max_script_streak 3, long_reasoning_steps 4, first_facts_step 28 | G3·G4 모두 임계값에 하나 모자라 안 울림. 모델은 z3 스크립트를 스스로 10번 썼지만 forward 모델이 틀려 전부 unsat; `solve_check`는 한 번도 부르지 않음. 오탐 없음 |

basic 2회차를 잡을 수 있는 임계값이 있는지 전 세션에 다시 재 봤다(접두 100/150/200자 × Jaccard 0.4/0.5/0.6). 접두 100자로 낮추면 basic 2회차가 스트릭 4로 걸리지만 **multipoint(해결)도 5로 걸려 오탐**이 생긴다. 접두 150자는 basic 2회차를 못 잡는다(3). 즉 §2.3 기준(해결 세션 오탐 0)을 만족하면서 basic 2회차를 잡는 값은 없다. 임계값은 그대로 둔다. 이 실행이 보여준 실패 모양은 "비슷한 스크립트 반복"이 아니라 "매번 다르게 쓴 z3 모델이 전부 unsat"이라, 다음 후보 신호는 "연속된 스크립트가 같은 결과 문자열(예: unsat/Traceback)로 끝남"이다. 데이터가 더 쌓이면 §2.3 기준으로 검토한다.

### 구현 중 변경 (2026-09-21)

- 지표 전용 신호 중 `signals`에 기록되는 것은 `first_facts_step`뿐이다. 관찰 없는 스크립트 연속(`scripting_streak`)은 "대상 바이너리를 실행하는 bash"를 가려낼 기준이 없어 구현하지 않고 보류한다(§2.7, §3.1).
