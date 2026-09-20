# 증거 사다리·비평가·런북 설계 (observe-first stage)

작성: 2026-09-20. 대상 저장소: `revagent` (`feat/pe-stage` 위에 이어서 작업).

## 1. 배경과 문제

captain-hook(Windows GUI, 클릭마다 글자 하나를 그리는 PE)에서 에이전트는 8회 run, 약 700스텝을 썼고 마지막 제출도 오답이었다. 로그를 되짚어 확인한 원인은 네 가지다.

0. (2026-09-20 추가) captain-hook의 정답은 `DH{H0000KER}`였다. 화면의 hex 스트림(18 432자)은 파일 오프셋 0x1E1F0에 PRNG XOR로 암호화된 내부 UPX PE였고, 그 PE를 실행하면 플래그가 그려진다. 에이전트는 '스트림 = 플래그'로 가정했고 글자 집합도 정하지 않았다. 아래 원인 4개에 더해 **'보이는 것이 무엇인지'를 묻지 않은 것**이 다섯 번째 원인이다.
1. **증거 서열이 없다.** 플레이북 절차가 triage → 검사 위치 찾기 → 분류라는 정적 파이프라인이고, 동적 관찰은 5절에 부록처럼 있다. 에이전트는 디컴파일을 진실로, 화면을 "wine이 이상함"으로 취급했다. 자기가 설치한 프록시 DLL이 렌더링을 망가뜨린 것도 도구 탓으로 돌렸다.
2. **출력형 플래그의 검증 기준이 없다.** 규칙 2("성공 메시지 또는 재구현")는 입력 검사형 문제용이다. 프로그램이 플래그를 *보여주는* 문제에는 성공 메시지가 없어서, 에이전트는 자기 로그를 자기가 검증하고 제출했다. 실제 오류는 글리프 두 개 오독(D→K, A→8)이었고, 글자 집합(hex 16자)을 먼저 정했다면 K는 불가능했다.
3. **관찰이 기억에 남지 않는다.** "클릭하면 글자가 바뀐다"를 두 번 관찰했지만 Facts에 적지 않아 압축 뒤 사라졌고, 다음 run은 다시 정적 분석으로 돌아갔다.
4. **막힘을 스스로 보지 못한다.** 같은 접근을 압축 4회 이상 반복해도 "무엇이 안 되고 있나"를 묻는 단계가 없다. 그 역할을 사람이 run 중단·재시작으로 대신했다.

이 설계는 GUI에 한정하지 않고 "실행해서 봐야 하는" 모든 유형(인터랙티브 콘솔, 안티디버깅, 런타임 언패킹, 네트워크)에 같은 장치를 적용한다.

## 2. 결정 사항

- 루프 구조(단일 ReAct, 압축, 케이스 파일)는 유지한다. 네 지점에 장치를 추가한다.
- 막힘 감지는 **비평가 호출**(같은 Qwen, 역할 분리)로 한다. 오케스트레이터/워커 분리는 이 설계가 부족하다는 증거가 생길 때 다시 검토한다.
- 사람 손이 필요한 절차(런북)는 **환경이 실행하지 못한다는 도구 증거가 있을 때만** 허용한다. "막혔다"는 이유로는 허용하지 않는다.

## 3. 구성 요소

### 3.1 증거 사다리 (플레이북, `revagent/prompts/system.md`)

- 절차 1단계(Triage)에 추가: "실행 가능한 바이너리는 triage 안에서 한 번 실행·관찰한다(`run_binary` 또는 `run_gui`). 관찰 결과의 결론을 Facts에 적는다."
- 새 규칙(번호 11): **증거 사다리.** 관찰(실행 출력, 화면, 디버거 값) > 트레이스/로그 > 디컴파일/디스어셈블 > 추론. 상위 증거와 하위 증거가 충돌하면 상위가 이긴다. 관찰이 이상하면 도구 탓을 하기 전에 "내가 환경을 바꿨나(DLL 교체, 잔여 프로세스, 패치)"를 먼저 의심하고 깨끗한 상태에서 한 번 더 관찰한다.
- 규칙 8(그래픽 플래그) 개정: 순서를 "먼저 화면·캡처에서 읽는다 → 안 될 때 좌표 추출·래스터"로 뒤집고, 다음을 추가한다. "글리프를 분류하기 전에 문자 집합을 정한다(그리기 루틴 개수, 게이트 상수 범위, 설명의 힌트). 문자 집합에 없는 글자로 읽혔다면 오독이다. 표준 폰트와 획이 다르면 대안 문자를 병기하고 두 번째 경로로 확정한다."
- 규칙 2(검증) 개정: 출력형 플래그의 검증 기준을 3.4와 같이 명시한다.
- 규칙 11에 한 문장 추가: "관찰은 정적 분석을 대체하는 것이 아니라 방향을 정한다. 지금 보이는 것이 *무엇인지*(문자 집합, 바이트 스트림, 상태 기계)를 관찰로 확정한 뒤, 그것을 얻는 가장 싼 길(정적 복호화, 로그, 에뮬레이션)을 고른다." captain-hook의 실제 답은 18 432번 클릭이 아니라 관찰로 '내부 PE의 hex dump'임을 확정한 뒤 정적으로 복호화하는 것이었다.
- 절차 3(분류)에 항목 추가 **중첩 바이너리**: "프로그램이 내는 바이트 스트림(hex, base64, 비트맵, 화면의 글자열)은 디코드해서 파일로 저장하고 `file`/매직(MZ, ELF, UPX, PK)으로 식별한다. PE/ELF면 2단계 문제다: 같은 절차(triage → 관찰 → 분류)를 그 파일에 다시 적용한다. 스트림이 길면 끝까지 관찰하지 말고, 관찰로 인코딩을 확정한 뒤 소스(파일 오프셋, 복호화 루틴)에서 통째로 뽑는다."

### 3.2 관찰 원장 (도구 쪽)

- `ToolContext.observe(line: str)`: 케이스 파일 Log 섹션에 `- [obs step N] <line>` 한 줄을 추가한다. `N`은 현재 스텝(agent가 ctx에 `step` 값을 갱신).
- 호출 지점: `run_binary`(exit code, stdout 첫 줄, stderr 요약, `[cannot run here]` 여부), `run_gui`(창 목록, window content, 입력 개수, 변화 있음/없음 개수, NOT DELIVERED 개수, 캡처 번호 범위).
- 형식 예: `- [obs step 22] run_gui CaptainHook.exe click×12: 5 changed / 7 unchanged; windows: CaptainHook; content 3057 px`
- 보존: `prune_log`는 `[obs` 줄을 (a) FACTS와 같은 등급으로 남긴다. `shrink_casefile` 프롬프트에 "`[obs …]` 줄은 삭제하지 말고 병합만 한다"를 추가한다.
- 에이전트의 `notes` 호출과 독립이다. 에이전트가 잊어도 남는다.

### 3.3 비평가 (`revagent/critic.py`)

- 트리거 (둘 중 하나):
  (a) 압축 직전(`compact` 호출 전).
  (b) 최근 `CRITIC_IDLE_STEPS = 12` 스텝 동안 케이스 파일의 Facts 섹션과 원장(`[obs`)에 새 줄이 없을 때. 발동 후 카운터를 초기화하고, 같은 run에서 최대 `CRITIC_MAX = 8`회.
- 입력: 케이스 파일 전문 + 최근 12스텝의 (도구 호출 인자 200자, 결과 앞 300자).
- 프롬프트 요지(고정 질문 4개): ① 현재 계획(Todo 첫 항목)과 모순되는 관찰이 있는가? ② 같은 접근이 반복되고 있는가, 몇 번째인가? ③ 가장 싸고 결정적인 다음 실험 하나는 무엇인가(도구 호출 형태로)? ④ 환경이 이 바이너리를 실행하지 못한다는 도구 증거가 있는가(있으면 인용, 없으면 "없음")?
- 출력: 5줄 이내. 다음 턴에 `[critic]` 접두어의 user 메시지로 주입하고, 케이스 파일 Log에 `- [critic step N] …`로 남긴다.
- 호출 설정: `reasoning_effort="low"`, `max_tokens=4096`. 실패(예외, 잘림)는 무시하고 루프를 계속한다.
- 비평가는 지시가 아니라 질문에 답한 메모다. 에이전트가 따를 의무는 없지만, 플레이북에 "비평가 메모가 실험을 제안하면 그 실험을 먼저 한 뒤 반박하라"를 넣는다.

### 3.4 출력형 플래그 검증 (`revagent/tools/submit_flag.py`)

- 파라미터 추가: `evidence` (enum) — `program_accepted` | `two_independent_readings` | `reimplementation_matches`. `how_verified`는 유지.
- 규칙: `two_independent_readings`일 때 `how_verified`는 **방법이 다른** 두 경로를 각각 한 문장으로 적어야 한다(예: "① 실제 클릭 후 캡처 diff를 래스터해서 읽음 ② 게이트 상수가 0..15 순열이라 hex 알파벳, 로그 좌표로 재구성"). 도구는 문장 수(줄바꿈 또는 `①②`/`1)2)` 구분자로 두 항목)만 기계적으로 검사하고, 하나뿐이면 `[rejected] second independent reading required: …`로 돌려보낸다. 내용의 독립성은 플레이북이 요구한다(같은 글리프→문자 표를 두 번 쓰는 것은 독립이 아니다).
- 플래그 정규식 검사와 `[accepted]` 동작은 그대로. 거부는 스텝을 소모할 뿐 run을 끝내지 않는다.

### 3.5 런북 결과 (`revagent/tools/handoff_runbook.py`)

- 도구 시그니처: `handoff_runbook(steps: list[str], expected_observation: str, flag_rule: str)`.
- 게이트(코드): `ctx.env_blocked`가 참일 때만 허용. `env_blocked`는 이번 run에서 `run_binary`/`run_gui`가 `[cannot run here]`를 반환했거나, 실행이 시작 직후 실패(exit code ≠ 0 이고 stdout 비어 있음이 2회 이상, 또는 `run_gui`에서 창이 한 번도 안 뜸이 2회 이상)했을 때 도구가 세운다. 게이트가 닫혀 있으면 `[rejected] the sandbox can run this program (see obs …); continue by observation`를 반환한다.
- 출력 파일 `.revagent/runbook.md`: 번호 매긴 절차, 각 단계에서 무엇을 어디서 보는지, 읽은 것을 플래그로 바꾸는 규칙, 맨 위에 `UNVERIFIED — 에이전트가 실행하지 못한 환경` 표시.
- 종료 상태: 세 번째 결과 `RUNBOOK`. `solve`는 `RUNBOOK: .revagent/runbook.md`를 출력하고 종료, `bench` 표와 README 표에 `runbook` 상태를 추가한다.
- 플레이북: "런북은 마지막 수단이다. 환경이 못 돌린다는 도구 메시지가 없으면 호출하지 마라. 호출 전에 정적 분석으로 알 수 있는 모든 것(입력 형식, 진행 이벤트, 글자 집합, 길이)을 절차에 담아라."

## 4. 데이터 흐름

```
step N: tool call → tool result
        └─ run_binary/run_gui → ctx.observe(...) → case.md Log "[obs step N]"
agent loop: after each step
        ├─ idle counter (no new Facts/obs lines) ≥ 12 → critic → "[critic]" user msg + Log
        └─ prompt tokens ≥ THRESHOLD → critic → compact (Log keeps [obs]/[critic])
submit_flag(evidence=two_independent_readings, how_verified="① … ② …") → accept / reject
handoff_runbook(...) → env_blocked ? write runbook.md, end RUNBOOK : reject
```

## 5. 오류 처리

- 비평가 호출 실패: 조용히 건너뛰고 Log에 `- [critic step N] (failed: …)` 한 줄.
- `observe`가 케이스 파일을 못 쓰면(권한, 잠금) 도구 결과 끝에 `(observation not recorded)`를 붙이고 계속.
- `submit_flag` 거부는 최대 3회까지 같은 플래그를 반복 제출하면 4회째에 `[rejected] same flag 3× — change approach`를 반환한다(플래그 스팸 방지).
- `env_blocked`는 run 안에서만 유효하다(케이스 파일에 저장하지 않음). 새 run은 다시 관찰부터 시작한다.

## 6. 테스트

- 단위: `observe` 형식과 `prune_log`/shrink 보존; 비평가 트리거(12스텝 무진전, 압축 직전, 최대 8회); `submit_flag` evidence 검사(한 문장 거부, 두 문장 수락, 다른 enum은 기존 동작); `handoff_runbook` 게이트(env_blocked 거짓이면 거부, 참이면 파일 생성과 `RUNBOOK` 종료).
- 통합(미니 벤치): `win_gui_key` 회귀(여전히 solved); 새 벤치 `win_gui_nodll` — 존재하지 않는 DLL을 임포트해 wine에서 즉시 실패하는 PE. 기대 결과 `RUNBOOK`이고 runbook.md에 절차가 있어야 한다.
- 실전: captain-hook 힌트 없이 1회. 성공 기준은 "관찰로 전체 글자를 읽고, 방법이 다른 두 경로가 일치한 뒤 제출" 또는 "정직한 UNSOLVED". 검증 없는 제출이 나오면 실패로 기록한다.

## 7. 범위 밖 (이번에 하지 않음)

- 오케스트레이터/워커 분리.
- 사람을 도구로 쓰는 대화형 런북(사람이 실행하고 관찰을 돌려주는 방식). `--no-ask` 배치 운용과 맞지 않아 보류.
- 비평가 모델을 다른 모델로 바꾸는 것.
