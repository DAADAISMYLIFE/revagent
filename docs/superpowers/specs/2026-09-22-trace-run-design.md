# 실행 추적 도구 설계 (`trace_run`: 프로그램 한 번 실행에서 실행된 코드 주소의 시퀀스를 얻는다)

## 1. 배경과 문제

못 푼 세 문제(ROVM, damnida, captain-hook)는 실패 지점이 같다. 모델은 인터프리터의 구조를 복원한다(ROVM: 스택 기반 ROP 체인 VM, Facts 70개; damnida: RWX 자기수정 tail-call VM, Facts 186개). 그런데 그 인터프리터가 **해석하는 프로그램**은 끝내 못 읽는다. 핸들러 하나하나를 디컴파일해서 머리로 프로그램을 재구성하려다 예산이 끝난다. 사람은 이 지점에서 실행 추적을 뜬다. 실행된 주소의 시퀀스가 곧 프로그램 리스팅이고, 어떤 핸들러가 몇 번 어떤 순서로 돌았는지는 읽는 게 아니라 관찰하는 것이다.

`emulate`는 순수 함수 하나의 입출력을 준다. 인터프리터는 함수가 아니라 프로그램 전체를 도는 루프이고, mmap한 영역이나 RWX 영역에서 돈다. `emulate`의 관측 범위 밖이다. `run_binary`는 최종 출력만 준다. 그 사이의 관찰, "프로그램이 어디를 어떤 순서로 실행했나"가 비어 있다.

프로브(2026-09-22, 샌드박스 이미지의 qemu-x86_64-static 7.2):

- ROVM: `qemu-x86_64-static -d exec,nochain,page ./chall`에 35바이트 입력 → 28,818개 TB 실행, 2,472개 서로 다른 주소. 고정 주소 0x1224000(mmap한 `opcode`)이 7,233번, 나머지 대부분은 0x4002a…(공유 라이브러리).
- damnida: 161,936개 TB. 메인 이미지 0x4000000000 영역 72k, 익명 매핑(RWX VM) 68k, 라이브러리 20k.
- 자기수정 코드도 잡힌다(qemu가 코드 페이지 쓰기에 TB를 무효화하고 재번역한다). 실행 시간 둘 다 수 초.

즉 qemu만으로 관찰은 얻어진다. 도구가 할 일은 **집계와 주소 환산**이다. 3만~16만 줄 로그를 모델이 읽을 수는 없다.

## 2. 결정 사항

1. **범용·내용 무관.** 도구는 qemu-user 로그 형식과 ELF 헤더만 안다. 문제, 함수 이름, VM 종류를 모른다. 입력은 바이너리 경로, stdin, 인자, 주소 범위 필터다.
2. **x86-64 ELF만.** PE는 wine 밑이라 qemu 추적이 안 된다(`[cannot trace] PE`). 다른 아키텍처 ELF는 qemu-<arch>-static이 이미지에 있으니 같은 로그 형식으로 되지만 이번엔 x86-64만 검증하고, 나머지는 시도 후 실패 시 `[cannot trace]`로 명시한다.
3. **주소는 Ghidra 기준으로 환산해서 준다.** qemu는 PIE를 0x4000000000 근처에 놓는다. 도구는 `-d page` 출력에서 매핑을 읽고, **base + e_entry 가 추적에 등장하는 매핑**을 메인 이미지로 정한다(내용 무관, 파일 이름 불필요). PIE ELF는 Ghidra 베이스 0x100000으로, non-PIE는 그대로. 이미지 밖 주소는 원본 그대로 두고 어느 영역인지 표시한다.
4. **출력은 세 부분이다.**
   - **영역 요약**: `-d page`의 최종 매핑별로 실행 TB 수. 메인 이미지는 `[image]`, 그 외는 `[anon rwx]`/`[anon]`/`[lib?]`로 표시한다. 라이브러리 판별은 "실행 시작 시점(첫 Trace 전)에 이미 존재한 파일 매핑"으로 한다. 모델은 여기서 VM이 어느 영역에서 도는지 본다(ROVM: 0x1224000, damnida: 익명 RWX).
   - **핫스팟**: 범위 안의 주소별 실행 횟수 상위 N(기본 40). Ghidra 주소 + 횟수.
   - **시퀀스**: 범위 안에서 실행된 주소의 순서를 **연속 반복 압축**해서 준다. 알고리즘: 길이 1~16의 직전 k-gram이 바로 이어서 반복되면 `(a b c)×n`으로 접는다. 접은 뒤에도 길면 앞 `head`개 + `...` + 뒤 `tail`개. 전체 시퀀스와 원본 로그는 `.revagent/out/trace-N.txt`, `.revagent/out/trace-N.log`에 저장하고 경로를 알려준다. 모델은 `bash`로 grep할 수 있다.
5. **범위 필터는 qemu에 넘긴다.** `range`가 주어지면 `-dfilter start..end`로 qemu가 로그를 그 범위로 줄인다(Ghidra 주소를 받아 guest 주소로 역환산; 이미지 밖 주소는 그대로). 범위 없이 첫 호출하면 영역 요약이 목적이니 라이브러리 영역은 시퀀스에서 뺀다.
6. **레지스터는 이번 범위 밖.** `-d cpu`는 TB당 20줄이라 폭발한다. 시퀀스가 있으면 특정 주소의 레지스터는 gdb 브레이크포인트나 `emulate`로 얻을 수 있다. §7.
7. **관찰 원장에 기록한다.** `- [obs step N] trace_run ./chall: 28818 TBs, hot [anon] 0x1224000 ×7233, image top 0x1013a4 ×564`.
8. **한계를 도구 설명에 적는다.** TB 단위라 한 블록 안의 명령은 안 보인다(`nochain`이라 블록 경계는 정확하다). 시간이 오래 걸리는 프로그램(수천만 TB)은 로그 크기 상한(기본 200 MB)에서 끊고 `[trace truncated]`.

## 3. 구성 요소

### 3.1 `revagent/trace.py` (순수 로직)

- `parse_qemu_log(text) -> Trace`: `Trace 0: 0x<host> [<cr3>/<guest pc>/<flags>/<cflags>]` 줄에서 guest pc를 뽑는다. `page layout changed` 블록은 마지막 것을 `mappings: list[(start, end, prot)]`로 남기고, 첫 Trace 줄 이전의 마지막 레이아웃을 `initial_mappings`로 따로 둔다(라이브러리 판별용).
- `find_image_base(mappings, pcs, e_entry, is_pie) -> int`: PIE면 `start + e_entry ∈ pcs`인 매핑 start(실행 가능 prot)를 찾고, 없으면 첫 실행 가능 매핑. non-PIE면 0.
- `to_ghidra(pc, image_base, image_end, is_pie) -> int | None`: 이미지 안이면 `pc - image_base + 0x100000`(PIE) 또는 그대로. 밖이면 None.
- `classify_regions(mappings, initial_mappings, image) -> list[Region]`: `[image]`, `[lib?]`(initial에 있던 실행 가능 매핑 중 이미지가 아닌 것), `[anon rwx]`(prot에 w와 x), `[anon]`.
- `compress(seq: list[int], max_k=16) -> list[Item]`: 연속 반복 압축. `Item = (tuple[int,...], count)`.
- `summarize(trace, image, range_, top=40, head=200, tail=50) -> str`: §2.4 형식의 텍스트.

### 3.2 `revagent/tools/trace_run.py` (도구)

- 입력: `binary`(문제 폴더 기준), `stdin`(문자열, 기본 ""), `args`(리스트), `range`(`"0x101000..0x102000"` 또는 `"0x1224000..0x1225000"`, 선택), `top`, `timeout`(기본 60, `ctx.clamp_timeout`).
- 실행: `qemu-x86_64-static -d exec,nochain,page -D <log> [-dfilter ...] ./bin args`, cwd = 바이너리의 디렉터리(ROVM처럼 상대 경로로 파일을 여는 프로그램 때문), stdin 파이프, 프로그램 stdout/stderr는 앞 400자만 붙인다. 로그 파일은 `ctx.out_dir/trace-<id>.log`. 로그 크기 상한 초과 시 프로세스 kill + `[trace truncated at 200 MB]`.
- ELF 판별: 매직 `\x7fELF`, `e_machine == 62`, `e_type == 3`(PIE) / 2, `e_entry`. `pyelftools` 대신 `struct`로 헤더만 읽는다(의존성 추가 없음).
- 출력 텍스트 예:

```
trace_run ./chall (stdin 36 bytes): exit 0, stdout 'Fail!'
image: 0x4000000000..0x4000202000 (PIE, Ghidra base 0x100000)
regions (executed TBs):
  [image]     0x100000..0x302000     7848
  [anon]      0x1224000..0x1225000   7233   <- mmap'd after start; not a library
  [lib?]      0x4002a00000..0x4002b40000  20816  (skipped in sequence; pass range= to include)
hot (Ghidra addr × count, top 40):
  0x1224000 ×7233   0x1013a4 ×564   0x1013b0 ×515 ...
sequence (image + anon, 15081 TBs, repeats folded):
  0x101040 0x101052 (0x1224000 0x1013a4 0x1013b0)×512 0x101070 ...
  ... [head 200 / tail 50 shown; full sequence: .revagent/out/trace-3.txt, raw qemu log: .revagent/out/trace-3.log]
```

- 원장: §2.7.
- `[cannot trace]`: PE, non-ELF, qemu 부재, 인터프리터(`#!`) 파일. `[cannot trace]`는 `ctx.observe_cannot_run`을 **부르지 않는다**(프로그램은 `run_binary`로 돌 수 있을 수 있다). 대신 원장에 `trace_run X: [cannot trace] 이유` 한 줄.

### 3.3 플레이북 (`prompts/system.md`)

- Environment에 도구 한 줄: "`trace_run`은 프로그램 한 번 실행에서 실행된 코드 주소의 시퀀스(반복 접음)와 영역별·주소별 실행 횟수를 준다. 인터프리터/VM/자기수정 코드가 실제로 무엇을 어떤 순서로 실행했는지는 핸들러를 읽지 말고 이걸로 관찰하라."
- 3단계에 **클래스 규칙** 한 항목(문제 이름 없음): "**Interpreter / VM / dispatch loop** (a loop that fetches from a table, a chain, a byte-code buffer or an mmap'd region and jumps through a handler table, `ret`-chains, `call rax`): the next deliverable is the LISTING of the interpreted program, not the analysis of every handler. Get it by observation: `trace_run` with a range over the region the dispatch executes in gives the handler sequence with repeats folded; map each distinct handler address to its operation ONCE (decompile or `emulate` it), then read the listing as a program. Only then invert. Reading handlers without the listing is how runs die at 150 steps with the VM 'fully understood'."
- 규칙 11 증거 사다리에 `trace_run`을 "trace/log" 등급으로 추가.

### 3.4 검증 데이터

- `bench/mini/`에 작은 인터프리터 바이너리 하나 추가(`vm_loop.c`: 바이트코드 8개를 핸들러 테이블로 디스패치, 입력을 변환해 비교). `trace_run`의 시퀀스에 핸들러 주소가 바이트코드 순서대로 나오고 반복이 접히는지 통합 테스트. PIE로 빌드해 주소 환산도 검증.
- 단위 테스트는 실제 qemu 로그 조각(프로브에서 잘라낸 40줄)을 픽스처로 넣어 파서·베이스 판별·압축·요약을 고정한다.

## 4. 데이터 흐름

```
모델: trace_run(binary, stdin=aaaa...) → 영역 요약 (VM이 [anon rwx] 0x1224000에서 돈다)
  → trace_run(range=0x1224000..0x1225000) → 핸들러 시퀀스 (a b c)×36 d (a b e)×36 ...
  → 서로 다른 핸들러 주소 N개를 decompile/emulate → 각각의 연산
  → 시퀀스를 프로그램으로 읽음 → forward 재구현 → emulate/trace_run으로 대조 → solve_check
```

두 번째 호출에서 입력을 바꿔 다시 뜨면 입력 의존 분기가 시퀀스 차이로 드러난다(`diff` 두 trace-N.txt). 도구가 diff를 대신하진 않는다.

## 5. 오류 처리

- qemu 부재 → `[tool error] qemu-x86_64-static not found` (샌드박스엔 있음).
- 타임아웃 → kill, 그때까지의 로그로 요약하고 `[trace stopped: timeout after N s]`.
- 로그 상한 → §2.8.
- 로그에 Trace 줄이 0개 → 프로그램 출력과 함께 `[no trace] program did not execute (exit N)`.
- 베이스를 못 찾음(e_entry가 추적에 없음, 예: 즉시 크래시) → 첫 실행 가능 매핑으로 두고 `(base guessed)` 표시.
- 어떤 예외도 루프 밖으로 안 나간다.

## 6. 테스트

- `tests/test_trace.py`: 파서(Trace 줄, page layout 블록, initial vs final), `find_image_base`(PIE/non-PIE/미발견), `to_ghidra`, `classify_regions`, `compress`(단순 반복, 중첩 없음, k=16 넘는 주기는 안 접힘, 길이 1), `summarize` 형식.
- `tests/test_tools.py`: 인자 검증, `[cannot trace]` 경로(PE 픽스처), 원장 줄, out 파일 생성, range 역환산.
- 통합: `bench/mini/vm_loop`(PIE ELF)이 빌드돼 있을 때 시퀀스에 핸들러 주소가 순서대로 나오는지; 없으면 skip.
- 리플레이: 새 플레이북 문구는 게이트가 아니므로 리플레이 검증 대상 아님. 라이브: ROVM run 5, damnida run 3(둘 다 새 이미지, fresh case file 아님 — case file은 이어간다).

## 7. 범위 밖

- 레지스터/메모리 값 추적(`-d cpu`, 특정 주소에서의 rax 등). 시퀀스가 있으면 gdb 브레이크포인트 한 번으로 얻는다. 필요하면 다음 라운드에 `trace_run(regs_at=[...])`.
- PE 추적(wine 밑 qemu 불가). captain-hook 클래스는 별도 `carve` 도구(중첩 바이너리 탐지)로 다룬다.
- 두 trace의 diff. 모델이 `bash diff`로 한다.
- 다른 아키텍처 ELF: 시도는 하되 검증하지 않는다.
