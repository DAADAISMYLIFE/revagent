# 함수 오라클 설계 (`emulate` 도구: 바이너리의 함수 하나를 unicorn으로 실행)

## 1. 배경과 문제

basic(Reversing Basic #9) 두 번의 실패는 같은 지점에서 났다. 모델은 디컴파일된 C에서 forward 변환을 파이썬으로 옮기는데, 어느 슬롯에 쓰고 어느 슬롯을 읽는지를 틀린 채 그 위에 z3 모델(10개)과 손 역산(16개)을 쌓았다. 틀렸다는 걸 확인할 방법이 없었다. 바이너리는 Correct/Wrong만 뱉고, Windows PE라 wine 밑에서 gdb로 중간값을 볼 수 없다. relativity에서도 "모델이 맞는데 key[0]만 다르다"를 확인하는 데 세 실행이 걸렸다. captain-hook은 그리기 함수의 인자를 손으로 추적하다 죽었다.

공통점은 **함수 하나의 입출력을 관찰할 오라클이 없다**는 것이다. 프로그램 전체는 `run_binary`로 돌릴 수 있지만 그건 최종 판정만 준다. 필요한 건 "이 함수에 이 바이트를 넣으면 무엇이 나오는가"다. 그게 있으면 모델은 자기 파이썬을 랜덤 입력 몇 개로 오라클과 비교해 틀린 곳을 고치고, 맞으면 `solve_check`로 뒤집는다. `solve_check`가 "뒤집기"를 대신하듯, 이 도구는 "검증"을 대신한다.

## 2. 결정 사항

1. **범용·내용 무관.** 도구는 로더(cle)와 CPU 에뮬레이터(unicorn)만 안다. 문제나 함수 이름을 모른다. 입력은 바이너리 경로, 함수 주소, 인자 목록이다.
2. **호출 규약은 파일 형식으로 정한다.** PE → Win64(rcx, rdx, r8, r9 + 32바이트 shadow space), ELF → SysV(rdi, rsi, rdx, rcx, r8, r9). 그 이상의 인자는 스택. x86-64만 지원하고 다른 아키텍처는 `[cannot emulate]`로 명시한다.
3. **인자는 세 종류.** `hex:<bytes>`(도구가 버퍼를 할당해 그 주소를 넘김; 호출 후 내용을 돌려줌), `int:<n>`(정수 그대로), `addr:0x...`(로드된 이미지 안의 주소, 예: 데이터 테이블). 이것으로 `f(buf)`, `f(table, buf)`, `f(buf, len)` 모두 표현된다.
4. **외부 호출은 실행하지 않고 보고한다.** 함수가 import(strlen, memcmp, GdipDrawLineI…)나 이미지 밖으로 나가면 즉시 멈추고, 어떤 심볼을 호출했는지와 그때의 인자 레지스터를 돌려준다. 이 단계에서 libc 스텁은 넣지 않는다(§7). 대신 그 자체가 관찰이다: captain-hook의 "그리기 호출 6인자 수집"이 이 보고로 된다.
5. **관찰 원장에 기록한다.** `run_binary`처럼 매 호출이 `- [obs step N] emulate FUN@0x...: rax=..., buf0=...` 한 줄을 남긴다. 증거 사다리에서 이 도구의 출력은 "관찰" 등급이다.
6. **한계를 도구 설명에 적는다.** 순수 함수(산술, 테이블, 자기 버퍼)만 된다. TLS, syscalls, 힙 할당, 예외, SIMD 일부는 안 되고 `[emulation stopped]`로 이유를 준다.

## 3. 구성 요소

### 3.1 `revagent/emulate.py` (순수 로직, 도구와 분리)

- `load_image(path) -> Image`: `cle.Loader(path, auto_load_libs=False, main_opts={"base_addr": 0x100000} if PIE ELF)`로 로드한다. **Ghidra와 같은 베이스**를 쓰는 것이 핵심이다: Ghidra는 PIE ELF를 0x100000에, PE를 ImageBase(예: 0x140000000)에 두고, cle의 PE 기본 베이스는 ImageBase와 같다(spike로 확인). 따라서 모델이 디컴파일에서 보는 주소(`FUN_1400010a0`, `DAT_00106020`)를 환산 없이 그대로 쓴다. 세그먼트 목록 (vaddr, memsize, bytes), `plt: dict[name, addr]`(cle `main_object.plt`)와 `imports`, `is_pe`, `base`를 돌려준다.
- `emulate_call(image, func_addr, args, max_insns=5_000_000, out_lens=None) -> Result`: unicorn `UC_ARCH_X86, UC_MODE_64`에 이미지 매핑, 스택 8MB, 인자 버퍼 영역(각 `hex:` 인자마다 페이지 정렬 4KB, 입력 바이트 뒤는 0), 반환 주소로 매핑된 sentinel 페이지(그 주소 도달 시 정지). 레지스터 세팅 후 `emu_start`. hook: `UC_HOOK_CODE`로 명령 수 상한, `UC_HOOK_MEM_UNMAPPED`/fetch로 이미지 밖 실행을 잡아 `imports`에서 이름을 찾는다(PLT 슬롯 값 읽기 포함). 결과: `rax`, 각 `hex:` 버퍼의 호출 후 내용(`out_lens[i]` 또는 입력 길이), `insns`, `stopped: None | {"reason": "import"|"unmapped"|"limit"|"invalid", "symbol": str|None, "rip": int, "args": [rcx/rdi.. 값 6개]}`.
- Win64 shadow space 32바이트와 16바이트 스택 정렬을 지킨다. FS/GS 세그먼트 접근(`__security_cookie` 같은 TLS/스택 쿠키 읽기)은 GS 베이스를 0 페이지로 매핑해 0을 읽게 한다. `__security_check_cookie`는 이미지 안의 함수라 그냥 돌아간다.

### 3.2 `revagent/tools/emulate.py` (도구)

- 입력: `binary`(문제 폴더 기준), `function`(Ghidra 이름 `FUN_...` 또는 `0x...`; 이름은 functions.json 캐시로 주소 환산, 캐시 없으면 주소만 허용), `args`(문자열 목록, §2.3), 선택 `out_lens`(정수 목록), 선택 `max_insns`.
- 출력 텍스트: `rax=0x...`, 각 버퍼 `arg0 (N bytes): hex / printable`, `instructions=...`, 그리고 멈췄으면 `[emulation stopped] called import strlen at 0x...; arg registers: rcx=..., rdx=...`. 실패 원인별로 다음 행동을 한 줄 붙인다("import를 부르지 않는 안쪽 함수(디컴파일에서 그 호출을 감싼 FUN_)를 대상으로 하라").
- 원장: `ctx.observe(f"emulate {function}: rax=0x{rax:x}, buf0={hex[:32]}...")`.
- 타임아웃은 `ctx.clamp_timeout`과 명령 수 상한 둘 다.

### 3.3 플레이북

- 규칙 11 증거 사다리에 "함수 단위 관찰 = `emulate`"를 추가. 3단계 Constraint/Sequential 항목 첫 문장을 "forward를 파이썬으로 옮긴 뒤 **`emulate`로 실제 함수와 같은 입력에서 비교**하고, 같으면 `solve_check`"로. 4단계 검증에 "`solve_check`가 준 입력을 `emulate`로 한 번 더 확인한 뒤 `run_binary`".
- Environment에 도구 한 줄과 주소 환산 규칙.

### 3.4 검증 데이터

spike(2026-09-21 밤, 호스트 venv, cle 9.3.3 + unicorn 2.1.0): chall9.exe의 `FUN_1400010a0`을 이 설계대로 호출해 3개 입력(`Reverse_`, `ABCDEFGH`, 난수 8바이트)에서 손으로 쓴 파이썬 forward와 바이트 단위로 일치했다. 즉 basic에서 모델이 두 번 실패한 "forward 검증" 단계는 이 도구 한 번으로 끝난다.


- bench/mini/xor_check(ELF)와 bench/mini/win_console(PE)의 체크 함수를 대상으로 `emulate`가 `run_binary`와 일치하는 결과를 내는 테스트. quiz/basic의 chall9.exe는 레포 밖이라 라이브 검증에서만 쓴다.
- 단위 테스트는 unicorn으로 직접 조립한 작은 코드(`add rdi, rsi; mov rax, rdi; ret`)와 cle 없이 매핑한 버퍼로 `emulate_call`의 규약(인자 레지스터, shadow space, sentinel 정지, import 보고)을 고정한다.

## 4. 데이터 흐름

```
모델: decompile FUN_x → 파이썬 forward 작성
  → emulate(binary, FUN_x, ["hex:<random 24 bytes>"]) → 실제 출력
  → 파이썬 forward(random) 과 비교 → 다르면 C 다시 읽고 수정 (2~3회)
  → 같으면 solve_check(forward, target) → 후보
  → emulate(FUN_x, [hex:후보]) == target 확인 → run_binary로 최종 → submit_flag
```

## 5. 오류 처리

- unicorn/cle 미설치 → `[tool error]`와 설치 안내(둘 다 이미지에 있음: unicorn 2.1.2, cle는 angr 의존성).
- 지원 안 하는 아키텍처/형식 → `[cannot emulate] ...`.
- 명령 수 상한·시간 상한 → `[emulation stopped] limit`, 마지막 rip 표시.
- 함수 주소가 이미지 밖 → `[tool error]`.
- 어떤 경우에도 예외가 루프로 나가지 않는다(`_execute`의 `[tool error]` 포장이 있지만 도구 안에서 먼저 잡는다).

## 6. 테스트

- `tests/test_emulate.py`: 규약 고정(SysV/Win64 인자, 버퍼 되돌리기, out_lens, sentinel, import 보고, 명령 상한, GS 읽기), 주소 환산(ELF PIE 0x100000→cle 베이스, PE ImageBase).
- `tests/test_tools.py`: 도구 텍스트, 원장 줄, 경로 오류, functions.json 이름 환산.
- bench/mini 두 바이너리로 통합 테스트(빌드된 바이너리가 있을 때만 실행; 없으면 skip).
- 라이브: basic 3회차(목표: emulate로 forward 검증 → solve_check → 해결), relativity 회귀.

## 7. 범위 밖

- libc 스텁(strlen/memcmp/memcpy)과 syscall 에뮬레이션. import 보고로 충분한지 basic·captain-hook에서 확인한 뒤 결정.
- 다른 아키텍처(ARM/MIPS): qemu-user가 있으니 프로그램 단위 실행은 이미 가능하고, 함수 단위는 unicorn 아키텍처 추가로 가능하지만 이번엔 x86-64만.
- 게이트와의 연동(예: G3가 "emulate로 비교하라"를 요구하는 문구)은 플레이북 문구로만.

## 수정 이력 (2026-09-21)

구현이 위 설계와 달라진 점. 본문은 고치지 않고 여기에만 적는다.

- §3.1 `Image`: 필드는 `segments/base/min_addr/max_addr/is_pe/symbol_at`. `plt`/`imports`/`insns`는 없고, import 이름은 cle의 `find_symbol`/`describe_addr`로 정지 시점에 찾는다.
- §3.1 스택은 8 MB(`STACK_SIZE = 0x800000`, unicorn이 지연 커밋). `UC_HOOK_CODE` 명령 카운터는 없고 `emu_start(count=max_insns)`로 상한을 건다.
- §3.1 `hex:` 버퍼는 인자 인덱스 × `0x20000` 간격, 최대 `0xE000` 바이트(뒤에 최소 한 페이지가 비매핑으로 남아 넘침이 다음 버퍼로 새지 않고 `unmapped`로 잡힌다).
- §3.2 출력에 `instructions=` 줄은 없다. 함수 이름은 `FUN_<hex>`/`thunk_FUN_<hex>`/`0x<hex>`를 그대로 파싱한다(functions.json 조회 없음). `addr:`는 `DAT_00106020`/`00106020`/`0x106020` 모두 받는다.
- §3.2 버퍼 표시와 원장(`arg1=...`)은 버퍼 순번이 아니라 인자 인덱스로 붙인다. 이미지 캐시 키는 `(경로, mtime_ns, size)`(모델이 바이너리를 패치하면 다시 로드).
- §6 functions.json 환산 테스트와 bench/mini 통합 테스트는 없다. gcc로 만든 PIE ELF 테스트(`test_load_image_pie_elf_at_ghidra_base`)와 컨트롤러의 레포 밖 PE 확인이 그 자리를 맡는다.
