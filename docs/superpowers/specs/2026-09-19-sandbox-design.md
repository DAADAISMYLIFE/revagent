# revagent 샌드박스 컨테이너 설계 (1단계)

- 날짜: 2026-09-19
- 상태: 승인됨
- 선행 스펙: `2026-09-19-revagent-design.md` (에이전트 본체)
- 후속: 2단계 PE 검증(wine/xvfb/tesseract), 3단계 헬퍼 툴(calls/emulate/rasterize)

## 1. 목표와 배경

첫 드림핵 실전(quiz/revlogin, multipoint, captain-hook)에서 실패의 대부분은 모델이 아니라 **환경**에서 왔다.
- revlogin: 바이너리가 `libcrypto.so.1.1`을 요구하는데 WSL엔 3.x뿐이고 sudo가 없어 설치 불가 → 수십 스텝을 심(shim) 제작에 낭비.
- captain-hook: Windows PE라 실행·검증이 불가능 → 정적 추적만으로 헤맴.
- 공통: 문제 바이너리를 호스트에서 그대로 실행(격리 없음), 도구 추가 설치 불가.

목표: **이미지 하나, 문제마다 새 컨테이너.** 에이전트 전체가 컨테이너 안에서 돌고, 호스트의 `revagent solve --sandbox <dir>`는 얇은 래퍼다. 컨테이너 안에서는 기존 코드가 변경 없이 그대로 실행된다.

비목표(이 단계에서 하지 않음): PE 실행(wine), 헬퍼 툴, 오케스트레이터, 이미지 레지스트리 배포, 비루트 실행.

## 2. 결정 사항

| 항목 | 결정 | 이유 |
|---|---|---|
| 구조 | 에이전트 전체를 컨테이너에서 실행(접근법 B) | 실행기 추상화 불필요, 기존 코드 무변경 |
| 베이스 이미지 | `python:3.12-slim-bookworm` | glibc(CTF 바이너리 실행 가능), Python 3.12 내장, 약 45MB. Alpine은 musl이라 부적합 |
| 패키지 | 툴이 실제로 쓰는 것만 명시 설치, `--no-install-recommends` | 크기 최소화. 최종 약 2.2GB(Ghidra+JDK 1.2GB, angr 스택 0.6GB가 대부분) |
| 사용자 | root | 에이전트가 런타임에 apt/pip 설치 가능. 컨테이너는 문제마다 폐기되므로 오염 없음 |
| 네트워크 | 기본 허용 | 원격 문제(nc), 모델 API 호출, 런타임 설치 |
| 이미지 빌드 | 로컬 `docker build`만 | 레지스트리 없음 |
| 호스트 모드 | 유지 | `--sandbox` 없으면 지금과 동일. 개발·테스트는 호스트에서 |
| Ghidra 위치 | 이미지의 `/root/tools` | HOME=/root이므로 `ghidra.py`의 `~/tools` 탐색이 코드 변경 없이 동작 |
| 자격증명 | 호스트가 `.secure`를 읽어 `QWEN/URL/MODEL` 환경변수로 전달 | 파일 마운트 없이 전달. `load_secure`가 환경변수를 파일보다 우선 |
| 문제 마운트 | `<절대경로>:/work/<폴더명>` | 케이스 파일 제목(폴더명) 보존, `.revagent/` 산출물이 호스트에 남음 |

## 3. 구성 요소

```
docker/
├── Dockerfile              # 이미지 정의 (아래 4절)
└── entrypoint.sh           # (없음: ENTRYPOINT는 revagent 콘솔 스크립트 직접)
scripts/
└── sandbox-build.sh        # docker build -t revagent-sandbox -f docker/Dockerfile .
revagent/
├── sandbox.py              # build_sandbox_cmd(), run_sandbox(): docker 명령 조립·실행
├── __main__.py             # solve/bench에 --sandbox, --sandbox-dev 플래그
└── llm.py                  # load_secure: 환경변수 QWEN/URL/MODEL 우선
tests/
└── test_sandbox.py
```

### 3.1 Dockerfile (요지)
```
FROM python:3.12-slim-bookworm
ENV LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive HOME=/root
RUN apt-get update && apt-get install -y --no-install-recommends \
      binutils gdb gcc g++ gcc-multilib libc6-i386 file strace ltrace \
      curl ca-certificates git make xxd radare2 qemu-user-static \
      libssl1.1(구 배포 deb 직접 설치) \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/install_ghidra.sh /tmp/   # + ghidra_scripts 경로 참조를 위해 revagent/ 일부
RUN bash /tmp/install_ghidra.sh && rm -f /root/tools/*.zip   # JDK 21 + Ghidra → /root/tools
COPY . /app
RUN pip install --no-cache-dir -e /app \
    && pip install --no-cache-dir angr z3-solver unicorn capstone pwntools pefile pycryptodome
WORKDIR /work
ENTRYPOINT ["revagent"]
# ---- 2단계 자리: wine64 xvfb tesseract-ocr imagemagick (이 스펙 범위 밖) ----
```
- `install_ghidra.sh`는 `$HOME/tools`를 쓰므로 그대로 재사용. 스크립트의 검증 단계(gcc hello)도 이미지 빌드 시 통과해야 한다.
- `libssl1.1`은 bookworm 저장소에 없다. Debian bullseye의 `libssl1.1_1.1.1w-0+deb11u*_amd64.deb`를 `curl`로 받아 `dpkg -i`. URL은 Dockerfile 상수로 두고 실패 시 빌드 실패(조용히 건너뛰지 않음).
- `-e /app`(editable)로 설치하므로 런타임에 `-v <저장소>:/app`을 마운트하면 재빌드 없이 코드 변경이 반영된다(`--sandbox-dev`).

### 3.2 sandbox.py
```python
IMAGE = "revagent-sandbox"

def build_sandbox_cmd(problem_dir: Path, passthrough: list[str], secure: Secure,
                      interactive: bool, dev_repo: Path | None) -> list[str]:
    """docker run 명령을 조립한다. 순수 함수(실행 안 함)."""
    name = problem_dir.resolve().name
    cmd = ["docker", "run", "--rm", "--init"]
    if interactive: cmd += ["-it"] else: cmd += ["-i"]
    cmd += ["-v", f"{problem_dir.resolve()}:/work/{name}"]
    for k, v in (("QWEN", secure.key), ("URL", secure.url), ("MODEL", secure.model)):
        cmd += ["-e", f"{k}={v}"]
    if dev_repo: cmd += ["-v", f"{dev_repo.resolve()}:/app"]
    cmd += [IMAGE, "solve", f"/work/{name}", *passthrough]
    return cmd

def check_docker() -> str | None:
    """docker CLI 없음 / 데몬 응답 없음 / 이미지 없음 → 사용자용 안내 문자열, 정상이면 None."""

def run_sandbox(cmd: list[str]) -> int:
    """subprocess.run(cmd).returncode. SIGINT는 docker CLI로 전달되어 컨테이너가 정리된다."""
```
- `interactive`는 `not --no-ask and sys.stdin.isatty()`.
- `passthrough`는 `--max-steps`, `--max-minutes`, `--no-ask`, `--show-thinking`, `--desc`(컨테이너 경로로 변환: `--desc`가 문제 폴더 안 파일이면 `/work/<name>/<상대경로>`, 아니면 에러).
- 환경변수 값에 셸 특수문자가 있어도 `subprocess.run(list)`이라 안전하다. 단 `docker inspect` 등으로 값이 보이므로 `.secure` 노출 범위는 로컬 docker 사용자와 동일하다(수용).

### 3.3 __main__.py 변경
- `solve`, `bench`에 `--sandbox`, `--sandbox-dev` 추가. `--sandbox-dev`는 `--sandbox`를 함의하며 저장소 루트(`Path(__file__).parents[1]`)를 `/app`에 마운트.
- `--sandbox`면: `check_docker()` → 안내 후 종료 코드 2 / `load_secure()` → `build_sandbox_cmd()` → `run_sandbox()` 종료 코드 반환. 호스트에서 `Agent`를 만들지 않는다.
- `bench --sandbox`는 폴더마다 `build_sandbox_cmd`를 만들어 순차 실행하고, 각 폴더의 `.revagent/result.json`을 읽어 표를 찍는다(컨테이너 stdout은 그대로 흘려보냄).

### 3.4 llm.py 변경
`load_secure`: `QWEN`, `URL`, `MODEL` 세 환경변수가 모두 있으면 파일 탐색 없이 그 값으로 `Secure`를 만든다(URL 끝 슬래시 제거 동일). 일부만 있으면 무시하고 파일 탐색으로 진행(부분 설정으로 인한 혼동 방지).

## 4. 데이터 흐름

```
호스트: revagent solve --sandbox quiz/revlogin --no-ask
  ├─ check_docker()          docker CLI, 데몬, 이미지 확인
  ├─ load_secure()           .secure → Secure
  ├─ build_sandbox_cmd()     docker run --rm --init -i -v .../quiz/revlogin:/work/revlogin -e QWEN=.. -e URL=.. -e MODEL=.. revagent-sandbox solve /work/revlogin --no-ask
  └─ run_sandbox()           stdout/stderr 그대로 통과, 종료 코드 반환
컨테이너: revagent solve /work/revlogin --no-ask
  ├─ load_secure()           환경변수에서 Secure
  ├─ Agent(...)              기존 루프 그대로. Ghidra는 /root/tools, 툴은 컨테이너 것
  └─ /work/revlogin/.revagent/{case.md, transcript.jsonl, result.json, ghidra/, out/}  → 호스트 폴더에 남음
```

## 5. 에러 처리

| 상황 | 처리 |
|---|---|
| `docker` CLI 없음 | "docker not found. Docker Desktop → Settings → Resources → WSL integration에서 이 배포판을 켜라" 출력, 종료 2 |
| 데몬 응답 없음(`docker info` 실패) | "Docker daemon not reachable. Docker Desktop이 실행 중인지 확인" 출력, 종료 2 |
| 이미지 없음(`docker image inspect` 실패) | "image revagent-sandbox not found. run scripts/sandbox-build.sh" 출력, 종료 2 (자동 빌드 안 함) |
| `.secure` 없음 | 기존 `FileNotFoundError` 메시지 그대로, 종료 2 |
| `--desc`가 문제 폴더 밖 파일 | "with --sandbox, --desc must be inside the problem dir" 종료 2 |
| 컨테이너 안 에이전트 실패 | result.json에 사유 기록(기존 동작), 종료 코드 1 전달 |
| Ctrl-C | docker CLI가 SIGINT를 받아 컨테이너 종료(`--init`이 PID 1 신호 전달), `--rm`으로 정리 |
| 이미지 빌드 중 libssl1.1 deb 다운로드 실패 | 빌드 실패(명시적) |

## 6. 검증

1. **단위(pytest, docker 불필요)**
   - `build_sandbox_cmd`: 마운트 경로/이름, env 3개, `-it` vs `-i`, dev 마운트 유무, passthrough 순서, `--desc` 경로 변환.
   - `check_docker`: `shutil.which` 없음 / `docker info` 실패 / `image inspect` 실패 각각의 안내 문구(subprocess는 monkeypatch).
   - `load_secure`: 환경변수 3개 모두 → 파일 무시; 일부만 → 파일 탐색.
   - `__main__`: `solve --sandbox`가 `Agent`를 만들지 않고 `run_sandbox`를 호출하며 그 반환값을 종료 코드로 씀(monkeypatch).
2. **이미지 빌드**: `scripts/sandbox-build.sh` 성공, `docker run --rm revagent-sandbox --help` 출력, `docker run --rm --entrypoint bash revagent-sandbox -c "ls /root/tools; python -c 'import angr,z3,unicorn'; gdb --version | head -1; ldconfig -p | grep libssl.so.1.1"`.
3. **배관**: `revagent solve --sandbox bench/mini/xor_check --no-ask` → solved.
4. **실전**: quiz/revlogin, multipoint를 `--sandbox`로 재실행. revlogin은 libssl1.1 덕에 `run_binary`가 바로 되는지 확인(심 제작 스텝이 사라져야 함). README 벤치 표 갱신.

## 7. 2단계 연결점

- Dockerfile 끝의 주석 자리에 wine64/xvfb/tesseract 레이어 추가.
- `run_binary`가 `.exe`(MZ)를 만나면 `[cannot run here]` 대신 `wine`(콘솔) 또는 `xvfb-run wine` + 스크린샷 + OCR(GUI) 경로로 분기. 이 스펙에서는 손대지 않는다.

## 8. 수정 이력 (구현 중 판결)

전체 브랜치 리뷰(2026-09-19, final-fix-list)에서 확정된, 이 문서 §2~§6과 다른 실제 동작:

- **이미지 크기**: §2의 "최종 약 2.2GB" 추정은 틀렸다. 실측 약 **4.3GB**(Ghidra+JDK, angr 스택에 더해 radare2 .deb, libssl1.1, 전체 Python 리버싱 스택이 추정보다 크다). README의 벤치 표/설치 안내는 4.3GB로 정정했다.
- **런타임 CA (R5)**: `docker/entrypoint.sh`가 실제로 존재한다(§3의 구성 요소 표는 "(없음)"이라 적었던 옛 버전). `--sandbox-ca <path>` 또는 `REVAGENT_SANDBOX_CA` 환경변수로 지정한 CA 인증서를 `-v ...:/usr/local/share/ca-certificates/extra-ca.crt:ro`로 런타임에만 마운트하고 entrypoint가 `update-ca-certificates`를 실행한다. 이미지 자체에는 절대 포함되지 않는다(TLS 가로채는 사내망 대응, 이미지 재사용성 유지).
- **JDK 설치 경로 (R4)**: `curl`로 adoptium API에서 받는 대신 `eclipse-temurin:21-jdk-jammy` 멀티스테이지 이미지에서 `COPY --from=jdk /opt/java/openjdk /root/tools/jdk-21-temurin`로 가져온다. api.adoptium.net이 이 네트워크에서 TLS 가로채기 대상이라 직접 다운로드가 불안정했기 때문.
- **radare2**: Debian bookworm 저장소에 없어 upstream GitHub 릴리스의 `.deb`를 고정 URL(`RADARE2_URL` ARG)로 받아 `dpkg -i`. 실패 시 빌드 실패(조용히 건너뛰지 않음).
- **파이썬 스택 고정 (R6/R7)**: `pip install` 대상을 전부 버전 고정(`angr==10.0.0` 등)했고, `openai`도 빌드 시점에 실제로 해석된 버전(`openai==3.16.2`)으로 고정했다. Ghidra도 `GHIDRA_URL` ARG(기본값은 특정 릴리스 zip의 고정 URL)로 고정하며, 호스트용 `scripts/install_ghidra.sh`는 `GHIDRA_URL` 환경변수가 설정되어 있으면 그 값을 쓰고 없으면 기존의 "latest" GitHub API 조회로 폴백한다(호스트 동작은 변경 없음). 목적: 재현 가능한 빌드, API가 조용히 바뀌어 생기는 회귀 방지.
- **자격증명 전달 방식**: `docker run` argv에는 `-e QWEN -e URL -e MODEL`처럼 **이름만** 실리고 값은 싣지 않는다(호스트 프로세스 테이블에서 `ps`/`/proc/<pid>/cmdline`으로 노출되는 것을 막기 위해). 실제 값은 `run_sandbox(cmd, env_extra=...)`가 `subprocess.run(cmd, env={**os.environ, **env_extra})`로 docker CLI 프로세스 자신의 환경에만 실어 전달한다. 단, `docker inspect`로는 실행 중인 컨테이너의 환경변수 값을 여전히 볼 수 있으므로 로컬 docker 그룹 사용자에게는 노출 범위가 동일하다(README에 명시).
- **`check_docker` 타임아웃**: `docker info`/`docker image inspect` 호출에 `timeout=20`을 두고, `subprocess.TimeoutExpired`를 데몬 무응답(`MSG_NO_DAEMON`)으로 처리한다. 데몬이 멈춰 있을 때 무한 대기하지 않기 위함.
- **bench의 오래된 결과 방지 (R2)**: `bench --sandbox`는 컨테이너 실행 전 `result.json`의 mtime을 기록해 두고, 컨테이너가 실패 종료(non-zero)했는데 파일이 갱신되지 않았으면 "이전 실행의 결과"를 성공으로 잘못 읽지 않고 `error: container exited <rc>`로 보고한다.
