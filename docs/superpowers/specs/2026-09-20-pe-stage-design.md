# PE 실행·검증 단계 설계 (2단계)

- 날짜: 2026-09-20
- 상태: 승인됨 (사용자가 2026-09-19 회의에서 "컨테이너 → PE 검증 → 헬퍼 툴" 순서를 승인, 이후 자율 진행 지시)
- 선행: `2026-09-19-sandbox-design.md`

## 1. 목표

Windows PE 문제를 컨테이너 안에서 **실행하고 검증**할 수 있게 한다. captain-hook은 정적 분석 4회(약 500스텝)로 실패했다. 화면에 그리는 플래그는 실행해서 화면을 읽는 것이 정답이다.

성공 기준: `revagent solve --sandbox`가 (1) 콘솔 PE crackme를 wine으로 실행해 입력을 넣고 출력을 검증할 수 있다, (2) GUI PE를 가상 화면에서 실행해 스크린샷과 OCR 텍스트를 얻을 수 있다, (3) captain-hook에서 화면의 숫자를 읽어 플래그를 제출한다.

비목표: Windows 드라이버·강한 안티디버깅·.NET·DirectX 렌더링(wine 한계), 대화형 디버깅(x64dbg), Windows Sandbox/VM.

## 2. 결정

| 항목 | 결정 | 이유 |
|---|---|---|
| 실행기 | Debian bookworm `wine64` 8.0 | 저장소 패키지, 추가 다운로드 없음(회사 TLS 환경) |
| 가상 화면 | `xvfb` 고정 디스플레이 `:99`, 컨테이너 시작 시 entrypoint가 띄움 | 툴마다 xvfb-run 하면 창 캡처가 안 됨 |
| 캡처·OCR | `imagemagick`(`import -window root`) + `tesseract-ocr`(eng) | 저장소 패키지 |
| 키 입력 | `xdotool` | GUI crackme의 입력창 대응 |
| PE 빌드 | `mingw-w64` | 자작 테스트 PE(콘솔·GUI)를 이미지 안에서 컴파일해 스모크·벤치 |
| 픽셀 분석 | `pillow` pip 고정 | OCR 실패 시 모델이 PNG를 직접 분석(7세그먼트 등) |
| wine prefix | 빌드 시 `wineboot -u`로 `/root/.wine` 미리 생성 | 첫 실행 30초 지연 제거 |
| 콘솔 PE | 기존 `run_binary`가 MZ를 만나면 `wine <exe>`로 실행 | 도구 추가 없이 검증 루프 확보 |
| GUI PE | 새 툴 `run_gui` | 스크린샷·OCR·키 입력은 별도 의미론 |

## 3. 구성 요소

- `docker/Dockerfile`: 2단계 레이어 추가(아래 패키지), `wineboot` 초기화, `pillow` 핀.
- `docker/entrypoint.sh`: `Xvfb :99 -screen 0 1280x800x24 &` 후 `export DISPLAY=:99`; 기존 CA 처리 유지.
- `revagent/tools/run_binary.py`: MZ 감지 시 `WINEDEBUG=-all wine <exe> <args>`로 실행(stdin 전달, timeout 동일). `[cannot run here]` 분기는 wine이 없을 때(호스트 모드)만.
- `revagent/tools/run_gui.py` (신규): `run_gui(path, wait_seconds=5, type_text="", args=[])` → 지정 초 뒤 스크린샷 `.revagent/screens/NNN.png` 저장, `tesseract --psm 6`과 `--psm 7` 두 결과, 창 목록(`xdotool search --name`), 프로세스 종료 여부·stdout 꼬리를 텍스트로 반환. `type_text`가 있으면 대기 후 `xdotool type` + Return, 다시 대기 후 캡처. 이미지는 마운트된 문제 폴더에 남으므로 모델은 pillow로 픽셀을 직접 볼 수 있다.
- `revagent/prompts/system.md`: PE 절 갱신 — 콘솔은 `run_binary`, GUI는 `run_gui`, OCR이 깨지면 PNG를 pillow로 열어 밝은 픽셀을 ASCII 그리드로 찍어 읽기.
- `bench/mini/win_console/`, `bench/mini/win_gui/`: mingw로 컴파일하는 자작 PE 2개(콘솔: xor 체크 "Correct"; GUI: `TextOutW`로 `DH{...}`를 창에 그림).
- `scripts/sandbox-build.sh` 스모크: `wine --version`, `Xvfb` 기동, 자작 PE 2개 빌드 후 콘솔은 wine으로 실행해 Correct 확인, GUI는 run_gui 경로로 OCR에 `DH{`가 나오는지 확인.

## 4. 데이터 흐름 (GUI)

```
run_gui(path=CaptainHook.exe, wait_seconds=6)
  → DISPLAY=:99 WINEDEBUG=-all wine CaptainHook.exe &   (백그라운드)
  → sleep 6 → import -display :99 -window root .revagent/screens/001.png
  → tesseract 001.png stdout --psm 6 / --psm 7
  → 반환: 창 목록, OCR 텍스트 2종, 프로세스 상태, PNG 경로
  → 필요 시 모델이 bash로 pillow 픽셀 분석
```

## 5. 에러 처리

| 상황 | 처리 |
|---|---|
| wine 없음(호스트 모드) | 기존 `[cannot run here]` 메시지 + "use --sandbox" |
| Xvfb 안 뜸 | entrypoint가 stderr 경고, run_gui는 `[tool error] no display` |
| 프로그램이 즉시 종료 | 스크린샷은 찍되 "process exited (code N) before capture" 명시 |
| wine 크래시/미지원 API | stderr 꼬리 반환; 모델은 unicorn/정적으로 폴백(플레이북) |
| OCR 빈 결과 | PNG 경로와 "read pixels with pillow" 안내 반환 |
| timeout | 프로세스 그룹 kill(기존 run_cmd 규약) |

## 6. 검증

1. 단위: run_binary의 wine 분기(명령 조립, wine 부재 시 메시지), run_gui 명령 조립·반환 포맷(subprocess는 mock), entrypoint 스크립트 문법.
2. 이미지 스모크: 위 3절 마지막 항목.
3. 배관: `revagent solve --sandbox bench/mini/win_console`, `bench/mini/win_gui` 둘 다 solved.
4. 실전: captain-hook을 `--sandbox`로 재실행(케이스 파일 이어받음).

## 7. 범위 밖

API 후킹(프록시 DLL), Windows Sandbox 경유 실행, 헬퍼 툴(calls/emulate/rasterize)은 3단계.


## 수정 이력

- 2026-09-20: `run_gui`의 `type_text`/`clicks` 파라미터를 일반 입력 스크립트 `actions`(`click` | `click X Y` | `key NAME` | `type TEXT` | `wait N`, 최대 32개, 입력마다 캡처)로 교체. 이유: 클릭 횟수 전용 파라미터와 "한 글자만 보이면 clicks=16" 힌트는 captain-hook 한 문제에 맞춘 오버핏이었다. 플레이북 규칙도 "인터랙티브 프로그램은 입력을 넣어 캡처를 비교한다"는 일반 원칙으로 바꿨고, 클릭이 아닌 키 입력으로 진행하는 미니 벤치 `win_gui_key`를 추가해 일반화를 검증한다.
