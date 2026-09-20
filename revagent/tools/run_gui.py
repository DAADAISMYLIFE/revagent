"""Run a GUI Windows PE under wine on the sandbox's Xvfb display, then screenshot + OCR it."""
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

DISPLAY = os.environ.get("DISPLAY", ":99")
MAX_WAIT = 60
MAX_CLICKS = 32

SCHEMA = {
    "type": "function",
    "function": {
        "name": "run_gui",
        "description": (
            "Run a GUI Windows program under wine on a virtual display, wait, optionally type text into it, "
            "take a screenshot, and OCR it. Returns window names, two OCR readings (psm 6 block / psm 7 line) "
            "and the PNG path under .revagent/screens/ so you can also read pixels with pillow via bash. "
            "With clicks=N the tool left-clicks the window centre N times and captures after every click (one PNG each) — "
            "use this when the program reveals one character per click. The program is killed after the last capture; "
            "call again to re-run. Use run_binary for console PEs."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "exe path relative to the challenge dir"},
                "args": {"type": "array", "items": {"type": "string"}},
                "wait_seconds": {"type": "integer", "description": "seconds before the capture (default 5, max 60)"},
                "type_text": {"type": "string", "description": "text typed into the focused window (then Enter) before a second wait and the capture"},
                "clicks": {"type": "integer", "description": "number of left-clicks on the window centre after the first capture, capturing after each (default 0, max 32)"},
            },
            "required": ["path"],
        },
    },
}


def launch_cmd(exe: Path, args: list[str]) -> list[str]:
    return ["wine", str(exe), *args]


def _display_ok(env: dict) -> bool:
    r = _run_quiet(["xdpyinfo", "-display", env["DISPLAY"]], env, 10)
    return r is not None and r.returncode == 0


def _run_quiet(cmd: list[str], env: dict, timeout: float) -> subprocess.CompletedProcess | None:
    """subprocess.run that turns a timeout/OS error into None instead of raising, so a slow or
    missing wine/X tool degrades the report instead of skipping the killpg cleanup below."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None


def _ocr(png: Path, psm: int, env: dict) -> str:
    r = _run_quiet(["tesseract", str(png), "stdout", "--psm", str(psm)], env, 60)
    if r is None:
        return "(timeout)"
    return (r.stdout or "").strip() or "(empty)"


def _window_center(env: dict) -> tuple[int, int]:
    """Centre of the first visible window (falls back to (100, 120) when geometry cannot be read)."""
    r = _run_quiet(["xdotool", "search", "--onlyvisible", "--name", ".", "getwindowgeometry", "%1"], env, 10)
    x = y = w = h = None
    for line in ((r.stdout if r else "") or "").splitlines():
        line = line.strip()
        if line.startswith("Position:"):
            try:
                x, y = (int(v) for v in line.split()[1].split(","))
            except ValueError:
                pass
        elif line.startswith("Geometry:"):
            try:
                w, h = (int(v) for v in line.split()[1].split("x"))
            except ValueError:
                pass
    if None in (x, y, w, h):
        return 100, 120
    return x + w // 2, y + h // 2


def _windows(env: dict) -> str:
    r = _run_quiet(["xdotool", "search", "--onlyvisible", "--name", ".", "getwindowname", "%@"], env, 10)
    if r is None:
        return "(timeout)"
    names = [l for l in (r.stdout or "").splitlines() if l.strip()]
    return ", ".join(names) or "(none)"


def _next_screenshot_path(screens: Path) -> Path:
    existing = [int(f.stem) for f in screens.glob("*.png") if f.stem.isdigit()]
    next_n = max(existing) + 1 if existing else 1
    return screens / f"{next_n:03d}.png"


def run(ctx, path: str, args: list[str] | None = None, wait_seconds: int = 5, type_text: str = "",
        clicks: int = 0) -> str:
    for tool in ("wine", "import", "tesseract", "xdotool", "xdpyinfo"):
        if shutil.which(tool) is None:
            return f"[cannot run here] {tool} is not installed on the host; run with --sandbox (the image has wine + Xvfb + OCR)."
    problem_dir = ctx.problem_dir.resolve()
    p = (ctx.problem_dir / path).resolve()
    if not p.is_relative_to(problem_dir):
        return f"[tool error] path escapes the challenge directory: {path}"
    if not p.is_file():
        return f"[tool error] no such file: {path}"
    scrubbed = {k: v for k, v in os.environ.items() if k not in ("QWEN", "URL", "MODEL")}
    env = {**scrubbed, "DISPLAY": DISPLAY, "WINEDEBUG": "-all"}
    if not _display_ok(env):
        return f"[tool error] no display at {DISPLAY}; the sandbox entrypoint should have started Xvfb"
    wait = max(1, min(int(wait_seconds), MAX_WAIT))
    cmd = launch_cmd(p, list(args or []))
    proc = subprocess.Popen(cmd, cwd=str(ctx.problem_dir), env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    info = {"tail": "", "clicks": ""}
    n_clicks = 0
    try:
        time.sleep(wait)
        if type_text:
            _run_quiet(["xdotool", "search", "--onlyvisible", "--name", ".", "windowfocus", "%@"], env, 10)
            _run_quiet(["xdotool", "type", "--delay", "20", "--", type_text], env, 30)
            _run_quiet(["xdotool", "key", "Return"], env, 10)
            time.sleep(min(wait, 5))
        screens = ctx.work_dir / "screens"
        screens.mkdir(parents=True, exist_ok=True)
        png = _next_screenshot_path(screens)
        shot = _run_quiet(["import", "-display", DISPLAY, "-window", "root", str(png)], env, 30)
        info["windows"] = _windows(env)
        info["state"] = ("still running at capture" if proc.poll() is None
                          else f"exited (code {proc.returncode}) before capture")
        if shot is not None and png.exists():
            info["screenshot_line"] = f"screenshot: .revagent/screens/{png.name}"
            info["ocr6"] = _ocr(png, 6, env)
            info["ocr7"] = _ocr(png, 7, env)
        else:
            info["screenshot_line"] = "screenshot: failed (timeout)"
            info["ocr6"] = "(timeout)"
            info["ocr7"] = "(timeout)"
        n_clicks = max(0, min(int(clicks or 0), MAX_CLICKS))
        click_lines = []
        if n_clicks:
            cx, cy = _window_center(env)
            for i in range(1, n_clicks + 1):
                _run_quiet(["xdotool", "mousemove", str(cx), str(cy), "click", "1"], env, 10)
                time.sleep(1)
                cpng = _next_screenshot_path(screens)
                cshot = _run_quiet(["import", "-display", DISPLAY, "-window", "root", str(cpng)], env, 30)
                if cshot is not None and cpng.exists():
                    ocr = _ocr(cpng, 7, env).replace("\n", " ")[:80]
                    click_lines.append(f"click {i}: .revagent/screens/{cpng.name}  ocr7: {ocr}")
                else:
                    click_lines.append(f"click {i}: capture failed")
        info["clicks"] = "\n".join(click_lines)
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            out, _ = proc.communicate(timeout=5)
            info["tail"] = (out or b"").decode("utf-8", errors="replace")[-800:]
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
        except Exception:
            pass
    return (f"launched: {' '.join(cmd)}\nprocess: {info['state']}\nwindows: {info['windows']}\n"
            f"{info['screenshot_line']}\n--- OCR psm6 (block) ---\n{info['ocr6']}\n"
            f"--- OCR psm7 (single line) ---\n{info['ocr7']}\n"
            + (f"--- captures after clicks (centre {n_clicks} clicks) ---\n{info['clicks']}\n" if info.get("clicks") else "")
            + f"--- program output (tail) ---\n{info['tail'] or '(none)'}\n"
            f"If the OCR is wrong, open the PNG(s) with pillow in bash and print dark/bright pixels as an ASCII grid.")
