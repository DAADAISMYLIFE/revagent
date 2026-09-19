"""Run a GUI Windows PE under wine on the sandbox's Xvfb display, then screenshot + OCR it."""
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

DISPLAY = os.environ.get("DISPLAY", ":99")
MAX_WAIT = 60

SCHEMA = {
    "type": "function",
    "function": {
        "name": "run_gui",
        "description": (
            "Run a GUI Windows program under wine on a virtual display, wait, optionally type text into it, "
            "take a screenshot, and OCR it. Returns window names, two OCR readings (psm 6 block / psm 7 line) "
            "and the PNG path under .revagent/screens/ so you can also read pixels with pillow via bash. "
            "The program is killed after the capture; call again to re-run. Use run_binary for console PEs."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "exe path relative to the challenge dir"},
                "args": {"type": "array", "items": {"type": "string"}},
                "wait_seconds": {"type": "integer", "description": "seconds before the capture (default 5, max 60)"},
                "type_text": {"type": "string", "description": "text typed into the focused window (then Enter) before a second wait and the capture"},
            },
            "required": ["path"],
        },
    },
}


def launch_cmd(exe: Path, args: list[str]) -> list[str]:
    return ["wine", str(exe), *args]


def _display_ok(env: dict) -> bool:
    r = subprocess.run(["xdpyinfo", "-display", env["DISPLAY"]], capture_output=True, text=True, env=env, timeout=10)
    return r.returncode == 0


def _ocr(png: Path, psm: int, env: dict) -> str:
    r = subprocess.run(["tesseract", str(png), "stdout", "--psm", str(psm)], capture_output=True, text=True, env=env, timeout=60)
    return (r.stdout or "").strip() or "(empty)"


def _windows(env: dict) -> str:
    r = subprocess.run(["xdotool", "search", "--onlyvisible", "--name", ".", "getwindowname", "%@"],
                       capture_output=True, text=True, env=env, timeout=10)
    names = [l for l in (r.stdout or "").splitlines() if l.strip()]
    return ", ".join(names) or "(none)"


def run(ctx, path: str, args: list[str] | None = None, wait_seconds: int = 5, type_text: str = "") -> str:
    for tool in ("wine", "import", "tesseract", "xdotool", "xdpyinfo"):
        if shutil.which(tool) is None:
            return f"[cannot run here] {tool} is not installed on the host; run with --sandbox (the image has wine + Xvfb + OCR)."
    problem_dir = ctx.problem_dir.resolve()
    p = (ctx.problem_dir / path).resolve()
    if not p.is_relative_to(problem_dir):
        return f"[tool error] path escapes the challenge directory: {path}"
    if not p.is_file():
        return f"[tool error] no such file: {path}"
    env = {**os.environ, "DISPLAY": DISPLAY, "WINEDEBUG": "-all"}
    if not _display_ok(env):
        return f"[tool error] no display at {DISPLAY}; the sandbox entrypoint should have started Xvfb"
    wait = max(1, min(int(wait_seconds), MAX_WAIT))
    cmd = launch_cmd(p, list(args or []))
    proc = subprocess.Popen(cmd, cwd=str(ctx.problem_dir), env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, start_new_session=True)
    time.sleep(wait)
    if type_text:
        subprocess.run(["xdotool", "type", "--delay", "20", type_text], env=env, timeout=30)
        subprocess.run(["xdotool", "key", "Return"], env=env, timeout=10)
        time.sleep(min(wait, 5))
    screens = ctx.work_dir / "screens"
    screens.mkdir(parents=True, exist_ok=True)
    png = screens / f"{len(list(screens.glob('*.png'))) + 1:03d}.png"
    subprocess.run(["import", "-display", DISPLAY, "-window", "root", str(png)], env=env, timeout=30)
    windows = _windows(env)
    state = "still running at capture" if proc.poll() is None else f"exited (code {proc.returncode}) before capture"
    ocr6 = _ocr(png, 6, env) if png.exists() else "(no screenshot)"
    ocr7 = _ocr(png, 7, env) if png.exists() else "(no screenshot)"
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        out, _ = proc.communicate(timeout=5)
    except Exception:
        out = b""
    tail = (out or b"").decode("utf-8", errors="replace")[-800:]
    rel = f".revagent/screens/{png.name}"
    return (f"launched: {' '.join(cmd)}\nprocess: {state}\nwindows: {windows}\n"
            f"screenshot: {rel}\n--- OCR psm6 (block) ---\n{ocr6}\n--- OCR psm7 (single line) ---\n{ocr7}\n"
            f"--- program output (tail) ---\n{tail or '(none)'}\n"
            f"If the OCR is wrong, open the PNG with pillow in bash and print bright pixels as an ASCII grid.")
