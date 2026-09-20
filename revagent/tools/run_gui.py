"""Run a GUI Windows PE under wine on the sandbox's Xvfb display, then screenshot + OCR it."""
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

DISPLAY = os.environ.get("DISPLAY", ":99")
MAX_WAIT = 60
MAX_ACTIONS = 32
ACTION_WAIT_MAX = 10

SCHEMA = {
    "type": "function",
    "function": {
        "name": "run_gui",
        "description": (
            "Run a GUI Windows program under wine on a virtual display, wait, take a screenshot and OCR it. "
            "Returns window names, two OCR readings (psm 6 block / psm 7 line) and the PNG path under "
            ".revagent/screens/ so you can also read pixels with pillow via bash. "
            "GUI programs are event-driven: pass `actions` to drive them after the first capture. Each action is "
            "one string: 'click' / 'rclick' / 'dclick' (left / right / double click at the window centre, or at 'click X Y' where X Y is a screen pixel = PNG pixel), 'key NAME' (xdotool key, "
            "e.g. Return, space, a, F1), 'type TEXT', 'wait N'. Every click/key/type is followed by a capture "
"(one PNG each, OCR line, and what changed vs the previous capture: pixel count, bounding box and a "
            "<NNN>.diff.png holding only the changed pixels, so static noise cancels out). "
            "The program is killed after the last capture; call again to re-run. Use run_binary for console PEs."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "exe path relative to the challenge dir"},
                "args": {"type": "array", "items": {"type": "string"}},
                "wait_seconds": {"type": "integer", "description": "seconds before the first capture (default 5, max 60)"},
                "actions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "input script run after the first capture, max 32 entries: 'click'|'rclick'|'dclick' [X Y] | 'key NAME' | 'type TEXT' | 'wait N'",
                },
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
    g = _window_geometry(env)
    if g is None:
        return 100, 120
    x, y, w, h = g
    return x + w // 2, y + h // 2


def _reset_display(env: dict) -> str:
    """Kill wine processes left on the display by earlier launches (e.g. `wine x.exe &` from bash): their
    windows would overlap the capture and the report would describe the wrong program. Returns a note."""
    before = _windows(env)
    if before == "(none)" or before == "(timeout)":
        return ""
    if shutil.which("wineserver"):
        _run_quiet(["wineserver", "-k"], env, 20)
        time.sleep(1)
    return f"killed leftover wine windows before launch: {before}"


def _windows(env: dict) -> str:
    r = _run_quiet(["xdotool", "search", "--onlyvisible", "--name", ".", "getwindowname", "%@"], env, 10)
    if r is None:
        return "(timeout)"
    names = [l for l in (r.stdout or "").splitlines() if l.strip()]
    return ", ".join(names) or "(none)"


def _window_geometry(env: dict) -> tuple[int, int, int, int] | None:
    r = _run_quiet(["xdotool", "search", "--onlyvisible", "--name", ".", "getwindowgeometry", "%1"], env, 10)
    x = y = w = h = None
    for line in ((r.stdout if r else "") or "").splitlines():
        line = line.strip()
        try:
            if line.startswith("Position:"):
                x, y = (int(v) for v in line.split()[1].split(","))
            elif line.startswith("Geometry:"):
                w, h = (int(v) for v in line.split()[1].split("x"))
        except ValueError:
            pass
    if None in (x, y, w, h):
        return None
    return x, y, w, h


def _window_content(png: Path, geom: tuple[int, int, int, int] | None) -> str:
    """How much is drawn inside the window: pixels that differ from the window's dominant colour.
    A blank window (uniform colour) is reported explicitly so an empty OCR is not mistaken for a
    rendering quirk of wine while the program actually drew nothing."""
    try:
        from PIL import Image
    except ImportError:
        return ""
    try:
        im = Image.open(png).convert("L")
        if geom:
            x, y, w, h = geom
            im = im.crop((max(0, x), max(0, y), min(im.width, x + w), min(im.height, y + h)))
        hist = im.histogram()
        total = sum(hist)
        if not total:
            return ""
        drawn = total - max(hist)
        if drawn == 0:
            return "window content: blank (uniform colour; the program drew nothing visible)"
        return f"window content: {drawn} px differ from the background ({100 * drawn / total:.1f}%)"
    except Exception:
        return ""


def _diff_capture(prev: Path, cur: Path) -> str:
    """Compare two captures; write cur's changed pixels to <cur>.diff.png (black on white) and describe them.
    Static noise (lines, background) cancels out, so the diff image shows only what the input changed."""
    try:
        from PIL import Image, ImageChops
    except ImportError:
        return ""
    try:
        a = Image.open(prev).convert("L")
        b = Image.open(cur).convert("L")
        if a.size != b.size:
            return "changed: (size differs)"
        d = ImageChops.difference(a, b).point(lambda v: 255 if v > 40 else 0)
        box = d.getbbox()
        if box is None:
            return "changed: nothing"
        n = d.histogram()[255]
        out = cur.with_name(cur.stem + ".diff.png")
        d.point(lambda v: 0 if v else 255).save(out)
        return f"changed: {n} px in bbox {box}  diff: .revagent/screens/{out.name}"
    except Exception as e:  # a broken PNG must not abort the action loop
        return f"changed: (diff failed: {e.__class__.__name__})"


def _next_screenshot_path(screens: Path) -> Path:
    existing = [int(f.stem) for f in screens.glob("*.png") if f.stem.isdigit()]
    next_n = max(existing) + 1 if existing else 1
    return screens / f"{next_n:03d}.png"


def _last_capture_name(screens: Path) -> str:
    existing = sorted(int(f.stem) for f in screens.glob("*.png") if f.stem.isdigit())
    return f"{existing[-1]:03d}" if existing else "?"


def _parse_action(spec: str) -> tuple[str, list[str]] | None:
    """'click' | 'click X Y' | 'key NAME' | 'type TEXT' | 'wait N' -> (verb, argv) or None when malformed."""
    parts = str(spec).strip().split(None, 1)
    if not parts:
        return None
    verb, rest = parts[0].lower(), (parts[1] if len(parts) > 1 else "")
    if verb in ("click", "rclick", "dclick"):
        if not rest:
            return verb, []
        xy = rest.split()
        if len(xy) == 2 and all(v.lstrip("-").isdigit() for v in xy):
            return verb, xy
        return None
    if verb == "key" and rest and len(rest.split()) == 1:
        return "key", [rest]
    if verb == "type" and rest:
        return "type", [rest]
    if verb == "wait" and rest.isdigit():
        return "wait", [str(min(int(rest), ACTION_WAIT_MAX))]
    return None


CLICK_ARGS = {"click": ["click", "1"], "rclick": ["click", "3"], "dclick": ["click", "--repeat", "2", "1"]}


def _apply_action(verb: str, argv: list[str], env: dict) -> str:
    """Perform one parsed action; returns '' on success or a short failure note (xdotool error text)."""
    if verb in CLICK_ARGS:
        if argv:
            x, y = argv
        else:
            x, y = (str(v) for v in _window_center(env))
        r = _run_quiet(["xdotool", "mousemove", x, y, *CLICK_ARGS[verb]], env, 10)
    elif verb == "key":
        _run_quiet(["xdotool", "search", "--onlyvisible", "--name", ".", "windowfocus", "%@"], env, 10)
        r = _run_quiet(["xdotool", "key", "--", argv[0]], env, 10)
    elif verb == "type":
        _run_quiet(["xdotool", "search", "--onlyvisible", "--name", ".", "windowfocus", "%@"], env, 10)
        r = _run_quiet(["xdotool", "type", "--delay", "20", "--", argv[0]], env, 30)
    else:  # wait
        time.sleep(int(argv[0]))
        return ""
    if r is None:
        return "xdotool timed out"
    # xdotool exits 0 for an unknown keysym ("No such key name ... Ignoring it.") and only warns on stderr,
    # so any stderr line counts as a failure: an input that was not delivered must not look like one that was.
    err = [l for l in ((r.stderr or "") + (r.stdout or "")).strip().splitlines() if l.strip()]
    if r.returncode != 0 or err:
        return "xdotool failed: " + (err[-1][:120] if err else f"exit {r.returncode}")
    return ""


def run(ctx, path: str, args: list[str] | None = None, wait_seconds: int = 5,
        actions: list[str] | None = None) -> str:
    for tool in ("wine", "import", "tesseract", "xdotool", "xdpyinfo"):
        if shutil.which(tool) is None:
            ctx.env_blocked = True
            ctx.observe(f"run_gui {path}: [cannot run here]")
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
    reset_note = _reset_display(env)
    cmd = launch_cmd(p, list(args or []))
    proc = subprocess.Popen(cmd, cwd=str(ctx.problem_dir), env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    info = {"tail": "", "actions": ""}
    action_specs = [str(a) for a in (actions or [])][:MAX_ACTIONS]
    try:
        time.sleep(wait)
        screens = ctx.work_dir / "screens"
        screens.mkdir(parents=True, exist_ok=True)
        png = _next_screenshot_path(screens)
        first_png_name = png.stem
        shot = _run_quiet(["import", "-display", DISPLAY, "-window", "root", str(png)], env, 30)
        info["windows"] = _windows(env)
        info["state"] = ("still running at capture" if proc.poll() is None
                          else f"exited (code {proc.returncode}) before capture")
        if shot is not None and png.exists():
            content = _window_content(png, _window_geometry(env))
            info["screenshot_line"] = f"screenshot: .revagent/screens/{png.name}" + (f"\n{content}" if content else "")
            info["ocr6"] = _ocr(png, 6, env)
            info["ocr7"] = _ocr(png, 7, env)
        else:
            info["screenshot_line"] = "screenshot: failed (timeout)"
            info["ocr6"] = "(timeout)"
            info["ocr7"] = "(timeout)"
        action_lines = []
        prev_png = png if (shot is not None and png.exists()) else None
        for i, spec in enumerate(action_specs, 1):
            parsed = _parse_action(spec)
            if parsed is None:
                action_lines.append(f"{i}. {spec!r}: ignored (expected 'click'|'rclick'|'dclick' [X Y] | 'key NAME' | 'type TEXT' | 'wait N')")
                continue
            verb, argv = parsed
            fail = _apply_action(verb, argv, env)
            if verb == "wait":
                action_lines.append(f"{i}. wait {argv[0]}")
                continue
            if fail:
                action_lines.append(f"{i}. {spec}: NOT DELIVERED ({fail}); key names are xdotool keysyms such as "
                                    f"Return, space, Escape, F1, a; mouse buttons are click/rclick/dclick")
                continue
            time.sleep(1)
            apng = _next_screenshot_path(screens)
            ashot = _run_quiet(["import", "-display", DISPLAY, "-window", "root", str(apng)], env, 30)
            if ashot is not None and apng.exists():
                ocr = _ocr(apng, 7, env).replace("\n", " ")[:80]
                diff = _diff_capture(prev_png, apng) if prev_png else ""
                action_lines.append(f"{i}. {spec}: .revagent/screens/{apng.name}  ocr7: {ocr}" + (f"  {diff}" if diff else ""))
                prev_png = apng
            else:
                action_lines.append(f"{i}. {spec}: capture failed")
        info["actions"] = "\n".join(action_lines)
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
    n_inputs = sum(1 for s in action_specs if (_parse_action(s) or ("wait", []))[0] != "wait")
    n_changed = sum(1 for l in info["actions"].splitlines() if "changed:" in l and "changed: nothing" not in l)
    n_unchanged = sum(1 for l in info["actions"].splitlines() if "changed: nothing" in l)
    n_undelivered = info["actions"].count("NOT DELIVERED")
    last_png = _last_capture_name(screens)
    ctx.observe(f"run_gui {path}{' ' + ' '.join(args) if args else ''}: windows: {info.get('windows', '?')}; "
                f"{info.get('state', '?')}; inputs: {n_inputs} (changed {n_changed}, unchanged {n_unchanged}, "
                f"undelivered {n_undelivered}); captures: {first_png_name}-{last_png}")
    if info.get("windows") in ("(none)", "(timeout)"):
        ctx.note_start_failure()
    return ((reset_note + "\n") if reset_note else "") + (f"launched: {' '.join(cmd)}\nprocess: {info['state']}\nwindows: {info['windows']}\n"
            f"{info['screenshot_line']}\n--- OCR psm6 (block) ---\n{info['ocr6']}\n"
            f"--- OCR psm7 (single line) ---\n{info['ocr7']}\n"
            + (f"--- captures after actions ---\n{info['actions']}\n" if info.get("actions") else "")
            + f"--- program output (tail) ---\n{info['tail'] or '(none)'}\n"
            f"If the OCR is wrong, open the PNG(s) with pillow in bash and print dark/bright pixels as an ASCII grid."
            + ("" if action_specs else "\nThis was a passive look. GUI programs change state on input: if the picture is "
                                       "incomplete or waits for the user, call run_gui again with actions "
                                       "(e.g. [\"click\",\"rclick\",\"key space\",\"type abc\",\"key Return\"]) and read every capture."))
