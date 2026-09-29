"""Ghidra headless wrapper: analyze once per binary, cache functions.json, query it."""
import hashlib
import json
import os
import re
import signal
import subprocess
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent / "ghidra_scripts"
INTERNAL_NAME_RE = re.compile(r"^(thunk_)?FUN_[0-9a-fA-F]+$")   # Ghidra's auto-name for code inside the image


class GhidraError(Exception):
    pass


def find_ghidra() -> tuple[Path, Path]:
    tools = Path(os.path.expanduser("~")) / "tools"
    heads = sorted(tools.glob("ghidra_*/support/analyzeHeadless"))
    jdks = sorted(tools.glob("jdk-21*"))
    if not heads or not jdks:
        raise GhidraError("Ghidra or JDK 21 not found under ~/tools. Run scripts/install_ghidra.sh")
    return heads[-1], jdks[-1]


def analyze(binary: Path, cache_dir: Path, timeout: int = 1200) -> Path:
    binary = Path(binary)
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()[:16]
    out = cache_dir / f"{binary.name}.{digest}.functions.json"
    if out.exists():
        try:
            json.loads(out.read_text(encoding="utf-8"))
            return out
        except json.JSONDecodeError:
            out.unlink()
    head, jdk = find_ghidra()
    tmp = cache_dir / f"{out.name}.tmp"
    tmp.unlink(missing_ok=True)
    env = dict(os.environ, JAVA_HOME=str(jdk), PATH=f"{jdk}/bin:{os.environ.get('PATH', '')}")
    log = cache_dir / f"headless_{digest}.log"
    # The Ghidra project directory must live outside cache_dir: Ghidra's
    # ProjectLocator rejects any path with a component starting with '.', and
    # cache_dir is typically under a hidden .revagent/ directory. Use a plain
    # system temp dir for the ephemeral project instead.
    with tempfile.TemporaryDirectory(prefix="revagent_ghidra_") as proj_parent:
        proj = Path(proj_parent) / "proj"
        proj.mkdir()
        cmd = [str(head), str(proj), "proj", "-import", str(binary),
               "-scriptPath", str(SCRIPT_DIR), "-postScript", "DumpFunctions.java", str(tmp),
               "-deleteProject"]
        # start_new_session=True puts the JVM (and any children it spawns) in its own
        # process group, so a timeout can kill the whole group instead of orphaning it.
        p = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, start_new_session=True)
        try:
            combined, _ = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                combined, _ = p.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                combined = ""
            tmp.unlink(missing_ok=True)
            log.write_text(combined or "", encoding="utf-8")
            raise GhidraError(f"headless analysis timed out after {timeout}s")
        returncode = p.returncode
    log.write_text(combined, encoding="utf-8")
    if not tmp.exists():
        raise GhidraError(f"analysis produced no output (exit {returncode}); log: {log}\n"
                          + combined[-2000:])
    try:
        json.loads(tmp.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        tmp.unlink()
        raise GhidraError(f"analysis output was not valid JSON (killed mid-write?); log: {log}")
    os.replace(tmp, out)
    return out


class FunctionDB:
    def __init__(self, funcs: list[dict]):
        self.funcs = funcs
        self.by_name = {f["name"]: f for f in funcs}
        self.by_addr = {}
        for f in funcs:
            try:
                self.by_addr[int(f["entry"], 16)] = f
            except ValueError:
                continue  # unparsable address (e.g. "ram:00401000"); skip, keep by-name lookup

    @classmethod
    def load(cls, path: Path) -> "FunctionDB":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def find(self, target: str) -> dict | None:
        t = target.strip()
        if t in self.by_name:
            return self.by_name[t]
        try:
            return self.by_addr.get(int(t, 16))
        except ValueError:
            return None

    def list_text(self, limit: int = 200, name_filter: str = "") -> str:
        funcs = self.funcs
        if name_filter:
            nf = name_filter.lower()
            funcs = [f for f in funcs if nf in f["name"].lower()]
        rows = sorted(funcs, key=lambda f: -f["size"])[:limit]
        filter_note = f" filter={name_filter!r}" if name_filter else ""
        lines = [f"{len(funcs)} functions (showing {len(rows)}, sorted by size desc){filter_note}. "
                 f"Format: name @entry size strs=<string refs> calls=<callees>"]
        for f in rows:
            lines.append(f'{f["name"]} @{f["entry"]} {f["size"]} strs={len(f["string_refs"])} '
                         f'calls={len(f["callees"])}' + ("  [thunk]" if f.get("is_thunk") else ""))
        return "\n".join(lines)

    def calls_no_imports(self, target: str) -> bool | None:
        """True when every callee is code inside the image (a FUN_/thunk_FUN_ name, or a non-thunk
        function of this DB), so `emulate` can run the function without hitting an import stop;
        False when some callee is an import (a thunk, or a name Ghidra did not define, e.g. strlen);
        None when the function is not found."""
        f = self.find(target)
        if not f:
            return None
        for callee in f["callees"]:
            if INTERNAL_NAME_RE.match(callee):
                continue
            g = self.by_name.get(callee)
            if g is None or g.get("is_thunk"):
                return False
        return True

    def get_text(self, target: str) -> str:
        f = self.find(target)
        if not f:
            return f"[not found] {target!r}; use action=list to see names/addresses"
        return f["decompiled_c"] or f"[decompilation failed or empty for {f['name']}]"

    def xrefs_text(self, target: str) -> str:
        f = self.find(target)
        if not f:
            return f"[not found] {target!r}; use action=list to see names/addresses"
        return (f"{f['name']} @{f['entry']} size={f['size']}\n"
                f"callers: {', '.join(sorted(f['callers'])) or '-'}\n"
                f"callees: {', '.join(sorted(f['callees'])) or '-'}\n"
                f"strings: {', '.join(repr(s) for s in f['string_refs']) or '-'}")
