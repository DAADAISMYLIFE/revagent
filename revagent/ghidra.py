"""Ghidra headless wrapper: analyze once per binary, cache functions.json, query it."""
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent / "ghidra_scripts"


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
    proj = cache_dir / f"proj_{digest}"
    shutil.rmtree(proj, ignore_errors=True)
    proj.mkdir()
    tmp = cache_dir / f"{out.name}.tmp"
    tmp.unlink(missing_ok=True)
    env = dict(os.environ, JAVA_HOME=str(jdk), PATH=f"{jdk}/bin:{os.environ.get('PATH', '')}")
    cmd = [str(head), str(proj), "proj", "-import", str(binary),
           "-scriptPath", str(SCRIPT_DIR), "-postScript", "DumpFunctions.java", str(tmp),
           "-deleteProject"]
    try:
        r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        tmp.unlink(missing_ok=True)
        raise GhidraError(f"headless analysis timed out after {timeout}s")
    log = cache_dir / f"headless_{digest}.log"
    log.write_text(r.stdout + r.stderr, encoding="utf-8")
    if not tmp.exists():
        raise GhidraError(f"analysis produced no output (exit {r.returncode}); log: {log}\n"
                          + (r.stdout + r.stderr)[-2000:])
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
        self.by_addr = {int(f["entry"], 16): f for f in funcs}

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

    def list_text(self, limit: int = 200) -> str:
        rows = sorted(self.funcs, key=lambda f: -f["size"])[:limit]
        lines = [f"{len(self.funcs)} functions (showing {len(rows)}, sorted by size desc). "
                 f"Format: name @entry size strs=<string refs> calls=<callees>"]
        for f in rows:
            lines.append(f'{f["name"]} @{f["entry"]} {f["size"]} strs={len(f["string_refs"])} '
                         f'calls={len(f["callees"])}' + ("  [thunk]" if f.get("is_thunk") else ""))
        return "\n".join(lines)

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
