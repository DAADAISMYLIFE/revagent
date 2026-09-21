from ..ghidra import FunctionDB, GhidraError, analyze
from .base import PathError, resolve_inside

SCHEMA = {
    "type": "function",
    "function": {
        "name": "decompile",
        "description": (
            "Ghidra decompiler. First call must pass binary=<path>; analysis runs once (may take minutes) "
            "and is cached. action=list: functions sorted by size with string-ref and call counts. "
            "action=get target=<name or 0xaddr>: decompiled C of one function. action=xrefs target=...: "
            "callers, callees, referenced strings. For huge functions, save the C to a file via bash "
            "and use summarize instead of reading it all."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["list", "get", "xrefs"]},
                "target": {"type": "string", "description": "function name or 0x address (get/xrefs)"},
                "binary": {"type": "string", "description": "path relative to challenge dir (required on first call)"},
                "limit": {"type": "integer",
                          "description": "action=list: max functions to show, sorted by size desc (default 200)"},
                "filter": {"type": "string",
                           "description": "action=list: only include functions whose name contains this "
                                          "substring (case-insensitive)"},
            },
            "required": ["action"],
        },
    },
}


def _get_db(ctx, binary: str, p) -> FunctionDB:
    """p is the resolved path of `binary` (from resolve_inside), or None when binary is empty."""
    if binary:
        if not p.is_file():
            raise GhidraError(f"no such file: {binary}")
        key = str(p)
        cached = ctx.function_dbs.get(key)
        if isinstance(cached, GhidraError):
            raise GhidraError(f"previous analysis failed; not retrying: {cached}")
        if cached is None:
            try:
                # analyze() gets the path as the model named it (not the resolved one): the cache file
                # and the Ghidra program are named after it, and the playbook tells the model to grep
                # `.revagent/ghidra/<binary>.<hash>.functions.json` by that name.
                json_path = analyze(ctx.problem_dir / binary, ctx.work_dir / "ghidra",
                                    timeout=ctx.clamp_timeout(1200))
            except GhidraError as e:
                # Negative cache: never re-run analysis on a binary that already
                # failed (e.g. timed out) within this session.
                ctx.function_dbs[key] = e
                raise
            ctx.function_dbs[key] = FunctionDB.load(json_path)
        ctx.current_binary = key
        ctx.current_binary_rel = binary
    if not ctx.current_binary:
        raise GhidraError("no binary analyzed yet; call decompile with binary=<path> first")
    db = ctx.function_dbs[ctx.current_binary]
    if isinstance(db, GhidraError):
        raise GhidraError(f"previous analysis failed; not retrying: {db}")
    return db


def _emulate_hint(ctx, f: dict) -> str:
    """Prepended (truncate() cuts the tail) to the C of a function whose callees are all inside the
    image: the model can run it under emulate as the oracle for its re-implementation."""
    callees = ", ".join(sorted(f["callees"])) or "none"
    binary = ctx.current_binary_rel or "<the binary you analyzed>"
    return (f"[hint] this function calls no imports (callees: {callees}), so emulate can run it directly: "
            f"emulate(binary={binary}, function={f['name']}, args=[\"hex:<input bytes>\"]) — compare its output "
            "with your re-implementation before inverting anything.\n")


def run(ctx, action: str, target: str = "", binary: str = "", limit: int = 200, filter: str = "") -> str:
    p = None
    if binary:
        try:
            p = resolve_inside(ctx, binary, must_exist=False)  # missing file is reported by _get_db
        except PathError as e:
            return str(e)
    try:
        db = _get_db(ctx, binary, p)
    except GhidraError as e:
        return (f"[decompile unavailable] {e}\n"
                f"Fallback: bash `objdump -d -M intel <bin> > dis.txt` and read the assembly in ranges.")
    if action == "list":
        return db.list_text(limit=limit, name_filter=filter)
    if action == "get":
        text = db.get_text(target)
        f = db.find(target)
        if f and f["decompiled_c"] and db.calls_no_imports(target):
            text = _emulate_hint(ctx, f) + text
        return text
    if action == "xrefs":
        return db.xrefs_text(target)
    return f"[tool error] unknown action {action!r}; use list, get or xrefs"
