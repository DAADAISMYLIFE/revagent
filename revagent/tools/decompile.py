from ..ghidra import FunctionDB, GhidraError, analyze

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
            },
            "required": ["action"],
        },
    },
}


def _get_db(ctx, binary: str) -> FunctionDB:
    if binary:
        p = ctx.problem_dir / binary
        if not p.is_file():
            raise GhidraError(f"no such file: {binary}")
        key = str(p.resolve())
        if key not in ctx.function_dbs:
            json_path = analyze(p, ctx.work_dir / "ghidra")
            ctx.function_dbs[key] = FunctionDB.load(json_path)
        ctx.current_binary = key
    if not ctx.current_binary:
        raise GhidraError("no binary analyzed yet; call decompile with binary=<path> first")
    return ctx.function_dbs[ctx.current_binary]


def run(ctx, action: str, target: str = "", binary: str = "") -> str:
    if binary:
        problem_dir = ctx.problem_dir.resolve()
        p = (ctx.problem_dir / binary).resolve()
        if not p.is_relative_to(problem_dir):
            return f"[tool error] path escapes the challenge directory: {binary}"
    try:
        db = _get_db(ctx, binary)
    except GhidraError as e:
        return (f"[decompile unavailable] {e}\n"
                f"Fallback: bash `objdump -d -M intel <bin> > dis.txt` and read the assembly in ranges.")
    if action == "list":
        return db.list_text()
    if action == "get":
        return db.get_text(target)
    if action == "xrefs":
        return db.xrefs_text(target)
    return f"[tool error] unknown action {action!r}; use list, get or xrefs"
