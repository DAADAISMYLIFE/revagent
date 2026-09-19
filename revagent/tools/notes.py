SCHEMA = {
    "type": "function",
    "function": {
        "name": "notes",
        "description": (
            "Your case file: the ONLY memory that survives context resets. Write conclusions, not raw "
            "output. Sections: facts (confirmed by tool output: addresses, constants, function roles, "
            "check logic), hypotheses (unverified), todo (next steps), log (history)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["read", "add"]},
                "section": {"type": "string", "enum": ["facts", "hypotheses", "todo", "log"],
                            "description": "for add (default facts)"},
                "text": {"type": "string", "description": "for add: one bullet (may be multi-line)"},
            },
            "required": ["action"],
        },
    },
}


def run(ctx, action: str, section: str = "facts", text: str = "") -> str:
    if action == "read":
        return ctx.casefile.read()
    if action == "add":
        if not text.strip():
            return "[tool error] text is empty"
        try:
            ctx.casefile.add(section, text)
        except ValueError as e:
            return f"[tool error] {e}"
        return f"added to {section}"
    return f"[tool error] unknown action {action!r}; use read or add"
