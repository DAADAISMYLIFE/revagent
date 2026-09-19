SCHEMA = {
    "type": "function",
    "function": {
        "name": "ask_user",
        "description": (
            "Ask the human a question and wait for the answer. ONLY when truly blocked: a remote "
            "host:port is needed, a file is missing, or two hypotheses cannot be separated by tools. "
            "Do not ask for hints on how to reverse."
        ),
        "parameters": {
            "type": "object",
            "properties": {"question": {"type": "string"}},
            "required": ["question"],
        },
    },
}


def run(ctx, question: str) -> str:
    if not ctx.interactive:
        return "[user unavailable] running non-interactively; make a reasonable assumption and continue."
    print(f"\n\033[1m[QUESTION FROM AGENT]\033[0m {question}\n> ", end="", flush=True)
    try:
        answer = input()
    except EOFError:
        return "[user unavailable] no stdin; make a reasonable assumption and continue."
    return answer.strip() or "(empty answer)"
