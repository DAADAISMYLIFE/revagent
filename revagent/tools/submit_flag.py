import re

FLAG_RE = re.compile(r"^[A-Za-z0-9_]+\{.+\}$")  # PREFIX{...}; the prefix comes from the challenge description (Dreamhack: DH)

SCHEMA = {
    "type": "function",
    "function": {
        "name": "submit_flag",
        "description": (
            "Submit the final flag and end the session. Format is PREFIX{...} with the prefix the description "
            "states (Dreamhack default DH{...}; e.g. XMAS{...} if the description says so). Only call after you "
            "VERIFIED it (run_binary printed the success message, or your Python re-implementation of "
            "the check accepts it). Describe the verification in how_verified."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "flag": {"type": "string"},
                "how_verified": {"type": "string", "description": "what you ran and what it printed"},
            },
            "required": ["flag", "how_verified"],
        },
    },
}


def run(ctx, flag: str, how_verified: str = "") -> str:
    flag = flag.strip()
    if not FLAG_RE.match(flag):
        return (f"[rejected] {flag!r} does not look like PREFIX{{...}}. Use the prefix the description "
                f"states (Dreamhack default DH). If the description says the flag is PREFIX{{<correct input>}}, "
                f"wrap the verified input; otherwise find the real flag string.")
    if not how_verified.strip():
        return "[rejected] how_verified is empty. Verify first (run_binary or re-implemented check), then resubmit."
    ctx.flag = flag
    ctx.how_verified = how_verified.strip()
    return "[accepted] flag recorded; the session will end now."
