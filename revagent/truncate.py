from pathlib import Path
from typing import Callable

LIMIT = 12_000


def truncate(text: str, out_dir: Path, next_id: Callable[[], int]) -> str:
    """Cap tool output at LIMIT chars. Longer output is saved whole to out_dir/NNN.txt
    and the returned text ends with a pointer the model can page through with sed/grep."""
    if len(text) <= LIMIT:
        return text
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{next_id():03d}.txt"
    path.write_text(text, encoding="utf-8", errors="replace")
    rel = f".revagent/out/{path.name}"
    return (
        text[:LIMIT]
        + f"\n[truncated: {len(text)} chars total. full output: {rel} "
        + f"— page it with bash: sed -n 'A,Bp' {rel}  or  grep -n PATTERN {rel}]"
    )
