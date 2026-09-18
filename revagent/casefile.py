from pathlib import Path

SECTIONS = {
    "facts": "## Facts",
    "hypotheses": "## Hypotheses",
    "todo": "## Todo",
    "log": "## Log",
}


class CaseFile:
    """External memory for the agent. Fixed sections; the model appends bullets,
    compaction appends raw blocks to Log."""

    def __init__(self, path: Path, title: str, description: str):
        self.path = Path(path)
        if not self.path.exists():
            desc = description.strip() or "(no description)"
            quoted = "\n".join("> " + line for line in desc.splitlines())
            body = f"# Case: {title}\n\n{quoted}\n\n"
            body += "\n\n".join(f"{h}\n" for h in SECTIONS.values()) + "\n"
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(body, encoding="utf-8")

    def read(self) -> str:
        return self.path.read_text(encoding="utf-8")

    def write(self, text: str) -> None:
        self.path.write_text(text, encoding="utf-8")

    def add(self, section: str, text: str, bullet: bool = True) -> None:
        if section not in SECTIONS:
            raise ValueError(f"unknown section {section!r}; use one of {list(SECTIONS)}")
        header = SECTIONS[section]
        lines = self.read().split("\n")
        start = lines.index(header)
        end = next(
            (i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")),
            len(lines),
        )
        while end - 1 > start and lines[end - 1].strip() == "":
            end -= 1
        if bullet:
            entry = "- " + text.strip().replace("\n", "\n  ")
        else:
            entry = text.rstrip()
        lines[end:end] = [entry, ""]
        self.write("\n".join(lines))
