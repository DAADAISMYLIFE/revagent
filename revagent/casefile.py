from pathlib import Path

SECTIONS = {
    "facts": "## Facts",
    "hypotheses": "## Hypotheses",
    "todo": "## Todo",
    "log": "## Log",
}
HEADERS = frozenset(SECTIONS.values())


def section_span(lines: list[str], section: str) -> tuple[int, int] | None:
    """(start, end) of `section` in `lines`: start is the index of its exact header line, end the
    index of the next canonical header (or len(lines)). None if the header line is absent."""
    try:
        start = lines.index(SECTIONS[section])
    except ValueError:
        return None
    end = next((i for i in range(start + 1, len(lines)) if lines[i].strip() in HEADERS), len(lines))
    return start, end


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

    def _span(self, lines: list[str], section: str) -> tuple[int, int]:
        span = section_span(lines, section)
        if span is None:
            raise ValueError(f"{self.path} has no {SECTIONS[section]!r} section")
        return span

    def add(self, section: str, text: str, bullet: bool = True) -> None:
        if section not in SECTIONS:
            raise ValueError(f"unknown section {section!r}; use one of {list(SECTIONS)}")
        lines = self.read().split("\n")
        start, end = self._span(lines, section)
        while end - 1 > start and lines[end - 1].strip() == "":
            end -= 1
        if bullet:
            entry = "- " + text.strip().replace("\n", "\n  ")
        else:
            entry = text.rstrip()
        lines[end:end] = [entry, ""]
        self.write("\n".join(lines))

    def replace_section(self, section: str, text: str) -> None:
        """Replace the body of `section` (between its exact header and the next canonical
        header) with `text`, leaving other sections untouched."""
        if section not in SECTIONS:
            raise ValueError(f"unknown section {section!r}; use one of {list(SECTIONS)}")
        lines = self.read().split("\n")
        start, end = self._span(lines, section)
        body = text.rstrip("\n").splitlines()
        lines[start + 1:end] = ["", *body, ""]
        self.write("\n".join(lines))
