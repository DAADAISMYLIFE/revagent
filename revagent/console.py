"""Console log: everything a run prints (stdout and stderr) is also appended to
<challenge>/.revagent/console.log, one `=== run <UTC time> argv: ... ===` header per run, so a run no
longer needs `2>&1 | tee`. The host installs the tee around each run; a sandbox run streams the
container's output through sys.stdout, so the same tee captures it."""
import contextlib
import datetime
import shlex
import sys
from pathlib import Path
from typing import Iterator, TextIO

LOG_NAME = "console.log"


def log_path(problem_dir: Path) -> Path:
    return problem_dir / ".revagent" / LOG_NAME


def header(argv: list[str]) -> str:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return f"=== run {now} argv: {shlex.join(['revagent', *argv])} ===\n"


class Tee:
    """A text stream that writes to `stream` and to `log`, flushing both on every write (a killed run
    must not lose its tail). Everything else (isatty, fileno, encoding, ...) is the wrapped stream's."""

    def __init__(self, stream: TextIO, log: TextIO):
        self._stream = stream
        self._log = log

    def write(self, s: str) -> int:
        n = self._stream.write(s)
        self._stream.flush()
        self._log.write(s)
        self._log.flush()
        return n if n is not None else len(s)

    def flush(self) -> None:
        self._stream.flush()
        self._log.flush()

    def __getattr__(self, name):
        return getattr(self._stream, name)


@contextlib.contextmanager
def tee_console(problem_dir: Path, argv: list[str]) -> Iterator[TextIO]:
    """Duplicate sys.stdout and sys.stderr into <problem_dir>/.revagent/console.log for the block.
    The work dir is created if needed (on the host it may not exist before the agent's first run)."""
    p = log_path(problem_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8", errors="replace") as log:
        log.write(header(argv))
        log.flush()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = Tee(old_out, log), Tee(old_err, log)
        try:
            yield log
        finally:
            sys.stdout, sys.stderr = old_out, old_err
