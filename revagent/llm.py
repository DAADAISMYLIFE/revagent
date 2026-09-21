"""OpenAI-compatible client for the vLLM Qwen server."""
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from openai import APIConnectionError, APIError, APIStatusError, BadRequestError, OpenAI

# The transport exceptions a dropped stream raises are the ones of the HTTP client the SDK itself uses:
# openai>=3 ships its own fork `httpx2` (a plain `httpx` may be absent, as in the sandbox image, or be
# an unrelated install whose exception classes never match); openai 1.x/2.x use `httpx`.
try:
    import httpx2 as httpx
except ImportError:  # pragma: no cover - openai < 3
    import httpx

REPO_SECURE = Path(__file__).resolve().parent.parent / ".secure"


class ContextOverflow(Exception):
    """vLLM rejected the request because the prompt exceeds max_model_len."""


@dataclass
class Secure:
    key: str
    url: str
    model: str


def load_secure(explicit: Path | None = None) -> Secure:
    env = {k: os.environ.get(k, "").strip() for k in ("QWEN", "URL", "MODEL")}
    if explicit is None and all(env.values()):
        return Secure(key=env["QWEN"], url=env["URL"].rstrip("/"), model=env["MODEL"])

    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    if os.environ.get("REVAGENT_SECURE"):
        candidates.append(Path(os.environ["REVAGENT_SECURE"]))
    try:
        cwd = Path.cwd()
    except FileNotFoundError:
        # the shell's cwd was deleted or re-created underneath it (a DrvFs directory on WSL after a
        # Windows-side rename): an explicit --secure must still work, so just skip the cwd candidate
        cwd = None
    if cwd is not None:
        candidates.append(cwd / ".secure")
    candidates += [
        REPO_SECURE,
        Path.home() / ".revagent" / ".secure",
    ]
    for p in candidates:
        if p.is_file():
            kv: dict[str, str] = {}
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                kv[k.strip()] = v.strip().strip('"').strip("'")
            try:
                return Secure(key=kv["QWEN"], url=kv["URL"].rstrip("/"), model=kv["MODEL"])
            except KeyError as e:
                raise ValueError(f"{p} is missing key {e.args[0]}") from e
    raise FileNotFoundError("no .secure found; tried: " + ", ".join(map(str, candidates)))


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict
    raw_args: str
    parse_error: bool = False


@dataclass
class ChatResponse:
    content: str
    reasoning: str
    tool_calls: list[ToolCall]
    message: dict
    prompt_tokens: int
    completion_tokens: int
    finish_reason: str = "stop"  # "length" means the output budget ran out (often mid-thinking)


def parse_assistant(m) -> tuple[str, str, list[ToolCall], dict]:
    """Split a ChatCompletionMessage into (content, reasoning, tool_calls, message-to-append).
    The message-to-append never carries reasoning: the chat template drops old thinking anyway."""
    content = m.content or ""
    me = getattr(m, "model_extra", None) or {}
    reasoning = (
        getattr(m, "reasoning_content", None)
        or me.get("reasoning_content")
        or getattr(m, "reasoning", None)
        or me.get("reasoning")
        or ""
    )
    calls: list[ToolCall] = []
    msg: dict = {"role": "assistant", "content": content}
    if m.tool_calls:
        msg["tool_calls"] = []
        for tc in m.tool_calls:
            raw = tc.function.arguments or "{}"
            try:
                args = json.loads(raw)
                parse_error = not isinstance(args, dict)
            except json.JSONDecodeError:
                args, parse_error = None, True
            calls.append(ToolCall(tc.id, tc.function.name, args if not parse_error else {}, raw, parse_error))
            msg["tool_calls"].append(
                {"id": tc.id, "type": "function", "function": {"name": tc.function.name, "arguments": raw}}
            )
    return content, reasoning, calls, msg


def collect_stream(chunks) -> SimpleNamespace:
    """Fold a chat-completions stream into one response-shaped object (choices[0].message with content,
    reasoning_content, tool_calls; choices[0].finish_reason; usage), so parse_assistant() and the
    accounting code do not care whether the reply was streamed.

    Why stream at all: the runpod proxy (Cloudflare) drops any request whose response has not STARTED
    within ~100 s (HTTP 524). A non-streamed reply starts only after the whole generation, and a hard
    step thinks for longer than that; a streamed reply starts with the first reasoning token."""
    content, reasoning, finish, usage = [], [], None, None
    tool_calls: dict[int, dict] = {}
    for ch in chunks:
        if getattr(ch, "usage", None):
            usage = ch.usage
        choices = getattr(ch, "choices", None) or []
        if not choices:
            continue
        c = choices[0]
        if getattr(c, "finish_reason", None):
            finish = c.finish_reason
        d = getattr(c, "delta", None)
        if d is None:
            continue
        if getattr(d, "content", None):
            content.append(d.content)
        me = getattr(d, "model_extra", None) or {}
        r = getattr(d, "reasoning_content", None) or me.get("reasoning_content") \
            or getattr(d, "reasoning", None) or me.get("reasoning")
        if r:
            reasoning.append(r)
        for tc in getattr(d, "tool_calls", None) or []:
            slot = tool_calls.setdefault(tc.index, {"id": None, "name": "", "arguments": []})
            if getattr(tc, "id", None):
                slot["id"] = tc.id
            fn = getattr(tc, "function", None)
            if fn is not None:
                if getattr(fn, "name", None):
                    slot["name"] = fn.name
                if getattr(fn, "arguments", None):
                    slot["arguments"].append(fn.arguments)
    calls = [
        SimpleNamespace(id=v["id"] or f"call_{i}", type="function",
                        function=SimpleNamespace(name=v["name"], arguments="".join(v["arguments"])))
        for i, v in sorted(tool_calls.items())
    ] or None
    message = SimpleNamespace(content="".join(content) or None, reasoning_content="".join(reasoning) or None,
                              tool_calls=calls, model_extra={})
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason=finish or "stop")],
                           usage=usage)


def _retryable(e: Exception) -> bool:
    """Connection errors, 5xx/429 and a stream that dies mid-reply are transient and worth a retry;
    any other APIStatusError (401/403/404/409/422/...) is a real failure and must not be retried.

    A dropped stream does NOT arrive as APIConnectionError: the SDK's Stream iterator lets httpx
    transport errors (RemoteProtocolError, ReadError, ReadTimeout) propagate unwrapped and raises a
    bare APIError for an in-band `{"error": ...}` SSE event."""
    if isinstance(e, (APIConnectionError, httpx.TransportError)):
        return True
    if isinstance(e, APIStatusError):
        return e.status_code >= 500 or e.status_code == 429
    if isinstance(e, APIError):
        return True
    return False


class LLM:
    # 16384: thinking tokens count toward max_tokens, and a hard step routinely thinks past 8k (relativity
    # run 1: 12 of 107 steps were cut at 8192 and every retry fitted in 16k). It is a cap, not a cost.
    # 44k compaction threshold + 16k output stays under the server's 65536 max_model_len.
    DEFAULT_MAX_TOKENS = 16384

    def __init__(self, secure: Secure, reasoning_effort: str = "medium", temperature: float = 0.6,
                 max_tokens: int = DEFAULT_MAX_TOKENS, retries: int = 3, stream: bool = True):
        # max_retries=0: the SDK's own silent 5xx retries would multiply with ours and never show up
        # in the run log. Every retry goes through _create below, which counts and reports it.
        self.client = OpenAI(api_key=secure.key, base_url=secure.url + "/v1", timeout=600, max_retries=0)
        self.model = secure.model
        self.reasoning_effort = reasoning_effort
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.retries = retries
        self.stream = stream   # see collect_stream(); False only for tests and direct-to-vLLM setups
        self.last_prompt_tokens = 0
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_retries = 0   # transient failures retried this session (5xx/429/connection)

    def _create(self, reasoning_effort: str | None = None, **kw):
        """One request, retried on transient failures. When streaming, the whole stream is consumed here
        (inside the retry loop) so a connection dropped mid-reply is retried like a failed request."""
        delay = 2.0
        if self.stream:
            kw = {**kw, "stream": True, "stream_options": {"include_usage": True}}
        for attempt in range(self.retries + 1):
            try:
                resp = self.client.chat.completions.create(
                    model=self.model,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    extra_body={"reasoning_effort": reasoning_effort or self.reasoning_effort},
                    **kw,
                )
                return collect_stream(resp) if self.stream else resp
            except BadRequestError as e:
                text = str(e)
                if "context length" in text or "maximum context" in text or "too long" in text:
                    raise ContextOverflow(text) from e
                raise
            except (APIError, httpx.TransportError) as e:
                if not _retryable(e) or attempt == self.retries:
                    raise
                self.total_retries += 1
                what = f"HTTP {e.status_code}" if isinstance(e, APIStatusError) else type(e).__name__
                # visible in the terminal/log: a 524 here means the runpod proxy cut a >100 s generation
                print(f"[llm] retry {attempt + 1}/{self.retries} after {what}; waiting {delay:.0f}s",
                      file=sys.stderr, flush=True)
                time.sleep(delay)
                delay *= 2

    def _account(self, resp) -> tuple[int, int]:
        u = resp.usage
        p, c = (u.prompt_tokens, u.completion_tokens) if u else (0, 0)
        self.total_prompt_tokens += p
        self.total_completion_tokens += c
        return p, c

    def chat(self, messages: list[dict], tools: list[dict] | None = None,
             reasoning_effort: str | None = None) -> ChatResponse:
        """reasoning_effort overrides the client default for this call only (e.g. "low" on a retry)."""
        kw: dict = {"messages": messages, "reasoning_effort": reasoning_effort}
        if tools:
            kw["tools"] = tools
            kw["tool_choice"] = "auto"
        resp = self._create(**kw)
        choice = resp.choices[0]
        content, reasoning, calls, msg = parse_assistant(choice.message)
        p, c = self._account(resp)
        self.last_prompt_tokens = p
        finish = getattr(choice, "finish_reason", None) or "stop"
        return ChatResponse(content, reasoning, calls, msg, p, c, finish)

    def complete(self, prompt: str, system: str | None = None, max_tokens: int | None = None,
                 reasoning_effort: str | None = None) -> str:
        """One-shot completion. `max_tokens` raises the budget for this call only (thinking tokens count
        toward it). Sets `self.last_finish_reason` so callers can detect a reply cut off by the budget."""
        msgs = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
        old_max = self.max_tokens
        if max_tokens:
            self.max_tokens = max(old_max, int(max_tokens))
        try:
            resp = self._create(messages=msgs, reasoning_effort=reasoning_effort)
        finally:
            self.max_tokens = old_max
        self._account(resp)
        self.last_finish_reason = getattr(resp.choices[0], "finish_reason", None)
        return resp.choices[0].message.content or ""
