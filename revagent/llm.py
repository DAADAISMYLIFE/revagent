"""OpenAI-compatible client for the vLLM Qwen server."""
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

from openai import APIConnectionError, APIStatusError, BadRequestError, OpenAI

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
    candidates += [
        Path.cwd() / ".secure",
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


def _retryable(e: Exception) -> bool:
    """Connection errors and 5xx/429 are transient and worth a retry; any other
    APIStatusError (401/403/404/409/422/...) is a real failure and must not be retried."""
    if isinstance(e, APIConnectionError):
        return True
    if isinstance(e, APIStatusError):
        return e.status_code >= 500 or e.status_code == 429
    return False


class LLM:
    def __init__(self, secure: Secure, reasoning_effort: str = "medium", temperature: float = 0.6,
                 max_tokens: int = 8192, retries: int = 3):
        self.client = OpenAI(api_key=secure.key, base_url=secure.url + "/v1", timeout=600)
        self.model = secure.model
        self.reasoning_effort = reasoning_effort
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.retries = retries
        self.last_prompt_tokens = 0
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0

    def _create(self, reasoning_effort: str | None = None, **kw):
        delay = 2.0
        for attempt in range(self.retries + 1):
            try:
                return self.client.chat.completions.create(
                    model=self.model,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    extra_body={"reasoning_effort": reasoning_effort or self.reasoning_effort},
                    **kw,
                )
            except BadRequestError as e:
                text = str(e)
                if "context length" in text or "maximum context" in text or "too long" in text:
                    raise ContextOverflow(text) from e
                raise
            except (APIConnectionError, APIStatusError) as e:
                if not _retryable(e) or attempt == self.retries:
                    raise
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
