import json

from revagent.gate import G3_TEXT, Gate


def _bash(script: str) -> tuple[str, str]:
    return ("bash", json.dumps({"cmd": f"cd /w && python3 - <<'EOF'\n{script}\nEOF"}))


def _variants(n: int) -> list[tuple[str, str]]:
    base = "import pefile\npe = pefile.PE('chall.exe')\nbase = pe.OPTIONAL_HEADER.ImageBase\n" + "x = 1\n" * 40
    return [_bash(base + f"print({i})") for i in range(n)]


def test_fourth_similar_script_is_blocked_and_earlier_ones_allowed():
    g = Gate()
    v = _variants(4)
    for step in range(1, 4):
        verdicts, events = g.check(step, [v[step - 1]])
        assert verdicts[0].allowed and events == []
    verdicts, events = g.check(4, [v[3]])
    assert not verdicts[0].allowed
    assert verdicts[0].text.startswith("[blocked by G3]") and verdicts[0].text == G3_TEXT
    assert events == [{"event": "gate_block", "gate": "G3", "step": 4, "streak": 4}]
    assert g.blocks == 1 and g.max_streak == 4


def test_dissimilar_script_or_other_tool_resets_the_streak():
    g = Gate()
    v = _variants(3)
    for step, call in enumerate(v, 1):
        g.check(step, [call])
    assert g.streak == 3
    g.check(4, [("notes", json.dumps({"action": "add", "text": "x"}))])
    assert g.streak == 0
    g.check(5, [v[0]])
    g.check(6, [_bash("completely = 'different'\nprint(completely)")])
    assert g.streak == 1  # the different script starts a new streak of its own


def test_block_opens_when_the_model_changes_approach():
    g = Gate()
    v = _variants(5)
    for step, call in enumerate(v[:4], 1):
        g.check(step, [call])
    verdicts, events = g.check(5, [("run_binary", json.dumps({"path": "chall", "stdin": "abc"}))])
    assert verdicts[0].allowed
    assert events == [{"event": "gate_open", "gate": "G3", "step": 5}]
    assert g.streak == 0


def test_three_consecutive_blocked_steps_release_the_gate_with_cooldown():
    g = Gate()
    v = _variants(9)
    for step, call in enumerate(v[:4], 1):
        g.check(step, [call])                       # step 4 blocked (streak 4)
    g.check(5, [v[4]])                              # blocked
    verdicts, events = g.check(6, [v[5]])           # third consecutive block -> released
    assert not verdicts[0].allowed
    assert {"event": "gate_released", "gate": "G3", "step": 6, "cooldown_until": 16} in events
    verdicts, _ = g.check(7, [v[6]])                # in cooldown: allowed even though similar
    assert verdicts[0].allowed
    assert g.streak == 0 and g.blocks == 3


def test_only_the_similar_call_in_a_step_is_blocked():
    g = Gate()
    v = _variants(4)
    for step, call in enumerate(v[:3], 1):
        g.check(step, [call])
    verdicts, _ = g.check(4, [("notes", json.dumps({"action": "read"})), v[3]])
    assert verdicts[0].allowed and not verdicts[1].allowed


def test_plain_bash_does_not_count_and_bad_json_is_ignored():
    g = Gate()
    v = _variants(3)
    for step, call in enumerate(v, 1):
        g.check(step, [call])
    g.check(4, [("bash", json.dumps({"cmd": "ls -la"}))])
    assert g.streak == 0
    verdicts, events = g.check(5, [("bash", "{not json")])
    assert verdicts[0].allowed and events == []


def test_gate_never_raises(monkeypatch):
    import revagent.gate as gate_mod
    monkeypatch.setattr(gate_mod, "script_body", lambda cmd: (_ for _ in ()).throw(RuntimeError("boom")))
    g = Gate()
    verdicts, events = g.check(1, [_bash("x = 1")])
    assert verdicts[0].allowed
    assert events == [{"event": "gate_error", "gate": "G3", "step": 1, "error": "RuntimeError: boom"}]
