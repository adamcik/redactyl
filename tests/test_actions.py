from redactyl import Action, Options, PathRule, SubstringRule, build_redactor


def test_action_drop_removes_key():
    redactor = build_redactor([PathRule("secret", Action.DROP)])
    payload = {"secret": "value", "keep": "ok"}

    redactor(payload)

    assert "secret" not in payload
    assert payload["keep"] == "ok"


def test_action_safe_skips_nested_redaction():
    redactor = build_redactor(
        [
            PathRule("safe", Action.SAFE),
            PathRule("safe.secret", Action.REDACT),
            SubstringRule(tokens=frozenset({"secret"}), action=Action.REDACT),
        ]
    )
    payload = {"safe": {"secret": "value"}, "unsafe": {"secret": "value"}}

    redactor(payload)

    assert payload["safe"]["secret"] == "value"
    assert payload["unsafe"]["secret"] == "[REDACTED]"


def test_action_redact_registers_secret_for_scrub():
    redactor = build_redactor(
        [
            PathRule("user.password", Action.REDACT),
            PathRule("message", Action.SCRUB),
        ]
    )
    payload = {"user": {"password": "hunter2"}, "message": "password=hunter2"}

    redactor(payload)

    assert payload["user"]["password"] == "[REDACTED]"
    assert payload["message"] == "password=[REDACTED]"


def test_action_hash_returns_short_hash():
    options = Options(hash_secret=b"secret", hash_length=8)
    redactor = build_redactor([PathRule("user.id", Action.HASH)], options=options)
    payload = {"user": {"id": "abc"}}

    redactor(payload)

    assert payload["user"]["id"].startswith("[")
    assert payload["user"]["id"].endswith("]")
    assert len(payload["user"]["id"]) == 10


def test_action_scrub_nested_values():
    redactor = build_redactor(
        [
            PathRule("secret", Action.REDACT),
            PathRule("payload", Action.SCRUB),
        ]
    )
    payload = {"secret": "token", "payload": {"message": "token=token"}}

    redactor(payload)

    assert payload["payload"]["message"] == "[REDACTED]=[REDACTED]"


def test_min_length_prevents_secret_registration():
    options = Options(min_length=6)
    redactor = build_redactor(
        [
            PathRule("secret", Action.REDACT),
            PathRule("message", Action.SCRUB),
        ],
        options=options,
    )
    payload = {"secret": "short", "message": "short"}

    redactor(payload)

    assert payload["secret"] == "[REDACTED]"
    assert payload["message"] == "short"
