from redactyl import Action, PathRule, build_redactor


def test_path_rule_exact_match():
    redactor = build_redactor([PathRule("user.password", Action.REDACT)])
    payload = {"user": {"password": "value", "password_hint": "hint"}}

    redactor(payload)

    assert payload["user"]["password"] == "[REDACTED]"
    assert payload["user"]["password_hint"] == "hint"


def test_path_rule_wildcard_matches_direct_child():
    redactor = build_redactor([PathRule("user.*", Action.REDACT)])
    payload = {"user": {"password": "value", "nested": {"secret": "value"}}}

    redactor(payload)

    assert payload["user"]["password"] == "[REDACTED]"
    assert payload["user"]["nested"] == "[REDACTED]"
