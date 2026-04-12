from redactyl import Action, SubstringRule, build_redactor


def test_substring_rule_boundary_matching():
    redactor = build_redactor(
        [SubstringRule(tokens=frozenset({"token"}), action=Action.REDACT)]
    )
    payload = {"id_token": "secret", "tokenize": "ok"}

    redactor(payload)

    assert payload["id_token"] == "[REDACTED]"
    assert payload["tokenize"] == "ok"
