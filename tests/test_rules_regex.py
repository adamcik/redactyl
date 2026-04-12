import re

from redactyl import Action, RegexPathRule, RegexValueRule, build_redactor


def test_regex_path_rule_from_string():
    redactor = build_redactor(
        [RegexPathRule(pattern=r"\.secret$", action=Action.REDACT)]
    )
    payload = {"user": {"secret": "value"}}

    redactor(payload)

    assert payload["user"]["secret"] == "[REDACTED]"


def test_regex_path_rule_from_compiled():
    redactor = build_redactor(
        [RegexPathRule(pattern=re.compile(r"\.secret$"), action=Action.REDACT)]
    )
    payload = {"user": {"secret": "value"}}

    redactor(payload)

    assert payload["user"]["secret"] == "[REDACTED]"


def test_regex_value_rule_from_string():
    redactor = build_redactor(
        [
            RegexValueRule(
                pattern=r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                action=Action.REDACT,
            )
        ]
    )
    payload = {"message": "Email a@b.com"}

    redactor(payload)

    assert payload["message"] == "Email [REDACTED]"


def test_regex_value_rule_from_compiled():
    redactor = build_redactor(
        [
            RegexValueRule(
                pattern=re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
                action=Action.REDACT,
            )
        ]
    )
    payload = {"message": "Contact a@b.com"}

    redactor(payload)

    assert payload["message"] == "Contact [REDACTED]"
