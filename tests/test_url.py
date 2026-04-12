import re

from redactyl import (
    Action,
    PathRule,
    RegexValueRule,
    SubstringRule,
    UrlRule,
    build_redactor,
)
from redactyl.presets import _URL_RULES


def test_url_rule_parses_and_scrubs_params():
    rules = [PathRule("params.token", Action.REDACT)]
    redactor = build_redactor([UrlRule("url", tuple(rules))])
    payload = {"url": "https://user:pass@example.com/path?token=abc&other=ok#frag"}

    redactor(payload)

    assert "token=%5BREDACTED%5D" in payload["url"]
    assert "other=ok" in payload["url"]


def test_url_rule_preset_redacts_params_userinfo_fragment():
    redactor = build_redactor([UrlRule("url", _URL_RULES)])
    payload = {"url": "https://user:pass@example.com/path?token=abc&other=ok#frag"}

    redactor(payload)

    assert "token=%5BREDACTED%5D" in payload["url"]
    assert "other=%5BREDACTED%5D" in payload["url"]
    assert "user:pass" not in payload["url"]
    assert "#frag" not in payload["url"]


def test_url_rule_preset_with_param_rules():
    redactor = build_redactor(
        [
            UrlRule(
                "url",
                (
                    PathRule("userinfo.user", Action.REDACT),
                    PathRule("userinfo.password", Action.REDACT),
                    PathRule("fragment", Action.REDACT),
                    SubstringRule(tokens=frozenset({"token"}), action=Action.REDACT),
                ),
            ),
        ]
    )
    payload = {"url": "https://example.com/path?token=abc&other=ok"}

    redactor(payload)

    assert "token=%5BREDACTED%5D" in payload["url"]
    assert "other=ok" in payload["url"]


def test_url_rule_uses_shared_secrets_for_scrub():
    redactor = build_redactor(
        [
            PathRule("secret", Action.REDACT),
            UrlRule("url", (PathRule("params.token", Action.SCRUB),)),
        ]
    )
    payload = {"secret": "abc123", "url": "https://example.com/path?token=abc123"}

    redactor(payload)

    assert "token=%5BREDACTED%5D" in payload["url"]


def test_regex_value_rule_redacts_url_in_text():
    url_rules = [PathRule("params.token", Action.REDACT)]
    rule = RegexValueRule(
        pattern=re.compile(r"https?://\S+"),
        action=Action.URL,
        rules=tuple(url_rules),
    )
    redactor = build_redactor([rule])
    payload = {"message": "See https://example.com/path?token=abc&x=1 now"}

    redactor(payload)

    assert "token=%5BREDACTED%5D" in payload["message"]
    assert "x=1" in payload["message"]
