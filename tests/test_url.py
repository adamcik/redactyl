import re
import urllib.parse

import pytest

from redactyl import (
    Action,
    Options,
    PathRule,
    RegexValueRule,
    SubstringRule,
    UrlRule,
    build_redactor,
    deserialize_url,
    serialize_url,
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


def test_repeated_encoded_query_values_are_all_discovered():
    payload = {
        "message": "synthetic-one synthetic-two",
        "url": "https://example.test/path?%74oken=synthetic-one&token=synthetic%2Dtwo&x=1&x=2",
    }
    build_redactor(
        [
            PathRule("message", Action.SCRUB),
            UrlRule("url", (PathRule("params.token", Action.REDACT),)),
        ]
    )(payload)
    params = urllib.parse.parse_qs(urllib.parse.urlsplit(payload["url"]).query)
    assert params == {"token": ["[REDACTED]"], "x": ["1", "2"]}
    assert payload["message"] == "[REDACTED] [REDACTED]"


def test_url_path_scrub_decodes_and_reencodes_known_secrets():
    payload = {
        "url": "https://example.test/accounts/synthetic%2D123?x=1",
        "password": "synthetic-123",
    }
    build_redactor(
        [
            PathRule("password", Action.REDACT),
            UrlRule("url", (PathRule("path", Action.SCRUB),)),
        ]
    )(payload)
    assert payload["url"] == "https://example.test/accounts/[REDACTED]?x=1"


@pytest.mark.parametrize(
    "value",
    [
        "https://[broken/?token=synthetic-123",
        "https://example.test:invalid/",
        "https://example.test:99999/",
        "https://example.test/?token=%FF",
        "https://example.test/?token=%zz",
        "https://example.test/\nprivate",
        "https:///missing-host",
        "https://user@",
    ],
)
def test_malformed_url_is_replaced_not_passed_through(value):
    payload = {"url": value}
    build_redactor([PathRule("url", Action.URL)])(payload)
    assert payload["url"] == "[REDACTED]"


def test_ipv6_userinfo_and_blank_repeated_parameters_roundtrip():
    value = "https://user:p%40ss@[::1]:443/path?x=&x=2#fragment"
    assert serialize_url(deserialize_url(value)) == value


@pytest.mark.parametrize("path", ["/a%2fb/%41", "/a%2Fb/%2541", "/%E2%82%AC"])
def test_unmodified_url_path_preserves_escaping(path):
    value = f"https://example.test{path}?token=synthetic-123"
    payload = {"url": value}
    build_redactor([UrlRule("url", (PathRule("params.token", Action.REDACT),))])(
        payload
    )
    assert urllib.parse.urlsplit(payload["url"]).path == path
    assert deserialize_url(value)["path"] == path
    assert serialize_url(deserialize_url(value)) == value


def test_nested_url_rules_use_configured_traversal_depth():
    class RecursiveUrlRule:
        def __init__(self):
            self.calls = 0

        def __call__(self, *, value, path, key, ctx):
            if path != "path":
                return None
            self.calls += 1
            return UrlRule("path", (self,))(value=value, path=path, key=key, ctx=ctx)

    rule = RecursiveUrlRule()
    max_depth = 4
    payload = {"url": "https://example.test/path"}
    build_redactor([UrlRule("url", (rule,))], options=Options(max_depth=max_depth))(
        payload
    )
    assert rule.calls == 2 * (max_depth - 1)  # discovery and rendering
    assert "[REDACTED]" in payload["url"]
