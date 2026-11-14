import datetime
import hashlib
import hmac
import itertools
import uuid
from concurrent.futures import ThreadPoolExecutor
from enum import IntEnum, StrEnum
from typing import Never

import pytest

from redactyl import (
    Action,
    Options,
    PathRule,
    RegexValueRule,
    StopDecision,
    SubstringRule,
    UrlRule,
    build_redactor,
)
from redactyl.secrets import SecretStore


def test_discovery_is_independent_of_field_order():
    payload = {"message": "synthetic-secret", "password": "synthetic-secret"}
    build_redactor(
        [
            PathRule("message", Action.SCRUB),
            PathRule("password", Action.REDACT),
        ]
    )(payload)
    assert payload == {"message": "[REDACTED]", "password": "[REDACTED]"}


def test_container_scrub_keeps_child_rules():
    payload = {"data": {"password": "synthetic-secret"}}
    build_redactor(
        [
            PathRule("data", Action.SCRUB),
            PathRule("data.password", Action.REDACT),
        ]
    )(payload)
    assert payload == {"data": {"password": "[REDACTED]"}}


def test_regex_registers_match_not_surrounding_text():
    store = SecretStore()
    payload = {"field": "prefix secret-123 suffix"}
    redactor = build_redactor(
        [
            RegexValueRule(r"secret-\d+", Action.REDACT),
        ]
    )
    redactor(payload, secrets=store)
    assert payload["field"] == "prefix [REDACTED] suffix"
    assert store.scrub("secret-123", "X") == "X"
    assert store.scrub("prefix secret-123 suffix", "X") == "prefix X suffix"


@pytest.mark.parametrize("order", itertools.permutations(["message", "data", "url"]))
def test_order_including_nested_lists_and_urls(order):
    values = {
        "message": "synthetic-123 synthetic-456",
        "data": [[{"password": "synthetic-123"}]],
        "url": "https://example.test/?token=synthetic-456",
    }
    payload = {key: values[key] for key in order}
    build_redactor(
        [
            PathRule("message", Action.SCRUB),
            SubstringRule(frozenset({"password"}), Action.REDACT),
            UrlRule("url", (PathRule("params.token", Action.REDACT),)),
        ]
    )(payload)
    assert payload["message"] == "[REDACTED] [REDACTED]"
    assert payload["data"] == [[{"password": "[REDACTED]"}]]


@pytest.mark.parametrize(("first", "second"), itertools.product(Action, repeat=2))
def test_first_matching_action_is_terminal(first, second):
    payload = {"value": "https://example.test/?token=synthetic-123"}
    expected = payload.copy()
    options = Options(hash_secret=b"synthetic-test-key")
    build_redactor([PathRule("value", first)], options=options)(expected)
    build_redactor(
        [PathRule("value", first), PathRule("value", second)], options=options
    )(payload)
    assert payload == expected


@pytest.mark.parametrize("action", [Action.REDACT, Action.DROP])
def test_removed_container_contributes_string_leaves(action):
    payload = {"message": "synthetic-123", "hidden": [{"x": "synthetic-123"}]}
    build_redactor(
        [
            PathRule("message", Action.SCRUB),
            PathRule("hidden", action),
        ]
    )(payload)
    assert payload["message"] == "[REDACTED]"


def test_safe_container_is_explicit_bypass_and_does_not_discover():
    payload = {"message": "synthetic-123", "safe": {"password": "synthetic-123"}}
    build_redactor(
        [
            PathRule("safe", Action.SAFE),
            PathRule("safe.password", Action.REDACT),
            PathRule("message", Action.SCRUB),
        ]
    )(payload)
    assert payload["message"] == "synthetic-123"
    assert payload["safe"]["password"] == "synthetic-123"


@pytest.mark.parametrize("action", [Action.REDACT, Action.HASH, Action.DROP])
def test_regex_actions_register_each_match(action):
    store = SecretStore()
    build_redactor([RegexValueRule(r"secret-\d+", action)])(
        {"text": "before secret-123 secret-456 after"},
        secrets=store,
    )
    assert store.scrub("secret-123 secret-456", "X") == "X X"


def test_call_isolation_and_explicit_cross_call_retention():
    redactor = build_redactor(
        [
            PathRule("password", Action.REDACT),
            PathRule("message", Action.SCRUB),
        ]
    )
    earlier = {"message": "synthetic-123"}
    store = SecretStore()
    redactor(earlier, secrets=store)
    redactor({"password": "synthetic-123"}, secrets=store)
    assert earlier["message"] == "synthetic-123"  # no retroactive protection
    later = {"message": "synthetic-123"}
    redactor(later)
    assert later["message"] == "synthetic-123"
    redactor(later, secrets=store)
    assert later["message"] == "[REDACTED]"


@pytest.mark.parametrize(
    "unsupported",
    [
        ValueError("synthetic-123"),
        (ValueError, ValueError("synthetic-123"), None),
        b"synthetic-123",
        uuid.UUID(int=1),
        datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
        object(),
    ],
)
def test_unsupported_values_fail_atomically(unsupported):
    store = SecretStore()
    nested = {"password": "synthetic-123"}
    payload = {"nested": nested, "unsupported": unsupported}
    with pytest.raises(TypeError):
        build_redactor([PathRule("nested.password", Action.REDACT)])(
            payload, secrets=store
        )
    assert payload["nested"] is nested
    assert nested["password"] == "synthetic-123"
    assert store.scrub("synthetic-123", "X") == "synthetic-123"


def test_custom_object_hooks_are_not_called():
    # Neither str nor repr is a redaction boundary: reject unsupported objects
    # without calling either hook, which could expose arbitrary sensitive text.
    class Unserializable:
        def __str__(self) -> str:
            raise AssertionError("must not stringify objects")

        def __repr__(self) -> str:
            raise AssertionError("must not represent objects")

        def __deepcopy__(self, memo):
            pytest.fail("must not call object copy hooks")

    with pytest.raises(TypeError):
        build_redactor([])({"object": Unserializable()})


@pytest.mark.parametrize("action", [Action.SAFE, Action.DROP, Action.REDACT])
def test_terminal_actions_do_not_bypass_input_validation(action):
    unsupported = object()
    payload = {"value": unsupported}
    with pytest.raises(TypeError, match="unsupported"):
        build_redactor([PathRule("value", action)])(payload)
    assert payload["value"] is unsupported


def test_primitive_subclasses_are_normalized_without_custom_hooks():
    class Source(StrEnum):
        TASK = "task"

        def __str__(self) -> str:
            raise AssertionError("must use the underlying string")

    class Code(IntEnum):
        OK = 1

    class Measurement(float):
        def __float__(self) -> float:
            raise AssertionError("must use the underlying float")

    payload = {"source": Source.TASK, "code": Code.OK, "value": Measurement(1.5)}
    build_redactor([])(payload)
    assert payload == {"source": "task", "code": 1, "value": 1.5}
    assert type(payload["source"]) is str
    assert type(payload["code"]) is int
    assert type(payload["value"]) is float


def test_size_and_capacity_limits_are_opt_in():
    options = Options()
    assert options.max_depth is None
    assert options.max_items is None
    assert options.max_string_length is None
    text = "x" * 1_000_001
    items = [None] * 10_001
    payload = {"text": text, "items": items}
    build_redactor([])(payload)
    assert payload == {"text": text, "items": items}
    store = SecretStore()
    store.add("x" * 1_000_001)
    for i in range(4097):
        store.add(f"synthetic-{i}")


@pytest.mark.parametrize("cyclic", [False, True])
def test_invalid_custom_rule_output_does_not_commit(cyclic):
    def custom_rule(**kwargs: object) -> StopDecision | None:
        if kwargs["key"] != "output":
            return None
        result = {}
        result["value"] = result if cyclic else object()
        return StopDecision(result, skip_children=True)

    payload = {"password": "synthetic-123", "output": "original"}
    store = SecretStore()
    with pytest.raises(
        ValueError if cyclic else TypeError, match=r"cyclic|unsupported"
    ):
        build_redactor([PathRule("password", Action.REDACT), custom_rule])(
            payload,
            secrets=store,
        )
    assert payload == {"password": "synthetic-123", "output": "original"}
    assert store.scrub("synthetic-123", "X") == "synthetic-123"


def test_cycles_fail_but_shared_references_are_copied_per_path():
    cycle = {}
    cycle["self"] = cycle
    with pytest.raises(ValueError, match="cyclic"):
        build_redactor([])(cycle)
    assert cycle["self"] is cycle
    shared = {"value": "synthetic-123"}
    payload = {"safe": shared, "hidden": shared}
    build_redactor([PathRule("hidden.value", Action.REDACT)])(payload)
    assert payload["safe"]["value"] == "synthetic-123"
    assert payload["hidden"]["value"] == "[REDACTED]"
    assert shared["value"] == "synthetic-123"


def test_rule_failure_does_not_commit_payload_or_secrets():
    def failing_rule(**_kwargs: object) -> Never:
        raise RuntimeError("synthetic failure")

    payload = {"password": "synthetic-123", "other": "text"}
    store = SecretStore()
    with pytest.raises(RuntimeError):
        build_redactor([PathRule("password", Action.REDACT), failing_rule])(
            payload,
            secrets=store,
        )
    assert payload == {"password": "synthetic-123", "other": "text"}
    assert store.scrub("synthetic-123", "X") == "synthetic-123"


def test_secret_store_capacity_failure_is_atomic():
    store = SecretStore(max_secrets=1)
    payload = {"password": "synthetic-123", "token": "synthetic-456"}
    with pytest.raises(ValueError, match="capacity"):
        build_redactor([PathRule("*", Action.REDACT)])(payload, secrets=store)
    assert payload["password"] == "synthetic-123"
    assert store.scrub("synthetic-123", "X") == "synthetic-123"


def test_shared_store_concurrent_calls_and_literal_replacement():
    store = SecretStore()
    redactor = build_redactor([PathRule("secret", Action.REDACT)])
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(
            executor.map(
                lambda i: redactor({"secret": f"synthetic-{i}"}, secrets=store),
                range(20),
            )
        )
    for i in range(20):
        assert store.scrub(f"synthetic-{i}", r"\1") == r"\1"


def test_base_store_is_snapshotted_and_overlaps_choose_longest():
    base = SecretStore()
    base.add("synthetic")
    redactor = build_redactor(
        [
            PathRule("secret", Action.REDACT),
            PathRule("message", Action.SCRUB),
        ],
        options=Options(base_secrets_store=base),
    )
    base.add("new-value")
    payload = {"message": "synthetic-123 new-value", "secret": "synthetic-123"}
    redactor(payload)
    assert payload["message"] == "[REDACTED] new-value"


@pytest.mark.parametrize("action", [Action.SCRUB, Action.URL])
def test_resource_bounds_cover_scrub_and_url(action):
    options = Options(max_depth=3, max_items=4, max_string_length=100)
    payload = {"value": {"nested": {"deep": {"password": "synthetic-123"}}}}
    if action is Action.URL:
        payload = {"value": "https://example.test/?a=1&b=2&c=3&d=4&e=5"}
    build_redactor([PathRule("value", action)], options=options)(payload)
    if action is Action.SCRUB:
        assert payload["value"]["nested"]["deep"] == {"...": "[...]"}
    else:
        assert payload["value"] == "[REDACTED]"


def test_configured_string_limit_fails_atomically():
    payload = {"text": "x" * 101}
    with pytest.raises(ValueError, match="string limit"):
        build_redactor([], options=Options(max_string_length=100))(payload)
    assert payload == {"text": "x" * 101}


def test_dotted_keys_have_documented_flat_path_semantics():
    payload = {"user.password": "synthetic-123", "user": {"password": "synthetic-456"}}
    build_redactor([PathRule("user.password", Action.REDACT)])(payload)
    assert payload == {
        "user.password": "[REDACTED]",
        "user": {"password": "[REDACTED]"},
    }


def test_list_drop_uses_original_indices():
    payload = {"items": ["zero", "one", "two"]}
    build_redactor([PathRule("items.0", Action.DROP)])(payload)
    assert payload == {"items": ["one", "two"]}


@pytest.mark.parametrize("mode", ["regex", "scrub", "url"])
def test_replacement_expansion_is_bounded_before_commit(mode):
    options = Options(max_string_length=100, replacement="r" * 80)
    payload = {"text": "synthetic-123 synthetic-123", "password": "synthetic-123"}
    rules = [PathRule("password", Action.REDACT)]
    if mode == "regex":
        rules.append(RegexValueRule("synthetic-123", Action.REDACT))
    elif mode == "scrub":
        rules.append(PathRule("text", Action.SCRUB))
    else:
        payload = {"text": "https://example.test/?a=one&b=two"}
        rules = [PathRule("text", Action.URL)]
    before = payload.copy()
    with pytest.raises(ValueError, match="limit"):
        build_redactor(rules, options=options)(payload)
    assert payload == before


def test_zero_width_regex_replacement_respects_configured_string_limit():
    payload = {"text": "x" * 50}
    with pytest.raises(ValueError, match="string limit"):
        build_redactor(
            [RegexValueRule("", Action.REDACT)], options=Options(max_string_length=100)
        )(payload)
    assert payload == {"text": "x" * 50}


def test_hash_key_lifetime_truncation_and_known_secret_scrubbing():
    key = b"synthetic-test-key"
    value = "synthetic-123"
    rules = [PathRule("id", Action.HASH), PathRule("message", Action.SCRUB)]
    options = Options(hash_secret=key, hash_length=16)
    payload = {"message": value, "id": value}
    build_redactor(rules, options=options)(payload)
    digest = hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:16]
    assert payload == {"message": "[REDACTED]", "id": f"[{digest}]"}
    second = {"id": value}
    build_redactor(rules, options=options)(second)
    assert second["id"] == payload["id"]

    random_key_redactor = build_redactor(rules)
    first = {"id": value}
    second = {"id": value}
    random_key_redactor(first)
    random_key_redactor(second)
    assert first == second


@pytest.mark.parametrize(
    "kwargs",
    [
        {"hash_length": 0},
        {"hash_length": 65},
        {"hash_secret": b""},
        {"min_length": 0},
        {"max_string_length": 0},
        {"max_depth": -1},
        {"max_items": -1},
        {"max_string_length": 1, "replacement": "too long"},
    ],
)
def test_invalid_options_fail_at_construction(kwargs):
    with pytest.raises(ValueError, match=r"must|exceeds"):
        Options(**kwargs)
