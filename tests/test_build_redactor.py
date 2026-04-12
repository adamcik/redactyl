import pytest

from redactyl import (
    Action,
    ContinueDecision,
    Options,
    PathRule,
    StopDecision,
    build_redactor,
)
from redactyl.secrets import SecretStore


def test_rules_can_continue_and_update_value_for_later_rules():
    class PrefixRule:
        def __call__(self, *, value, path, key, ctx):  # noqa: ARG002
            if path != "user.name":
                return None
            return ContinueDecision(value=f"user:{value}")

    class StopRule:
        def __call__(self, *, value, path, key, ctx):  # noqa: ARG002
            if path != "user.name":
                return None
            if value != "user:alice":
                raise AssertionError("expected updated value")
            return StopDecision(value=value)

    redactor = build_redactor([PrefixRule(), StopRule()])
    payload = {"user": {"name": "alice"}}

    redactor(payload)

    assert payload["user"]["name"] == "user:alice"


def test_dict_only_contract():
    redactor = build_redactor([])

    with pytest.raises(TypeError):
        redactor(["not", "a", "dict"])


def test_secrets_store_can_be_shared():
    redactor = build_redactor(
        [PathRule("secret", Action.REDACT), PathRule("message", Action.SCRUB)]
    )
    secrets = SecretStore()
    payload = {"secret": "token", "message": "token"}

    redactor(payload, secrets=secrets)

    assert payload["message"] == "[REDACTED]"


def test_default_store_isolation_between_calls():
    redactor = build_redactor(
        [PathRule("secret", Action.REDACT), PathRule("message", Action.SCRUB)]
    )

    payload = {"secret": "token", "message": "token"}
    redactor(payload)

    next_payload = {"message": "token"}
    redactor(next_payload)

    assert next_payload["message"] == "token"


def test_base_secrets_are_always_consulted():
    base_store = SecretStore()
    base_store.add("seed")
    options = Options(base_secrets_store=base_store)
    redactor = build_redactor([PathRule("message", Action.SCRUB)], options=options)

    payload = {"message": "seed"}
    redactor(payload)

    assert payload["message"] == "[REDACTED]"


def test_base_secrets_do_not_mutate_on_redact():
    base_store = SecretStore()
    base_store.add("seed")
    options = Options(base_secrets_store=base_store)
    redactor = build_redactor(
        [PathRule("secret", Action.REDACT), PathRule("message", Action.SCRUB)],
        options=options,
    )

    payload = {"secret": "token", "message": "seed token"}
    redactor(payload)

    assert base_store.scrub("token", "[REDACTED]") == "token"


def test_passed_store_persists_between_calls():
    base_store = SecretStore()
    base_store.add("seed")
    options = Options(base_secrets_store=base_store)
    redactor = build_redactor(
        [PathRule("secret", Action.REDACT), PathRule("message", Action.SCRUB)],
        options=options,
    )
    secrets = SecretStore()

    payload = {"secret": "token", "message": "seed token"}
    redactor(payload, secrets=secrets)

    next_payload = {"message": "token"}
    redactor(next_payload, secrets=secrets)

    assert next_payload["message"] == "[REDACTED]"


def test_shared_store_between_redactors():
    shared = SecretStore()
    redactor_a = build_redactor([PathRule("secret", Action.REDACT)])
    redactor_b = build_redactor([PathRule("message", Action.SCRUB)])

    payload = {"secret": "token"}
    redactor_a(payload, secrets=shared)

    next_payload = {"message": "token"}
    redactor_b(next_payload, secrets=shared)

    assert next_payload["message"] == "[REDACTED]"
