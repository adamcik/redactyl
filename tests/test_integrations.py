import io
import json
import sys
from datetime import UTC, datetime
from typing import Never

import pytest
import sentry_sdk
import structlog
from sentry_sdk import logger as sentry_logger
from sentry_sdk.scrubber import EventScrubber
from sentry_sdk.transport import Transport

from redactyl import Action, PathRule
from redactyl.presets import (
    sentry_before_send_log_redactor,
    sentry_before_send_redactor,
    sentry_breadcrumb_redactor,
    structlog_redactor,
)

_SECRET = "synthetic-secret-value"
_REPLACEMENT = "[REDACTED]"


class CaptureTransport(Transport):
    """Keep real SDK envelopes locally; no HTTP transport is constructed."""

    def __init__(self):
        super().__init__()
        self.envelopes = []

    def capture_envelope(self, envelope):
        self.envelopes.append(envelope)

    def payloads(self, item_type):
        return [
            item.payload.json
            for envelope in self.envelopes
            for item in envelope.items
            if item.type == item_type
        ]


@pytest.fixture
def sentry():
    transport = CaptureTransport()
    clients = []
    with sentry_sdk.isolation_scope(), sentry_sdk.new_scope() as scope:

        def configure(**options: object) -> CaptureTransport:
            client = sentry_sdk.Client(
                dsn="https://public@example.invalid/1",
                transport=transport,
                default_integrations=False,
                auto_enabling_integrations=False,
                send_client_reports=False,
                event_scrubber=EventScrubber(denylist=[], pii_denylist=[]),
                traces_sample_rate=1.0,
                **options,
            )
            scope.set_client(client)
            clients.append(client)
            return transport

        yield configure
        for client in clients:
            client.close()


def _raise_rule(**_kwargs: object) -> Never:
    raise RuntimeError("synthetic rule failure")


def _interrupt_rule(**_kwargs: object) -> Never:
    raise KeyboardInterrupt


def test_sentry_error_preserves_exception_and_stack_without_frame_locals(sentry):
    transport = sentry(
        before_send=sentry_before_send_redactor([]),
        include_local_variables=True,
    )
    sentry_sdk.set_extra("password", _SECRET)
    try:
        raise ValueError(f"failed with {_SECRET}")  # noqa: TRY301
    except ValueError:
        sentry_sdk.capture_exception()

    [event] = transport.payloads("event")
    [exception] = event["exception"]["values"]
    assert exception["type"] == "ValueError"
    assert exception["value"] == f"failed with {_REPLACEMENT}"
    frames = exception["stacktrace"]["frames"]
    assert frames
    assert frames[-1]["function"] == (
        "test_sentry_error_preserves_exception_and_stack_without_frame_locals"
    )
    assert all("vars" not in frame for frame in frames)
    assert _SECRET not in json.dumps(event)


def test_sentry_thread_stack_and_nested_sensitive_keys(sentry):
    transport = sentry(before_send=sentry_before_send_redactor([]))
    sentry_sdk.capture_event(
        {
            "message": f"thread failed with {_SECRET}",
            "threads": {
                "values": [
                    {
                        "id": 7,
                        "name": "worker",
                        "stacktrace": {
                            "frames": [
                                {
                                    "function": "work",
                                    "filename": "worker.py",
                                    "lineno": 42,
                                    "vars": {"local": _SECRET},
                                    "context_line": f"work('{_SECRET}')",
                                }
                            ]
                        },
                    }
                ]
            },
            "extra": {"nested": {"accessToken": _SECRET}},
        }
    )
    [event] = transport.payloads("event")
    [thread] = event["threads"]["values"]
    assert thread["name"] == "worker"
    [frame] = thread["stacktrace"]["frames"]
    assert frame["function"] == "work"
    assert frame["lineno"] == 42  # noqa: PLR2004
    assert "vars" not in frame
    assert frame["context_line"] == f"work('{_REPLACEMENT}')"
    assert event["extra"]["nested"]["accessToken"] == _REPLACEMENT
    assert _SECRET not in json.dumps(event)


def test_sentry_breadcrumb_hook_and_event_breadcrumb_shape(sentry):
    transport = sentry(
        before_send=sentry_before_send_redactor([]),
        before_breadcrumb=sentry_breadcrumb_redactor([]),
    )
    sentry_sdk.add_breadcrumb(
        message=f"request {_SECRET}",
        data={"nested": {"password": _SECRET}},
    )
    sentry_sdk.capture_message("safe message")
    [event] = transport.payloads("event")
    [breadcrumb] = event["breadcrumbs"]["values"]
    assert breadcrumb["message"] == f"request {_REPLACEMENT}"
    assert breadcrumb["data"]["nested"]["password"] == _REPLACEMENT
    assert _SECRET not in json.dumps(event)


def test_event_hook_scrubs_breadcrumbs_without_breadcrumb_hook(sentry):
    transport = sentry(before_send=sentry_before_send_redactor([]))
    sentry_sdk.add_breadcrumb(message=f"request {_SECRET}", data={"password": _SECRET})
    sentry_sdk.capture_message("safe message")
    [event] = transport.payloads("event")
    assert event["breadcrumbs"]["values"][0]["message"] == (f"request {_REPLACEMENT}")
    assert _SECRET not in json.dumps(event)


def test_sentry_transaction_and_span_strings(sentry):
    transport = sentry(
        before_send_transaction=sentry_before_send_redactor([]),
    )
    sentry_sdk.set_extra("password", _SECRET)
    with (
        sentry_sdk.start_transaction(name=f"job {_SECRET}", op="task"),
        sentry_sdk.start_span(op="work", name=f"process {_SECRET}"),
    ):
        pass

    [event] = transport.payloads("transaction")
    assert event["transaction"] == f"job {_REPLACEMENT}"
    assert event["spans"][0]["description"] == f"process {_REPLACEMENT}"
    assert event["spans"][0]["op"] == "work"
    assert _SECRET not in json.dumps(event)


def test_sentry_log_hook_receives_sdk_body_and_plain_attributes(sentry):
    transport = sentry(
        enable_logs=True,
        before_send_log=sentry_before_send_log_redactor([]),
        # Event callbacks are not used for the separate log pipeline.
        before_send=sentry_before_send_redactor([_raise_rule]),
    )
    sentry_logger.info(
        f"login {_SECRET}",
        attributes={"password": _SECRET, "description": f"used {_SECRET}"},
    )
    sentry_sdk.flush()

    [batch] = transport.payloads("log")
    [log] = batch["items"]
    assert log["body"] == f"login {_REPLACEMENT}"
    assert log["attributes"]["password"] == {
        "value": _REPLACEMENT,
        "type": "string",
    }
    assert log["attributes"]["description"]["value"] == f"used {_REPLACEMENT}"
    assert _SECRET not in json.dumps(log)


@pytest.mark.parametrize("pipeline", ["event", "breadcrumb", "transaction", "log"])
def test_sentry_redaction_failure_drops_the_affected_payload(sentry, pipeline):
    options = {
        "event": {"before_send": sentry_before_send_redactor([_raise_rule])},
        "breadcrumb": {"before_breadcrumb": sentry_breadcrumb_redactor([_raise_rule])},
        "transaction": {
            "before_send_transaction": sentry_before_send_redactor([_raise_rule])
        },
        "log": {
            "enable_logs": True,
            "before_send_log": sentry_before_send_log_redactor([_raise_rule]),
        },
    }
    transport = sentry(**options[pipeline])
    if pipeline == "breadcrumb":
        sentry_sdk.add_breadcrumb(message=_SECRET)
        sentry_sdk.capture_message("safe message")
        [event] = transport.payloads("event")
        assert not event.get("breadcrumbs", {}).get("values")
    elif pipeline == "transaction":
        with sentry_sdk.start_transaction(name=_SECRET):
            pass
        assert not transport.payloads("transaction")
    elif pipeline == "log":
        sentry_logger.info(_SECRET)
        sentry_sdk.flush()
        assert not transport.payloads("log")
    else:
        assert sentry_sdk.capture_message(_SECRET) is None
        assert not transport.payloads("event")


def test_attachments_bypass_event_redaction(sentry):
    """Event hooks cannot promise attachment privacy; omit or sanitize separately."""
    transport = sentry(before_send=sentry_before_send_redactor([]))
    sentry_sdk.get_current_scope().add_attachment(
        bytes=_SECRET.encode(), filename="synthetic.txt"
    )
    sentry_sdk.set_extra("password", _SECRET)
    sentry_sdk.capture_message(f"request {_SECRET}")

    [event] = transport.payloads("event")
    assert _SECRET not in json.dumps(event)
    attachments = [
        item
        for envelope in transport.envelopes
        for item in envelope.items
        if item.type == "attachment"
    ]
    assert len(attachments) == 1
    assert attachments[0].get_bytes() == _SECRET.encode()


def test_event_failure_drops_attached_envelope_items(sentry):
    transport = sentry(before_send=sentry_before_send_redactor([_raise_rule]))
    sentry_sdk.get_current_scope().add_attachment(
        bytes=_SECRET.encode(), filename="synthetic.txt"
    )
    assert sentry_sdk.capture_message(_SECRET) is None
    assert not transport.envelopes


@pytest.mark.parametrize(
    "header",
    [
        "Authorization",
        "authorization",
        "AUTHORIZATION",
        "Cookie",
        "Set-Cookie",
    ],
)
def test_sentry_serialized_headers_with_different_casing(sentry, header):
    transport = sentry(before_send=sentry_before_send_redactor([]))
    sentry_sdk.capture_event(
        {
            "message": f"request {_SECRET}",
            "request": {"headers": {header: _SECRET}},
        }
    )
    [event] = transport.payloads("event")
    assert event["request"]["headers"][header] == _REPLACEMENT
    assert event["message"] == f"request {_REPLACEMENT}"


def test_structlog_normalizes_exception_before_redaction():
    sink = io.StringIO()
    logger = structlog.wrap_logger(
        structlog.PrintLogger(file=sink),
        processors=[
            structlog.processors.format_exc_info,
            structlog_redactor([]),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(0),
    )
    try:
        raise ValueError(_SECRET)  # noqa: TRY301
    except ValueError:
        logger.exception("synthetic failure", password=_SECRET)
    event = json.loads(sink.getvalue())
    assert "ValueError" in event["exception"]
    assert _REPLACEMENT in event["exception"]
    assert _SECRET not in sink.getvalue()


def test_structlog_unnormalized_exception_is_not_emitted():
    sink = io.StringIO()
    logger = make_logger(structlog_redactor([]), sink)
    try:
        raise ValueError(_SECRET)  # noqa: TRY301
    except ValueError:
        logger.error("synthetic failure", exc_info=sys.exc_info())  # noqa: G201
    assert sink.getvalue() == ""


def make_logger(processor, sink):
    return structlog.wrap_logger(
        structlog.PrintLogger(file=sink),
        processors=[processor, structlog.processors.JSONRenderer()],
        wrapper_class=structlog.BoundLogger,
    )


def test_structlog_processor_returns_renderable_sanitized_event():
    sink = io.StringIO()
    logger = make_logger(structlog_redactor([]), sink)
    logger.info(f"login {_SECRET}", nested={"password": _SECRET})  # noqa: G004
    event = json.loads(sink.getvalue())
    assert event["event"] == f"login {_REPLACEMENT}"
    assert event["nested"]["password"] == _REPLACEMENT
    assert _SECRET not in sink.getvalue()


@pytest.mark.parametrize(
    ("rules", "fields"), [([_raise_rule], {}), ([], {"bad": object()})]
)
def test_structlog_redaction_failure_never_reaches_sink(rules, fields):
    sink = io.StringIO()
    logger = make_logger(structlog_redactor(rules), sink)
    logger.info(_SECRET, **fields)
    assert sink.getvalue() == ""


@pytest.mark.parametrize(
    "factory",
    [
        sentry_before_send_redactor,
        sentry_breadcrumb_redactor,
        sentry_before_send_log_redactor,
    ],
)
def test_sentry_hooks_return_original_dictionary_and_leave_hint_untouched(factory):
    payload = {"password": _SECRET}
    hint = {"password": "hint-is-outside-the-event"}
    assert factory([])(payload, hint) is payload
    assert payload == {"password": _REPLACEMENT}
    assert hint == {"password": "hint-is-outside-the-event"}


@pytest.mark.parametrize(
    "factory",
    [
        sentry_before_send_redactor,
        sentry_breadcrumb_redactor,
        sentry_before_send_log_redactor,
    ],
)
def test_sentry_hooks_do_not_swallow_process_control_exceptions(factory):
    with pytest.raises(KeyboardInterrupt):
        factory([_interrupt_rule])({"ordinary": "value"}, {})


@pytest.mark.parametrize(
    "factory",
    [
        sentry_before_send_redactor,
        sentry_breadcrumb_redactor,
        sentry_before_send_log_redactor,
    ],
)
def test_sentry_hooks_drop_unsupported_payloads_without_mutating_them(factory):
    unsupported = object()
    payload = {"password": _SECRET, "unsupported": unsupported}
    assert factory([])(payload, {}) is None
    assert payload == {"password": _SECRET, "unsupported": unsupported}


def test_breadcrumb_adapter_normalizes_only_the_sdk_timestamp():
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)
    payload = {"timestamp": timestamp, "message": "safe message"}
    assert sentry_breadcrumb_redactor([])(payload, {}) is payload
    assert payload["timestamp"] == timestamp.isoformat()

    unsupported = {"timestamp": timestamp, "data": {"arbitrary": timestamp}}
    assert sentry_breadcrumb_redactor([])(unsupported, {}) is None
    assert unsupported["timestamp"] is timestamp
    assert unsupported["data"]["arbitrary"] is timestamp


def test_structlog_processor_does_not_swallow_process_control_exceptions():
    with pytest.raises(KeyboardInterrupt):
        structlog_redactor([_interrupt_rule])(None, "info", {"event": "value"})


def test_sentry_custom_rule_can_identify_additional_secrets(sentry):
    transport = sentry(
        before_send=sentry_before_send_redactor(
            [PathRule("extra.account_id", Action.REDACT)]
        )
    )
    sentry_sdk.set_extra("account_id", _SECRET)
    sentry_sdk.capture_message(f"account {_SECRET}")
    [event] = transport.payloads("event")
    assert event["message"] == f"account {_REPLACEMENT}"
    assert event["extra"]["account_id"] == _REPLACEMENT
