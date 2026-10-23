from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Protocol, cast

from .core import (
    Action,
    PathRule,
    RegexPathRule,
    SubstringRule,
    UrlRule,
    build_redactor,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .options import Options
    from .types import JsonValue, Redactor, Rule


class _SentryHook(Protocol):
    # Preserve SDK TypedDict types without requiring the SDK at core import time.
    def __call__[Payload](self, payload: Payload, hint: object) -> Payload | None: ...


class _StructlogProcessor(Protocol):
    def __call__[Payload](
        self, logger: object, method_name: str, event_dict: Payload
    ) -> Payload: ...


_SENSITIVE_TOKENS: frozenset[str] = frozenset(
    {
        "authorization",
        "auth",
        "bearer",
        "cookie",
        "credential",
        "jwt",
        "passphrase",
        "password",
        "private",
        "secret",
        "session",
        "token",
    }
)

_URL_RULES: tuple[Rule, ...] = (
    PathRule("userinfo.user", Action.REDACT),
    PathRule("userinfo.password", Action.REDACT),
    PathRule("fragment", Action.REDACT),
    PathRule("params.*", Action.REDACT),
)


def structlog_redactor(
    rules: Iterable[Rule], *, options: Options | None = None
) -> _StructlogProcessor:
    """Build a processor that drops the log if redaction cannot complete.

    Place this before rendering. Exception objects and ``exc_info`` tuples must
    first be converted to JSON-compatible data by a preceding processor.
    """
    from structlog import DropEvent  # noqa: PLC0415

    redact = build_redactor(
        [
            SubstringRule(tokens=_SENSITIVE_TOKENS, action=Action.REDACT),
            *rules,
            PathRule("event", Action.SCRUB),
            PathRule("exception", Action.SCRUB),
            PathRule("exc_info", Action.SCRUB),
            PathRule("error", Action.SCRUB),
            PathRule("stack", Action.SCRUB),
            PathRule("traceback", Action.SCRUB),
        ],
        options=options,
    )

    def processor[Payload](
        logger: object,  # noqa: ARG001
        method_name: str,  # noqa: ARG001
        event_dict: Payload,
    ) -> Payload:
        try:
            redact(cast("dict[str, JsonValue]", event_dict))
        except Exception:  # noqa: BLE001 - never emit a partially redacted log
            raise DropEvent from None
        return event_dict

    return processor


def sentry_before_send_redactor(
    rules: Iterable[Rule], *, options: Options | None = None
) -> _SentryHook:
    """Build a fail-closed ``before_send`` or ``before_send_transaction`` hook.

    Exception and thread stacks remain useful, but frame locals are dropped.
    Attachments are separate envelope items and bypass this hook: callers must
    omit or independently sanitize them. Logs require their separate hook.
    """
    return _sentry_hook(
        build_redactor(
            [
                RegexPathRule(r"(^|\.)frames\.\d+\.vars$", Action.DROP),
                *rules,
                SubstringRule(tokens=_SENSITIVE_TOKENS, action=Action.REDACT),
                UrlRule("request.url", _URL_RULES),
                PathRule("request.headers.authorization", Action.REDACT),
                PathRule("request.headers.cookie", Action.REDACT),
                PathRule("request.headers.*", Action.SCRUB),
                PathRule("request.cookies.*", Action.REDACT),
                PathRule("request.data", Action.SCRUB),
                PathRule("request.query_string", Action.SCRUB),
                PathRule("request.env", Action.SCRUB),
                PathRule("extra", Action.SCRUB),
                PathRule("contexts", Action.SCRUB),
                PathRule("tags", Action.SCRUB),
                PathRule("user.email", Action.REDACT),
                PathRule("user.ip_address", Action.REDACT),
                PathRule("message", Action.SCRUB),
                PathRule("event", Action.SCRUB),
                PathRule("exception", Action.SCRUB),
                PathRule("threads", Action.SCRUB),
                PathRule("stacktrace", Action.SCRUB),
                PathRule("transaction", Action.SCRUB),
                PathRule("spans", Action.SCRUB),
                PathRule("logentry.message", Action.SCRUB),
                PathRule("logentry.formatted", Action.SCRUB),
                PathRule("logentry.params", Action.SCRUB),
                PathRule("breadcrumbs", Action.SCRUB),
            ],
            options=options,
        ),
    )


def sentry_breadcrumb_redactor(
    rules: Iterable[Rule], *, options: Options | None = None
) -> _SentryHook:
    """Build a fail-closed ``before_breadcrumb`` hook.

    Sentry's datetime timestamp is normalized to ISO text; other unsupported
    values still cause the breadcrumb to be dropped.
    """
    return _sentry_hook(
        build_redactor(
            [
                SubstringRule(tokens=_SENSITIVE_TOKENS, action=Action.REDACT),
                *rules,
                UrlRule("data.url", _URL_RULES),
                PathRule("message", Action.SCRUB),
                PathRule("data", Action.SCRUB),
            ],
            options=options,
        ),
        breadcrumb=True,
    )


def sentry_before_send_log_redactor(
    rules: Iterable[Rule], *, options: Options | None = None
) -> _SentryHook:
    """Build a fail-closed ``before_send_log`` hook for SDK log dictionaries.

    The SDK supplies plain attribute values here, not the typed attribute
    envelopes it serializes for transport. Event hooks do not process logs.
    """
    return _sentry_hook(
        build_redactor(
            [
                *rules,
                SubstringRule(tokens=_SENSITIVE_TOKENS, action=Action.REDACT),
                PathRule("body", Action.SCRUB),
                PathRule("attributes", Action.SCRUB),
            ],
            options=options,
        )
    )


def _sentry_hook(redact: Redactor, *, breadcrumb: bool = False) -> _SentryHook:
    def hook[Payload](
        payload: Payload,
        hint: object,  # noqa: ARG001
    ) -> Payload | None:
        try:
            if type(payload) is not dict:
                return None
            target = cast("dict[str, JsonValue]", payload)
            candidate = target
            timestamp = cast("object", target.get("timestamp"))
            if breadcrumb and type(timestamp) is datetime:
                candidate = dict(target)
                candidate["timestamp"] = timestamp.isoformat()
            redact(candidate)
        except Exception:  # noqa: BLE001 - callback failure must drop the payload
            return None
        if candidate is not target:
            target.clear()
            target.update(candidate)
        return cast("Payload", payload)

    return hook
