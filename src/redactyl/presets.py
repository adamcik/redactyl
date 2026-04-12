from __future__ import annotations

from typing import TYPE_CHECKING

from .core import Action, PathRule, SubstringRule, UrlRule, build_redactor

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .options import Options
    from .types import Redactor, Rule

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
) -> Redactor:
    return build_redactor(
        [
            SubstringRule(tokens=_SENSITIVE_TOKENS, action=Action.REDACT),
            PathRule("event", Action.SCRUB),
            PathRule("exception", Action.SCRUB),
            PathRule("exc_info", Action.SCRUB),
            PathRule("error", Action.SCRUB),
            PathRule("stack", Action.SCRUB),
            PathRule("traceback", Action.SCRUB),
            *rules,
        ],
        options=options,
    )


def sentry_before_send_redactor(
    rules: Iterable[Rule], *, options: Options | None = None
) -> Redactor:
    return build_redactor(
        [
            PathRule("exception.values", Action.DROP),
            PathRule("threads.values", Action.DROP),
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
            PathRule("logentry.message", Action.SCRUB),
            PathRule("logentry.formatted", Action.SCRUB),
            PathRule("logentry.params", Action.SCRUB),
            PathRule("breadcrumbs.*.message", Action.SCRUB),
            PathRule("breadcrumbs.*.data", Action.SCRUB),
        ],
        options=options,
    )


def sentry_breadcrumb_redactor(
    rules: Iterable[Rule], *, options: Options | None = None
) -> Redactor:
    return build_redactor(
        [
            SubstringRule(tokens=_SENSITIVE_TOKENS, action=Action.REDACT),
            UrlRule("data.url", _URL_RULES),
            PathRule("message", Action.SCRUB),
            PathRule("data", Action.SCRUB),
            *rules,
        ],
        options=options,
    )
