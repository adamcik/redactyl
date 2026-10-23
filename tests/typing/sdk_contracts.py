"""Static integration tests against SDK annotations, not replacement SDK stubs.

Callback assignments must type-check against the installed SDKs. The runtime
integration tests separately check emitted payloads with local capture sinks.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from sentry_sdk._types import Breadcrumb, Event, Hint, Log
    from structlog.types import Processor

    from redactyl import (
        sentry_before_send_log_redactor,
        sentry_before_send_redactor,
        sentry_breadcrumb_redactor,
        structlog_redactor,
    )

    event_hook: Callable[[Event, Hint], Event | None] = sentry_before_send_redactor([])
    transaction_hook: Callable[[Event, Hint], Event | None] = (
        sentry_before_send_redactor([])
    )
    breadcrumb_hook: Callable[[Breadcrumb, Hint], Breadcrumb | None] = (
        sentry_breadcrumb_redactor([])
    )
    log_hook: Callable[[Log, Hint], Log | None] = sentry_before_send_log_redactor([])
    processor: Processor = structlog_redactor([])
