# SDK callback migration

The SDK factories now return callbacks with the signatures and return values required
by their SDKs, not one-argument mutators. Update registration and direct invocations.
Install `sentry-sdk` or `structlog` separately; neither is a core runtime dependency.

## Sentry

```python
import sentry_sdk
from redactyl import (
    sentry_before_send_log_redactor,
    sentry_before_send_redactor,
    sentry_breadcrumb_redactor,
)

sentry_sdk.init(
    before_send=sentry_before_send_redactor([]),
    before_breadcrumb=sentry_breadcrumb_redactor([]),
    before_send_transaction=sentry_before_send_redactor([]),
    before_send_log=sentry_before_send_log_redactor([]),
)
```

Each hook accepts `(payload, hint)` and returns the sanitized payload or `None` to drop
it on failure. Configure transactions and logs separately: `before_send` does not cover
them. Frame-local `vars` dictionaries are dropped while stack structure remains.
Breadcrumb timestamps are normalized; hints are left untouched. Hooks do not share a
secret store implicitly.

Attachments bypass these hooks. Omit or sanitize their bytes, names, and metadata
independently. Profiles, sessions, metrics, replays, and other telemetry are not covered.

## Structlog

```python
import structlog
from redactyl import structlog_redactor

structlog.configure(processors=[
    structlog.processors.dict_tracebacks,
    structlog_redactor([]),
    structlog.processors.JSONRenderer(),
])
```

The processor accepts `(logger, method_name, event_dict)` and returns the sanitized
dictionary. On redaction failure it raises `structlog.DropEvent`, suppressing that log.
Normalize exception objects and `exc_info` tuples before redaction, and redact before
rendering and every sink. Structured traceback `locals` dictionaries are dropped;
exception messages, filenames, and other unknown text are not automatically safe.
Later processors can still introduce sensitive data.

Both adapters let process-control exceptions such as `KeyboardInterrupt` propagate.
Do not catch redaction errors and emit the original payload as a fallback. The
[core compatibility notes](core-migration.md) also apply, including nested object
replacement and deterministic custom rules.
