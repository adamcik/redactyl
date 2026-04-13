<p align="center">
  <img src="https://github.com/adamcik/redactyl/raw/main/static/redactyl.svg" alt="Redactyl logo" width="420" />
</p>

# Redactyl

Defense-in-depth redaction and scrubbing for Python structured payloads.

Redactyl is a Python library for removing sensitive data from structured logs,
error payloads, Sentry events, and other nested JSON-like dict/list payloads.
It is built for real-world payloads where the full shape is not known ahead of
time. You define layered rules and heuristics, then Redactyl mutates payloads
in-place.

`REDACT` replaces the matched value directly. `SCRUB` removes previously seen
secrets from surrounding text using a shared `SecretStore`.

## Features

- Built for Python services that process logs, events, and nested payloads
- In-place mutation of dict/list payloads with no schema requirement
- Path-based rules with wildcards (`PathRule("user.*", ...)`)
- Regex rules for paths and string values (`RegexPathRule`, `RegexValueRule`)
- Key token matching across snake_case and camelCase (`SubstringRule`)
- URL-aware rewriting for query params, userinfo, and fragments (`UrlRule`, `Action.URL`)
- Actions for different handling strategies: `REDACT`, `SCRUB`, `DROP`, `SAFE`, `URL`, `HASH`
- Optional limits (`max_depth`, `max_items`) to cap large payload traversal

## Install

This project uses `uv` for dependency management.

```bash
uv sync
```

## Quick start

```python
from redactyl import Action, PathRule, SubstringRule, build_redactor

rules = [
    PathRule("user.password", Action.REDACT),
    SubstringRule(tokens=frozenset({"token"}), action=Action.REDACT),
]

redactor = build_redactor(rules)

payload = {
    "user": {"password": "hunter2"},
    "id_token": "secret",
    "message": "token=hunter2",
}

redactor(payload)
print(payload)
```

## API taxonomy

The API has two primary concepts:

- Rules: match a path or value and return a `RuleDecision`.
- Actions: what to do when a rule matches (replace, scrub, drop, stop).

Common taxonomy:

- Path-based rules (`PathRule`, `RegexPathRule`, `UrlRule`) match structured payload paths.
- Value-based rules (`RegexValueRule`) match and transform string content.
- Token rules (`SubstringRule`) match key names by tokenizing camel/snake case.

Notes:

- Prefer `UrlRule` when you know a field is a URL and want to apply URL rules.
- Use `RegexValueRule(..., action=Action.URL, rules=...)` to find URLs inside strings.
- `SCRUB` always relies on the shared `SecretStore` for the current call or provided `secrets=`.

## Cookbook

Examples are independent. Copy the snippet you need.

```python
import re

from redactyl import (
    Action,
    PathRule,
    RegexValueRule,
    SubstringRule,
    UrlRule,
    build_redactor,
)
from redactyl.secrets import SecretStore

# Redact known sensitive fields
redactor = build_redactor(
    [
        PathRule("user.password", Action.REDACT),
        PathRule("auth.token", Action.REDACT),
    ]
)

# Redact by key token (camel/snake)
redactor = build_redactor(
    [
        SubstringRule(tokens=frozenset({"token", "secret"}), action=Action.REDACT),
    ]
)

# Scrub previously seen secrets from a message
redactor = build_redactor(
    [
        PathRule("user.password", Action.REDACT),
        PathRule("message", Action.SCRUB),
    ]
)

# Share secrets across multiple payloads in a request lifecycle
secrets = SecretStore()
redactor = build_redactor(
    [
        PathRule("secret", Action.REDACT),
        PathRule("message", Action.SCRUB),
    ]
)
redactor({"secret": "token", "message": "token"}, secrets=secrets)
redactor({"message": "token"}, secrets=secrets)

# Redact URL params in a known URL field
redactor = build_redactor(
    [
        UrlRule(
            "url",
            (
                PathRule("params.token", Action.REDACT),
                PathRule("params.password", Action.REDACT),
            ),
        ),
    ]
)

# Redact sensitive param names inside URLs found in text
url_rules = (
    SubstringRule(
        tokens=frozenset({"token", "apikey", "password"}), action=Action.REDACT
    ),
    PathRule("userinfo.*", Action.REDACT),
    PathRule("fragment", Action.REDACT),
)
redactor = build_redactor(
    [
        RegexValueRule(
            pattern=re.compile(r"https?://\S+"),
            action=Action.URL,
            rules=url_rules,
        ),
    ]
)

# Scrub URL params using previously seen secrets
redactor = build_redactor(
    [
        PathRule("secret", Action.REDACT),
        UrlRule("url", (PathRule("params.*", Action.SCRUB),)),
        RegexValueRule(
            pattern=re.compile(r"https?://\S+"),
            action=Action.URL,
            rules=(PathRule("params.*", Action.SCRUB),),
        ),
    ]
)
```

## Secret store lifetime

By default, each `redactor(...)` call uses a fresh mutable secret store, so newly seen secrets do not leak across calls. You can also pass your own `SecretStore` to persist secrets for a request lifecycle.

Important limitation: if a later call sees a new secret that should have been scrubbed in an earlier call, it will not be scrubbed retroactively. Avoid relying on cross-call scrubbing for newly discovered values.

```python
from redactyl import Action, Options, PathRule, build_redactor
from redactyl.secrets import SecretStore

base = SecretStore()
base.add("seed", "[REDACTED]")

options = Options(base_secrets_store=base)
redactor = build_redactor(
    [
        PathRule("secret", Action.REDACT),
        PathRule("message", Action.SCRUB),
    ],
    options=options,
)

request_store = SecretStore()
payload = {"secret": "token", "message": "seed token"}
redactor(payload, secrets=request_store)
```

## Rules and actions

### PathRule

Matches dot-delimited paths with optional `*` wildcards.

```python
from redactyl import Action, PathRule

PathRule("user.password", Action.REDACT)
PathRule("user.*", Action.REDACT)
```

### RegexPathRule

Matches a path using a regular expression.

```python
from redactyl import Action, RegexPathRule

RegexPathRule(pattern=r"\.secret$", action=Action.REDACT)
```

### SubstringRule

Matches key tokens derived from camelCase, snake_case, and alphanumerics.

```python
from redactyl import Action, SubstringRule

SubstringRule(tokens=frozenset({"token"}), action=Action.REDACT)
```

### RegexValueRule

Matches string values by regex and applies the action to the match.

```python
from redactyl import Action, RegexValueRule

RegexValueRule(
    pattern=r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    action=Action.REDACT,
)
```

### URL rules

Use `UrlRule` to parse a URL string and apply rules to its parts.

```python
from redactyl import Action, PathRule, UrlRule, build_redactor

redactor = build_redactor(
    [
        UrlRule("url", (PathRule("params.token", Action.REDACT),)),
    ]
)

preset = build_redactor(
    [
        UrlRule(
            "url",
            (
                PathRule("userinfo.user", Action.REDACT),
                PathRule("userinfo.password", Action.REDACT),
                PathRule("fragment", Action.REDACT),
                PathRule("params.*", Action.REDACT),
            ),
        ),
    ]
)
```

### Actions

- `REDACT`: Replace with the configured replacement string (default `[REDACTED]`).
- `SCRUB`: Replace any previously-seen secrets within the value.
- `DROP`: Remove the key from the payload.
- `SAFE`: Stop rule processing and skip children.
- `URL`: Parse and redact URL components using default rules.
- `HASH`: Replace a string with a short hash digest.

## Presets

Common entry points for structured logging and error reporting.

```python
from redactyl import (
    Action,
    PathRule,
    sentry_before_send_redactor,
    sentry_breadcrumb_redactor,
    structlog_redactor,
)

rules = [PathRule("user.password", Action.REDACT)]

before_send = sentry_before_send_redactor(rules)
breadcrumb = sentry_breadcrumb_redactor(rules)
structlog = structlog_redactor(rules)
```

## Options

Configure behavior via `Options`:

```python
from redactyl import Options, build_redactor

options = Options(
    replacement="[REDACTED]",
    min_length=4,
    max_depth=None,
    max_items=None,
    hash_secret=b"secret",
    hash_length=10,
)

redactor = build_redactor([], options=options)
```

Notes:

- `max_depth` and `max_items` replace oversized structures with `[...]`.
- `min_length` controls which redacted values are registered for `SCRUB`.

## Tests

```bash
uv run pytest
```
