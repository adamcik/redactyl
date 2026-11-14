<p align="center">
  <img src="https://github.com/adamcik/redactyl/raw/main/static/redactyl.svg" alt="Redactyl logo" width="420" />
</p>

# Redactyl

Rule-based redaction for Python logs, events, and nested JSON-like payloads.

**Redactyl is not a general-purpose PII detector or a guarantee that a payload is safe
to publish.** Key rules protect values under selected keys. Regex rules protect matching
text. Known-secret scrubbing protects exact occurrences of discovered or explicitly
seeded strings in selected string values. Unknown identifiers, names, addresses, source
code, and arbitrary free text remain potentially sensitive. Prefer not collecting
sensitive data; use allowlists where possible.

## Install and use

Python 3.12 or later; the core has no runtime dependencies.

```sh
pip install redactyl
```

```python
from redactyl import Action, PathRule, SubstringRule, build_redactor

redact = build_redactor([
    SubstringRule(frozenset({"password", "token"}), Action.REDACT),
    PathRule("message", Action.SCRUB),
])
payload = {
    "message": "failed with synthetic-secret",  # order does not matter
    "data": [{"password": "synthetic-secret"}],
}
redact(payload)  # returns None; commits the result to this root dictionary
assert payload["message"] == "failed with [REDACTED]"
```

## Guarantees and boundaries

### One payload

Redaction first discovers secrets, then renders a private copy with the complete
discovered set. Within a successful call, `SCRUB` can therefore remove a secret even
when its sensitive field occurs later in dictionary or list traversal. Discovery follows
the same rule precedence, `SAFE` boundaries, and structural limits as output. This is
not universal string scrubbing: only locations selected for `SCRUB` are scrubbed. Other
terminal actions can deliberately exempt a value.

`REDACT`, `DROP`, and `HASH` register strings of at least `min_length` characters.
Dropped or replaced containers contribute all reachable string **values** in their
bounded subtree, irrespective of child rules. Numbers, keys, and strings below the
threshold are not registered. Secrets hidden by truncation or `SAFE` boundaries are not
discovered. Regex REDACT/HASH/DROP register each whole regex match, not its surrounding
input or individual capture groups. Zero-length matches contribute nothing.

Scrubbing is case-sensitive literal substring replacement, longest match first. It does
not infer related values, normalize Unicode, discover arbitrary encodings, or scrub
dictionary keys. Accidental substring matches can over-redact useful text. Replacement
strings are literal, including backslashes. Avoid replacement strings that themselves
contain sensitive data.

### Across calls and concurrent use

By default, each call gets a new store. Newly discovered values do not cross calls. An
explicit `SecretStore` retains them until that store is discarded:

```python
from redactyl.secrets import SecretStore

store = SecretStore()
redact({"password": "synthetic-secret"}, secrets=store)
later = {"message": "synthetic-secret"}
redact(later, secrets=store)
```

No call can retroactively sanitize earlier output. A secret discovered only in a later
event cannot protect an earlier event. Sharing a store across unrelated events increases
retention and cross-event coupling; use a short, explicit lifetime, such as one request,
rather than a global store. There is no TTL, eviction, disk persistence, or secure
memory erasure. Python's regex caches can retain compiled secret patterns after a store
is discarded. Optional `max_secrets` and `max_chars` limits fail rather than evict
protection; both default to `None` (unlimited).

The built redactor can process independent payloads concurrently with built-in rules.
Operations using the same explicit store serialize discovery, rendering, and commit;
failed operations do not add secrets. Concurrent ordering does not guarantee that a
consumer runs after the event that discovers its secret. Do not concurrently mutate the
same payload, rule configuration, or caller-owned nested data.

`Options(base_secrets_store=...)` snapshots seed secrets when building the redactor;
later changes to the base store are ignored. Seeds count toward any configured store
capacity. `store.add("synthetic-secret")` can seed a store explicitly.

### Atomic failure and supported input

The root must be a plain `dict` with string keys. Nested plain dictionaries, lists,
strings, integers, floats, booleans, and `None` are supported. List paths include
zero-based original indices, including when earlier elements are dropped.

String, integer, and float subclasses (including string/integer enums) are normalized to
their built-in values. Exceptions, `exc_info` tuples, bytes, UUIDs, datetimes, tuples,
other custom objects, and container subclasses are rejected with `TypeError`; they are
not silently stringified. Values inside structurally truncated subtrees are not
inspected. Normalize unsupported values deliberately before calling the core. Cycles
encountered within the traversal bounds raise `ValueError`. Shared references are copied
independently per path, so one path's `SAFE` rule cannot undo another path's redaction.

On a rule, type, resource, or parsing-processing failure, the core raises and leaves the
original payload and explicit secret store unchanged. **Never emit the original payload
after catching a redaction error.** A successful call replaces nested objects; external
aliases to the original nested data remain unsanitized. The root identity is preserved;
nested identities and shared-reference relationships are not.

Custom rules run twice (discovery with scrubbing disabled, then rendering). They must be
deterministic and have no external side effects. The library cannot undo external side
effects, provide transactional guarantees for malicious rule code, or interrupt a rule
that never returns.

## Rules and precedence

Rules are evaluated **in supplied order**, not by an implicit action ranking. The first
matching built-in rule is terminal at its node. A custom `ContinueDecision` transforms
the value and permits later rules to run.

| Action   | Effect at a matching path/key                                                                                                 |
| -------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `REDACT` | Replace the entire value with `Options.replacement`; skip children.                                                           |
| `DROP`   | Remove the key/list element; skip children.                                                                                   |
| `HASH`   | HMAC a string, register its original, skip children; other types fail.                                                        |
| `SAFE`   | Preserve the value and skip all child rules and inherited scrubbing. Explicit trust bypass.                                   |
| `SCRUB`  | Scrub a string; on a container, keep evaluating child rules and inherit scrubbing for otherwise unmatched string descendants. |
| `URL`    | Parse a string and apply URL rules; other types fail.                                                                         |

Thus `SAFE` before `REDACT` preserves; reversing them redacts. `SCRUB` on a container
does **not** disable child sensitive-key rules. A child's terminal `SAFE`, `URL`, regex
transformation, or replacement takes precedence over inherited `SCRUB`. Put narrowly
targeted exceptions before broader rules, deliberately.

Event/log presets put custom rules before generic defaults (except frame-local DROP).
Structlog/breadcrumb presets put sensitive-token rules before custom rules; custom rules
precede their broad SCRUB defaults. Ancestor SAFE still bypasses children.

- `PathRule("user.*", action)` matches one segment per `*`, case-sensitively. Dots
  flatten paths: a literal key `"user.password"` and nested `user/password` match the
  same path. There is no escape syntax; use a key-token rule when needed.
- `RegexPathRule(r"(^|\.)password$", action)` searches flattened paths.
- `SubstringRule(frozenset({"password", "token"}), action)` matches lowercase tokens
  split from snake_case, camelCase, punctuation, and header names. It is not an
  arbitrary substring search or a comprehensive list of sensitive fields.
- `RegexValueRule(pattern, action)` searches string values. REDACT/HASH/DROP replace
  matches (DROP deletes matches, not the field); SCRUB scrubs only matches; SAFE
  preserves the whole value. URL processes each matched URL with its `rules=` tuple.

## URLs

```python
from redactyl import UrlRule

redact_url = build_redactor([
    PathRule("password", Action.REDACT),
    UrlRule("url", (
        PathRule("userinfo.*", Action.REDACT),
        PathRule("params.*", Action.REDACT),
        PathRule("fragment", Action.REDACT),
        PathRule("path", Action.SCRUB),
    )),
])
```

`UrlRule` exposes `scheme`, `host`, `port`, `path`, `fragment`, `userinfo.user`,
`userinfo.password`, and `params.<decoded-name>`. It applies only its supplied URL
rules, not the outer rules. `Action.URL` uses defaults that redact all query values,
userinfo, and fragments; it does **not** redact the host or path. Unknown identifiers in
paths/hosts remain sensitive. Add rules or replace the entire URL as appropriate.

Query names and values, userinfo, paths, and fragments are decoded once for rules.
Repeated query names retain all values as a list, so none are silently discarded before
discovery. Unchanged repeated values and blank values survive serialization; replacing a
parameter container collapses its occurrences to one replacement. Use `params.token.*`
for element-wise actions such as HASH on repeated values. Query ordering across distinct
names and original query escaping are not preserved. Unchanged paths preserve their
original escaping, including encoded separators. Only a rule that changes the decoded
path triggers path re-encoding. The standalone `deserialize_url`/`serialize_url` helpers
expose the raw escaped path; `UrlRule` provides the decoded path to its rules. Redacted
URLs are for telemetry, not request replay.

Invalid brackets, ports, escapes, UTF-8 in decoded components, controls/whitespace,
missing HTTP hosts, or excessive query fields replace the whole URL. This parser is not
a URL security validator: relative references and non-HTTP schemes can parse
successfully. Other processing failures abort the call atomically. Ordinary SCRUB
outside URL rules does not decode URLs.

## SDK adapters

Install `sentry-sdk` or `structlog` separately. The integration tests use actual
`sentry-sdk 2.73.0` and `structlog 26.1.0`, local transport/sinks, and synthetic data.

```python
import sentry_sdk
from redactyl import (
    sentry_before_send_redactor,
    sentry_before_send_log_redactor,
    sentry_breadcrumb_redactor,
)

sentry_sdk.init(
    before_send=sentry_before_send_redactor([]),
    before_breadcrumb=sentry_breadcrumb_redactor([]),
    before_send_transaction=sentry_before_send_redactor([]),
    before_send_log=sentry_before_send_log_redactor([]),
)
```

| Channel              | Hook and failure behavior                                                                                                                                                                          |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Error/message events | `before_send`: return sanitized event; `None` on failure.                                                                                                                                          |
| Breadcrumbs          | `before_breadcrumb`: return sanitized breadcrumb; `None` drops it. Event hook also handles serialized `breadcrumbs.values`.                                                                        |
| Transactions/spans   | Configure `before_send_transaction` separately; `None` drops the transaction.                                                                                                                      |
| Sentry logs          | Configure `before_send_log` separately; `None` drops the log. The SDK hook uses plain attribute values, not transport-level typed envelopes.                                                       |
| Attachments          | **Not redacted by these hooks.** Successful events can still emit raw attachment bytes, filenames, and metadata. Omit or sanitize independently. Tests verify this bypass and event-drop behavior. |
| Other SDK telemetry  | Profiles, sessions, metrics, replays, and other envelope items are not covered.                                                                                                                    |

Sentry presets redact sensitive key tokens and email/IP fields, scrub selected
message/request/context/stack strings, and drop frame locals while retaining useful
exception types and stack structure. Unknown stack text, filenames, identifiers, and
names are not guaranteed safe. The breadcrumb adapter normalizes SDK timestamps; the
core handles string enums without SDK-specific conversion. Arbitrary non-JSON objects
still cause a drop. Hints are not emitted payloads and are not modified or mined for
secrets. No store is implicitly shared between SDK hooks.

`structlog_redactor(rules)` returns a real `(logger, method_name, event_dict)`
processor, returning the sanitized dict or raising `structlog.DropEvent` on failure.
Place it **after** exception/object normalization (for example, `format_exc_info`) and
**before** rendering and every sink. An unnormalized exception object or `exc_info`
tuple causes the log to be dropped. `exc_info=True` remains a boolean, not a formatted
traceback. Other logging paths and processors after redaction can still introduce
sensitive data. Adapter failures suppress the affected payload, not process-control
exceptions such as `KeyboardInterrupt`.

## Limits and HASH

`Options` defaults: `replacement="[REDACTED]"`, `min_length=4`, `max_depth=None`,
`max_items=None`, `max_string_length=None`, `hash_secret=None`, `hash_length=10`,
`base_secrets_store=None`.

Limits are opt-in. Depth/item limits replace oversized structures with
`{"...": "[...]"}` or `["[...]"]`; truncated secrets cannot protect other text. The same
depth limit covers normal traversal, inherited SCRUB, and nested URL processing.
`max_items` also limits query fields. A configured string limit applies to keys, input,
and output; replacement expansion is checked before joining strings or assembling a URL
query. Exceeding it raises without committing partial output.

These are size controls, not execution deadlines or process-memory guarantees. Use
reviewed regex patterns; Python regexes can backtrack excessively. Secret-store matching
costs grow with the retained set. Core redaction copies the payload once for discovery
and once for rendering; it is not streaming. Without a depth limit, deeply nested data
remains subject to Python's recursion limit.

HASH is **pseudonymization, not anonymization or encryption**. It uses HMAC-SHA256 over
UTF-8 text and returns a bracketed, truncated hex digest. The default random 32-byte key
lives with the built redactor; a newly built redactor gets a new key. Supply
`hash_secret` from a secret manager only when stable correlation is intended; protect
it, scope it by purpose, and define rotation/retirement. Rotation breaks correlation.
Reusing a key across datasets permits linkage; key compromise or a query oracle enables
guessing low-entropy inputs. Never use an example key in production. The default 10 hex
characters are only 40 bits: collisions become material around a million distinct
values. Choose a longer digest (1–64 hex digits accepted), and never treat truncated
hashes as unique IDs or access-control tokens.

## Development

```sh
uv sync
uv run pytest
uv run ruff check src tests
uv run basedpyright
```

Behavior changes from earlier alpha versions: order-independent discovery, transactional
nested replacement rather than alias mutation, container SCRUB retaining child rules,
discovery from DROP/replaced containers, and SDK-compatible adapter signatures instead
of one-argument mutators. Use `build_redactor` for the one-argument core API.
