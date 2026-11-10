# Core redaction compatibility

Redaction discovers secrets before rendering a private copy. A sensitive value later in
a payload can therefore protect earlier text selected for `SCRUB`. Container `SCRUB`
still evaluates child rules; it does not hide sensitive fields from discovery.

## Update callers

- Treat success as replacing nested objects. The root dictionary stays the same, but
  aliases to the old nested data remain unsanitized. Emit the updated root, not an
  alias.
- On an exception, discard the payload. Failure leaves the original payload and an
  explicit secret store unchanged; that original is not safe to emit.
- Normalize exceptions, tuples, bytes, datetimes, and custom objects to plain JSON-like
  data first. The core rejects unsupported objects instead of calling `str` or `repr`.
- Make custom rules deterministic and free of external side effects. Rules run twice:
  once for discovery and once for rendering. External side effects cannot be rolled
  back.
- Pass `secrets=SecretStore()` explicitly to retain discoveries across calls. Base-store
  seeds are snapshotted when the redactor is built; they are not an implicit shared
  store.
- Configure limits when needed: depth, item, string, and store-capacity limits are
  opt-in. Truncated or `SAFE` subtrees cannot contribute secrets to other text.

`REDACT`, `DROP`, and `HASH` register eligible strings. Replaced or dropped containers
contribute bounded descendant string values; regex actions register whole matches. Only
strings selected for scrubbing are scrubbed. Keys, numbers, short strings, unknown PII,
and text behind a `SAFE` boundary are not automatically protected.

## URL compatibility

Repeated query names retain their values as lists. Use `params.token.*` for actions on
individual repeated values. Unchanged paths retain their original escaping; changing a
decoded path re-encodes it. Query ordering and escaping are not preserved. Sanitized
URLs are telemetry, not URLs to replay as requests.

SDK callback migration is a separate change; these core guarantees do not establish that
an SDK hook returns the value its SDK expects.
