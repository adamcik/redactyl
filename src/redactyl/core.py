import hashlib
import hmac
import re
import secrets
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import assert_never, cast

from ._text import substitute
from .options import Options
from .secrets import SecretStore
from .types import (
    ContinueDecision,
    DropDecision,
    Hasher,
    JsonValue,
    Redactor,
    Rule,
    RuleContext,
    RuleResult,
    SecretStoreProtocol,
    StopDecision,
)
from .url import deserialize_url, serialize_url


class Action(StrEnum):
    REDACT = "redact"
    SCRUB = "scrub"
    DROP = "drop"
    URL = "url"
    SAFE = "safe"
    HASH = "hash"


@dataclass(frozen=True)
class PathRule:
    path: str
    action: Action
    _segments: tuple[str, ...] = field(init=False, default=())

    def __post_init__(self) -> None:
        object.__setattr__(self, "_segments", tuple(self.path.split(".")))

    def __call__(
        self,
        *,
        value: JsonValue,
        path: str,
        key: str | None,
        ctx: RuleContext,
    ) -> RuleResult:
        if not _path_matches(self._segments, path):
            return None
        return _apply_action(self.action, value, path, key, ctx)


@dataclass(frozen=True)
class RegexPathRule:
    pattern: re.Pattern[str] | str
    action: Action

    def __post_init__(self) -> None:
        if isinstance(self.pattern, str):
            object.__setattr__(self, "pattern", re.compile(self.pattern))

    def __call__(
        self,
        *,
        value: JsonValue,
        path: str,
        key: str | None,
        ctx: RuleContext,
    ) -> RuleResult:
        pattern = self.pattern
        if isinstance(pattern, str):
            raise TypeError("pattern must be compiled in __post_init__")
        if not pattern.search(path):
            return None
        return _apply_action(self.action, value, path, key, ctx)


@dataclass(frozen=True)
class SubstringRule:
    tokens: frozenset[str]
    action: Action

    def __call__(
        self,
        *,
        value: JsonValue,
        path: str,
        key: str | None,
        ctx: RuleContext,
    ) -> RuleResult:
        if key is None:
            return None
        if not _key_matches_tokens(key, self.tokens):
            return None
        return _apply_action(self.action, value, path, key, ctx)


@dataclass(frozen=True)
class UrlRule:
    path: str
    rules: tuple[Rule, ...]
    _segments: tuple[str, ...] = field(init=False, default=())

    def __post_init__(self) -> None:
        object.__setattr__(self, "_segments", tuple(self.path.split(".")))

    def __call__(
        self,
        *,
        value: JsonValue,
        path: str,
        key: str | None,  # noqa: ARG002
        ctx: RuleContext,
    ) -> RuleResult:
        if not _path_matches(self._segments, path):
            return None
        if not isinstance(value, str):
            raise TypeError("URL rule expects a string value")
        return StopDecision(
            value=_apply_url_to_match(value, ctx, self.rules), skip_children=True
        )


@dataclass(frozen=True)
class RegexValueRule:
    pattern: re.Pattern[str] | str
    action: Action
    rules: tuple[Rule, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.pattern, str):
            object.__setattr__(self, "pattern", re.compile(self.pattern))

    def __call__(
        self,
        *,
        value: JsonValue,
        path: str,  # noqa: ARG002
        key: str | None,  # noqa: ARG002
        ctx: RuleContext,
    ) -> RuleResult:
        if not isinstance(value, str):
            return None
        pattern = self.pattern
        if isinstance(pattern, str):
            raise TypeError("pattern must be compiled in __post_init__")
        if not pattern.search(value):
            return None
        return _apply_value_action(self.action, value, ctx, pattern, self.rules)


@dataclass
class _Context(RuleContext):
    options: Options
    secrets: SecretStoreProtocol
    hasher: Hasher
    scrub_paths: set[str] = field(default_factory=set)
    depth: int = 0


class _HmacHasher:
    def __init__(self, secret: bytes, length: int) -> None:
        self._secret = secret
        self._length = length

    def hash(self, value: str) -> str:
        digest = hmac.new(self._secret, value.encode(), hashlib.sha256).hexdigest()
        return f"[{digest[: self._length]}]"


@dataclass(frozen=True)
class _CallSecrets:
    store: SecretStore
    max_length: int | None
    discovering: bool

    def add(self, value: str) -> None:
        self.store.add(value)

    def scrub(self, value: str, replacement: str) -> str:
        if self.discovering:
            return value
        return self.store.scrub(value, replacement, max_length=self.max_length)


def build_redactor(
    rules: Iterable[Rule], *, options: Options | None = None
) -> Redactor:
    """Build an atomic dict mutator with payload-local secret discovery.

    Rules run on private copies twice: discovery (SCRUB is inert), then rendering.
    Custom rules must be deterministic and free of external side effects. Only
    explicit SecretStore arguments retain newly discovered strings across calls.
    Successful calls replace nested objects; external aliases are not sanitized.
    """
    rule_list = tuple(rules)
    opts = options or Options()
    base_secrets = (opts.base_secrets_store or SecretStore())._snapshot()  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    hasher = _HmacHasher(opts.hash_secret or secrets.token_bytes(32), opts.hash_length)

    def _redactor(payload: object, *, secrets: SecretStore | None = None) -> None:
        if type(payload) is not dict:
            raise TypeError("redactor expects a dict[str, JsonValue]")
        target = cast("dict[str, JsonValue]", payload)
        mutable_secrets = secrets if secrets is not None else SecretStore()
        with mutable_secrets._transaction() as working:  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            working._include(base_secrets)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            for discovering in (True, False):
                result = cast(
                    "dict[str, JsonValue]", _prepare_payload(target, opts, set())
                )
                call_secrets = _CallSecrets(
                    working, opts.max_string_length, discovering
                )
                ctx = _Context(opts, call_secrets, hasher)
                _redact_dict(result, "", ctx, rule_list, depth=0)
            # Validate custom-rule output without copying the whole result again.
            _prepare_payload(result, opts, set(), copy_containers=False)
            target.clear()
            target.update(result)

    return _redactor


def _prepare_payload(
    value: object,
    opts: Options,
    ancestors: set[int],
    depth: int = 0,
    *,
    copy_containers: bool = True,
) -> JsonValue:
    """Normalize primitives and validate plain containers without object copy hooks."""
    if value is None or isinstance(value, (str, int, float)):
        return _normalize_primitive(value, opts.max_string_length)
    if type(value) not in (dict, list):
        raise TypeError("unsupported payload value type")
    if id(value) in ancestors:
        raise ValueError("cyclic payload")
    container = cast("dict[object, object] | list[object]", value)
    if (opts.max_depth is not None and depth >= opts.max_depth) or (
        opts.max_items is not None and len(container) > opts.max_items
    ):
        return {"...": "[...]"} if type(value) is dict else ["[...]"]
    ancestors.add(id(value))
    try:
        if isinstance(container, dict):
            result = {} if copy_containers else cast("dict[str, JsonValue]", container)
            for key, child in container.items():
                if not isinstance(key, str):
                    raise TypeError("payload keys must be strings")
                normal_key = str.__str__(key)
                if (
                    opts.max_string_length is not None
                    and len(normal_key) > opts.max_string_length
                ):
                    raise ValueError("payload key limit exceeded")
                result[normal_key] = _prepare_payload(
                    child, opts, ancestors, depth + 1, copy_containers=copy_containers
                )
            return result
        items = [] if copy_containers else cast("list[JsonValue]", container)
        for index, child in enumerate(container):
            prepared = _prepare_payload(
                child, opts, ancestors, depth + 1, copy_containers=copy_containers
            )
            if copy_containers:
                items.append(prepared)
            else:
                items[index] = prepared
        return items
    finally:
        ancestors.remove(id(value))


def _normalize_primitive(
    value: str | float | None, max_length: int | None
) -> str | int | float | None:
    """Strip primitive subclasses without calling user-defined conversion hooks."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        value = str.__str__(value)
        if max_length is not None and len(value) > max_length:
            raise ValueError("payload string limit exceeded")
        return value
    if isinstance(value, int):
        return int.__int__(value)
    return float.__float__(value)


def _redact_dict(
    payload: dict[str, JsonValue],
    path: str,
    ctx: RuleContext,
    rules: tuple[Rule, ...],
    depth: int,
) -> None:
    if ctx.options.max_depth is not None and depth >= ctx.options.max_depth:
        payload.clear()
        payload["..."] = "[...]"
        return
    if ctx.options.max_items is not None and len(payload) > ctx.options.max_items:
        payload.clear()
        payload["..."] = "[...]"
        return

    for key in list(payload.keys()):
        value = payload[key]
        child_path = key if not path else f"{path}.{key}"
        decision = _apply_rules(value, child_path, key, ctx, rules, depth + 1)
        match decision:
            case None:
                pass
            case DropDecision():
                payload.pop(key, None)
                continue
            case ContinueDecision(value=new_value):
                payload[key] = new_value
                value = new_value
            case StopDecision(value=new_value, skip_children=skip_children):
                payload[key] = new_value
                value = new_value
                if skip_children:
                    continue
            case _:
                assert_never(decision)
        _recurse_value(value, child_path, ctx, rules, depth + 1)


def _recurse_value(
    value: JsonValue,
    path: str,
    ctx: RuleContext,
    rules: tuple[Rule, ...],
    depth: int,
) -> None:
    if isinstance(value, dict):
        _redact_dict(value, path, ctx, rules, depth)
        return
    if isinstance(value, list):
        _redact_list(value, path, ctx, rules, depth)
        return
    if not _is_json_leaf(value):
        raise TypeError(f"unsupported value type at {path}")


def _redact_list(
    payload: list[JsonValue],
    path: str,
    ctx: RuleContext,
    rules: tuple[Rule, ...],
    depth: int,
) -> None:
    if ctx.options.max_depth is not None and depth >= ctx.options.max_depth:
        payload[:] = ["[...]"]
        return
    if ctx.options.max_items is not None and len(payload) > ctx.options.max_items:
        payload[:] = ["[...]"]
        return

    index = 0
    original_index = 0
    while index < len(payload):
        value = payload[index]
        child_path = f"{path}.{original_index}"
        decision = _apply_rules(
            value, child_path, str(original_index), ctx, rules, depth + 1
        )
        original_index += 1
        match decision:
            case None:
                pass
            case DropDecision():
                payload.pop(index)
                continue
            case ContinueDecision(value=new_value):
                payload[index] = new_value
                value = new_value
            case StopDecision(value=new_value, skip_children=skip_children):
                payload[index] = new_value
                value = new_value
                if skip_children:
                    index += 1
                    continue
            case _:
                assert_never(decision)
        _recurse_value(value, child_path, ctx, rules, depth + 1)
        index += 1


def _apply_rules(
    value: JsonValue,
    path: str,
    key: str | None,
    ctx: RuleContext,
    rules: tuple[Rule, ...],
    depth: int,
) -> RuleResult:
    if isinstance(ctx, _Context):
        ctx.depth = depth
    decision = _decide_rules(value, path, key, ctx, rules)
    if isinstance(decision, (DropDecision, StopDecision)):
        return decision
    current = decision.value if isinstance(decision, ContinueDecision) else value
    if (
        isinstance(current, str)
        and isinstance(ctx, _Context)
        and any(path.startswith(f"{parent}.") for parent in ctx.scrub_paths)
    ):
        return ContinueDecision(ctx.secrets.scrub(current, ctx.options.replacement))
    return decision


def _decide_rules(
    value: JsonValue,
    path: str,
    key: str | None,
    ctx: RuleContext,
    rules: tuple[Rule, ...],
) -> RuleResult:
    current_value = value
    matched = False
    for rule in rules:
        decision = rule(value=current_value, path=path, key=key, ctx=ctx)
        match decision:
            case None:
                continue
            case ContinueDecision(value=new_value):
                matched = True
                current_value = new_value
                continue
            case StopDecision(value=stop_value, skip_children=skip_children):
                matched = True
                return StopDecision(value=stop_value, skip_children=skip_children)
            case DropDecision():
                matched = True
                return decision
            case _:
                assert_never(decision)
    if matched:
        return ContinueDecision(value=current_value)
    return None


def _apply_action(
    action: Action,
    value: JsonValue,
    path: str,
    _key: str | None,
    ctx: RuleContext,
) -> RuleResult:
    if action is Action.SAFE:
        return StopDecision(value=value, skip_children=True)
    if action is Action.DROP:
        _register_value(value, ctx)
        return DropDecision()
    if action is Action.SCRUB:
        if isinstance(value, (dict, list)):
            if isinstance(ctx, _Context):
                ctx.scrub_paths.add(path)
            return StopDecision(value=value, skip_children=False)
        return StopDecision(value=_scrub_value(value, ctx), skip_children=True)
    if action is Action.HASH:
        if not isinstance(value, str):
            raise TypeError(f"HASH action expects string at {path}")
        replacement = ctx.hasher.hash(value)
        if len(value) >= ctx.options.min_length:
            ctx.secrets.add(value)
        return StopDecision(value=replacement, skip_children=True)
    if action is Action.REDACT:
        _register_value(value, ctx)
        return StopDecision(value=ctx.options.replacement, skip_children=True)
    if action is Action.URL:
        if not isinstance(value, str):
            raise TypeError(f"URL action expects string at {path}")
        return StopDecision(
            value=_apply_url_to_match(value, ctx, _DEFAULT_URL_RULES),
            skip_children=True,
        )
    return None


def _apply_value_action(
    action: Action,
    value: str,
    ctx: RuleContext,
    pattern: re.Pattern[str],
    rules: tuple[Rule, ...],
) -> RuleResult:
    if action is Action.SAFE:
        return StopDecision(value=value, skip_children=True)

    def replace(match: re.Match[str]) -> str:
        matched = match.group(0)
        if action in (Action.REDACT, Action.HASH, Action.DROP):
            _register_value(matched, ctx)
        if action is Action.REDACT:
            return ctx.options.replacement
        if action is Action.HASH:
            return ctx.hasher.hash(matched)
        if action is Action.DROP:
            return ""
        if action is Action.URL:
            return _apply_url_to_match(matched, ctx, rules)
        return ctx.secrets.scrub(matched, ctx.options.replacement)

    return StopDecision(
        value=substitute(pattern, value, replace, ctx.options.max_string_length),
        skip_children=True,
    )


def _apply_url_to_match(value: str, ctx: RuleContext, rules: tuple[Rule, ...]) -> str:
    try:
        url_dict = deserialize_url(value, max_fields=ctx.options.max_items)
        original_path = url_dict["path"]
        decoded_path = urllib.parse.unquote(original_path, errors="strict")
    except ValueError:
        _register_value(value, ctx)
        return ctx.options.replacement
    url_dict["path"] = decoded_path
    url_ctx = _Context(
        ctx.options,
        ctx.secrets,
        ctx.hasher,
    )
    _redact_dict(
        cast("dict[str, JsonValue]", url_dict),
        "",
        url_ctx,
        rules,
        depth=ctx.depth if isinstance(ctx, _Context) else 0,
    )
    if "..." in url_dict:
        return ctx.options.replacement
    # Only an explicit path transformation should change routing-relevant escaping.
    if url_dict.get("path") == decoded_path:
        url_dict["path"] = original_path
    elif "path" in url_dict:
        url_dict["path"] = urllib.parse.quote(
            url_dict["path"], safe="/[]:@!$&'()*+,;=-._~"
        )
    return serialize_url(url_dict, max_length=ctx.options.max_string_length)


def _scrub_value(value: JsonValue, ctx: RuleContext) -> JsonValue:
    if isinstance(value, str):
        return ctx.secrets.scrub(value, ctx.options.replacement)
    if not _is_json_leaf(value):
        raise TypeError("unsupported value type for scrub")
    return value


def _register_value(value: JsonValue, ctx: RuleContext) -> None:
    if isinstance(value, str):
        if len(value) >= ctx.options.min_length:
            ctx.secrets.add(value)
    elif isinstance(value, dict):
        for child in value.values():
            _register_value(child, ctx)
    elif isinstance(value, list):
        for child in value:
            _register_value(child, ctx)


def _is_json_leaf(value: JsonValue) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _path_matches(segments: tuple[str, ...], path: str) -> bool:
    path_segments = tuple(path.split("."))
    if len(path_segments) != len(segments):
        return False
    for pattern, actual in zip(segments, path_segments, strict=False):
        if pattern not in {"*", actual}:
            return False
    return True


def _tokenize_key(key: str) -> tuple[str, ...]:
    key = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    return tuple(token.lower() for token in re.findall(r"[A-Za-z0-9]+", key))


def _key_matches_tokens(key: str, tokens: frozenset[str]) -> bool:
    return any(token in tokens for token in _tokenize_key(key))


_DEFAULT_URL_RULES: tuple[Rule, ...] = (
    PathRule("userinfo.*", Action.REDACT),
    PathRule("fragment", Action.REDACT),
    PathRule("params.*", Action.REDACT),
)
