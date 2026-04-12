import hashlib
import hmac
import re
import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from functools import lru_cache
from typing import assert_never, cast

from .options import Options
from .secrets import CompositeSecretStore, SecretStore
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
        url_dict = deserialize_url(value)
        _redact_dict(
            cast("dict[str, JsonValue]", url_dict), "", ctx, self.rules, depth=0
        )
        return StopDecision(value=serialize_url(url_dict), skip_children=True)


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


@dataclass(frozen=True)
class _Context(RuleContext):
    options: Options
    secrets: SecretStoreProtocol
    hasher: Hasher


class _HmacHasher:
    def __init__(self, secret: bytes, length: int) -> None:
        self._secret = secret
        self._length = length

    def hash(self, value: str) -> str:
        digest = hmac.new(self._secret, value.encode(), hashlib.sha256).hexdigest()
        return f"[{digest[: self._length]}]"


def build_redactor(
    rules: Iterable[Rule], *, options: Options | None = None
) -> Redactor:
    rule_list = tuple(rules)
    opts = options or Options()
    base_secrets = opts.base_secrets_store or SecretStore()
    hasher = _HmacHasher(opts.hash_secret or secrets.token_bytes(32), opts.hash_length)

    def _redactor(payload: object, *, secrets: SecretStore | None = None) -> None:
        if not isinstance(payload, dict):
            raise TypeError("redactor expects a dict[str, JsonValue]")
        mutable_secrets = secrets or SecretStore()
        composite = CompositeSecretStore(base_secrets, mutable_secrets)
        ctx = _Context(options=opts, secrets=composite, hasher=hasher)
        _redact_dict(cast("dict[str, JsonValue]", payload), "", ctx, rule_list, depth=0)

    return _redactor


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
        decision = _apply_rules(value, child_path, key, ctx, rules)
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
        _recurse_value(payload, key, value, child_path, ctx, rules, depth + 1)


def _recurse_value(
    _parent: dict[str, JsonValue],
    _key: str,
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
    while index < len(payload):
        value = payload[index]
        child_path = f"{path}.{index}"
        decision = _apply_rules(value, child_path, str(index), ctx, rules)
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
        _recurse_list_value(payload, index, value, child_path, ctx, rules, depth + 1)
        index += 1


def _recurse_list_value(
    _parent: list[JsonValue],
    _index: int,
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


def _apply_rules(
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
        return DropDecision()
    if action is Action.SCRUB:
        return StopDecision(value=_scrub_value(value, ctx), skip_children=True)
    if action is Action.HASH:
        if not isinstance(value, str):
            raise TypeError(f"HASH action expects string at {path}")
        replacement = ctx.hasher.hash(value)
        if len(value) >= ctx.options.min_length:
            ctx.secrets.add(value)
        return StopDecision(value=replacement, skip_children=True)
    if action is Action.REDACT:
        if isinstance(value, str) and len(value) >= ctx.options.min_length:
            ctx.secrets.add(value)
        return StopDecision(value=ctx.options.replacement, skip_children=True)
    if action is Action.URL:
        if not isinstance(value, str):
            raise TypeError(f"URL action expects string at {path}")
        url_dict = deserialize_url(value)
        _redact_dict(cast("dict[str, JsonValue]", url_dict), "", ctx, (), depth=0)
        return StopDecision(value=serialize_url(url_dict), skip_children=True)
    return None


def _apply_value_action(
    action: Action,
    value: str,
    ctx: RuleContext,
    pattern: re.Pattern[str],
    rules: tuple[Rule, ...],
) -> RuleResult:
    if action is Action.REDACT:
        if len(value) >= ctx.options.min_length:
            ctx.secrets.add(value)
        return StopDecision(
            value=pattern.sub(ctx.options.replacement, value), skip_children=True
        )
    if action is Action.SCRUB:
        return StopDecision(
            value=pattern.sub(
                lambda m: ctx.secrets.scrub(m.group(0), ctx.options.replacement), value
            ),
            skip_children=True,
        )
    if action is Action.HASH:
        return StopDecision(
            value=pattern.sub(lambda m: ctx.hasher.hash(m.group(0)), value),
            skip_children=True,
        )
    if action is Action.URL:
        return StopDecision(
            value=pattern.sub(
                lambda m: _apply_url_to_match(m.group(0), ctx, rules), value
            ),
            skip_children=True,
        )
    if action is Action.DROP:
        return StopDecision(value=pattern.sub("", value), skip_children=True)
    if action is Action.SAFE:
        return StopDecision(value=value, skip_children=True)
    return None


def _apply_url_to_match(value: str, ctx: RuleContext, rules: tuple[Rule, ...]) -> str:
    url_dict = deserialize_url(value)
    _redact_dict(cast("dict[str, JsonValue]", url_dict), "", ctx, rules, depth=0)
    return serialize_url(url_dict)


def _scrub_value(value: JsonValue, ctx: RuleContext) -> JsonValue:
    if isinstance(value, str):
        return ctx.secrets.scrub(value, ctx.options.replacement)
    if isinstance(value, dict):
        _scrub_dict(value, ctx)
        return value
    if isinstance(value, list):
        _scrub_list(value, ctx)
        return value
    if not _is_json_leaf(value):
        raise TypeError("unsupported value type for scrub")
    return value


def _scrub_dict(payload: dict[str, JsonValue], ctx: RuleContext) -> None:
    for key, value in payload.items():
        if isinstance(value, str):
            payload[key] = ctx.secrets.scrub(value, ctx.options.replacement)
        elif isinstance(value, dict):
            _scrub_dict(value, ctx)
        elif isinstance(value, list):
            _scrub_list(value, ctx)
        elif not _is_json_leaf(value):
            raise TypeError("unsupported value type for scrub")


def _scrub_list(payload: list[JsonValue], ctx: RuleContext) -> None:
    for index, value in enumerate(payload):
        if isinstance(value, str):
            payload[index] = ctx.secrets.scrub(value, ctx.options.replacement)
        elif isinstance(value, dict):
            _scrub_dict(value, ctx)
        elif isinstance(value, list):
            _scrub_list(value, ctx)
        elif not _is_json_leaf(value):
            raise TypeError("unsupported value type for scrub")


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


@lru_cache(maxsize=2048)
def _tokenize_key(key: str) -> tuple[str, ...]:
    key = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    return tuple(token.lower() for token in re.findall(r"[A-Za-z0-9]+", key))


def _key_matches_tokens(key: str, tokens: frozenset[str]) -> bool:
    return any(token in tokens for token in _tokenize_key(key))
