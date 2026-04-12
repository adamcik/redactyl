from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol

from .options import Options

if TYPE_CHECKING:
    from .secrets import SecretStore

type JsonValue = (
    int | float | str | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
)


class Redactor(Protocol):
    def __call__(
        self,
        payload: dict[str, JsonValue],
        *,
        secrets: "SecretStore | None" = None,
    ) -> None: ...


@dataclass(frozen=True)
class ContinueDecision:
    value: JsonValue
    kind: Literal["continue"] = "continue"


@dataclass(frozen=True)
class StopDecision:
    value: JsonValue
    skip_children: bool = False
    kind: Literal["stop"] = "stop"


@dataclass(frozen=True)
class DropDecision:
    kind: Literal["drop"] = "drop"


type RuleDecision = ContinueDecision | StopDecision | DropDecision
type RuleResult = RuleDecision | None


class Rule(Protocol):
    def __call__(
        self,
        *,
        value: JsonValue,
        path: str,
        key: str | None,
        ctx: "RuleContext",
    ) -> RuleResult: ...


class RuleContext(Protocol):
    options: Options
    secrets: "SecretStoreProtocol"
    hasher: "Hasher"


class Hasher(Protocol):
    def hash(self, value: str) -> str: ...


class SecretStoreProtocol(Protocol):
    def add(self, value: str) -> None: ...
    def scrub(self, value: str, replacement: str) -> str: ...
