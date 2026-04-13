from importlib.metadata import PackageNotFoundError, version

from .core import (
    Action,
    PathRule,
    RegexPathRule,
    RegexValueRule,
    SubstringRule,
    UrlRule,
    build_redactor,
)
from .options import Options
from .presets import (
    sentry_before_send_redactor,
    sentry_breadcrumb_redactor,
    structlog_redactor,
)
from .types import (
    ContinueDecision,
    DropDecision,
    JsonValue,
    Redactor,
    Rule,
    RuleDecision,
    RuleResult,
    StopDecision,
)
from .url import deserialize_url, serialize_url

try:
    __version__ = version("redactyl")
except PackageNotFoundError:
    __version__ = "0+unknown"

__all__ = [
    "Action",
    "ContinueDecision",
    "DropDecision",
    "JsonValue",
    "Options",
    "PathRule",
    "Redactor",
    "RegexPathRule",
    "RegexValueRule",
    "Rule",
    "RuleDecision",
    "RuleResult",
    "StopDecision",
    "SubstringRule",
    "UrlRule",
    "__version__",
    "build_redactor",
    "deserialize_url",
    "sentry_before_send_redactor",
    "sentry_breadcrumb_redactor",
    "serialize_url",
    "structlog_redactor",
]
