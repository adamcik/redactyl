import re
from collections.abc import Generator
from contextlib import contextmanager
from threading import RLock

from ._text import substitute


class SecretStore:
    """Explicit cross-call retention with optional capacity limits.

    Shared-store redactions serialize discovery and commit. A failed call adds
    nothing. Capacity exhaustion raises instead of silently evicting protection.
    """

    def __init__(
        self, *, max_secrets: int | None = None, max_chars: int | None = None
    ) -> None:
        if any(limit is not None and limit < 1 for limit in (max_secrets, max_chars)):
            raise ValueError("secret-store limits must be positive")
        self._max_secrets = max_secrets
        self._max_chars = max_chars
        self._secrets: set[str] = set()
        self._chars = 0
        self._pattern: re.Pattern[str] | None = None
        self._lock = RLock()

    def add(self, value: str) -> None:
        with self._lock:
            if not value or value in self._secrets:
                return
            if (
                self._max_secrets is not None
                and len(self._secrets) >= self._max_secrets
            ) or (
                self._max_chars is not None
                and self._chars + len(value) > self._max_chars
            ):
                raise ValueError("secret-store capacity exceeded")
            self._secrets.add(value)
            self._chars += len(value)
            self._pattern = None

    def scrub(
        self, value: str, replacement: str, *, max_length: int | None = None
    ) -> str:
        with self._lock:
            if not value or not self._secrets:
                return value
            if self._pattern is None:
                values = sorted(self._secrets, key=lambda item: (-len(item), item))
                self._pattern = re.compile("|".join(map(re.escape, values)))
            # A replacement is literal text, not a regex replacement template.
            return substitute(self._pattern, value, lambda _: replacement, max_length)

    def _snapshot(self) -> "SecretStore":
        with self._lock:
            other = SecretStore(
                max_secrets=self._max_secrets, max_chars=self._max_chars
            )
            other._secrets = self._secrets.copy()
            other._chars = self._chars
            return other

    @contextmanager
    def _transaction(self) -> Generator["SecretStore"]:
        with self._lock:
            working = self._snapshot()
            yield working
            self._secrets = working._secrets  # noqa: SLF001
            self._chars = working._chars  # noqa: SLF001
            self._pattern = None

    def _include(self, other: "SecretStore") -> None:
        for value in other._secrets:  # noqa: SLF001
            self.add(value)
