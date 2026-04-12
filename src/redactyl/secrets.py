import re


class SecretStore:
    def __init__(self) -> None:
        self._secrets: set[str] = set()
        self._pattern: re.Pattern[str] | None = None

    def add(self, value: str) -> None:
        if not value:
            return
        self._secrets.add(value)
        self._pattern = None

    def scrub(self, value: str, replacement: str) -> str:
        if not value or not self._secrets:
            return value
        pattern = self._get_pattern()
        return pattern.sub(replacement, value)

    def _get_pattern(self) -> re.Pattern[str]:
        if self._pattern is None:
            values = sorted(self._secrets, key=len, reverse=True)
            escaped = (re.escape(value) for value in values if value)
            self._pattern = re.compile("|".join(escaped))
        return self._pattern


class CompositeSecretStore:
    def __init__(self, base: SecretStore, mutable: SecretStore) -> None:
        self._base = base
        self._mutable = mutable

    def add(self, value: str) -> None:
        self._mutable.add(value)

    def scrub(self, value: str, replacement: str) -> str:
        if not value:
            return value
        scrubbed = self._base.scrub(value, replacement)
        return self._mutable.scrub(scrubbed, replacement)
