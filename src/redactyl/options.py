from dataclasses import dataclass

from .secrets import SecretStore


@dataclass(frozen=True)
class Options:
    replacement: str = "[REDACTED]"
    min_length: int = 4
    max_depth: int | None = None
    max_items: int | None = None
    max_string_length: int | None = None
    hash_secret: bytes | None = None
    hash_length: int = 10
    base_secrets_store: SecretStore | None = None

    def __post_init__(self) -> None:
        for value in (self.max_depth, self.max_items):
            if value is not None and value < 0:
                raise ValueError("traversal limits must be nonnegative")

        if self.min_length < 1:
            raise ValueError("min_length must be positive")

        if self.max_string_length is not None and self.max_string_length < 1:
            raise ValueError("max_string_length must be positive")

        if not 1 <= self.hash_length <= _SHA256_HEX_LENGTH:
            raise ValueError("hash_length must be between 1 and 64 hex digits")

        if self.hash_secret == b"":
            raise ValueError("hash_secret must not be empty")

        if (
            self.max_string_length is not None
            and len(self.replacement) > self.max_string_length
        ):
            raise ValueError("replacement exceeds string limit")


_SHA256_HEX_LENGTH = 64
