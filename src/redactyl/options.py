from dataclasses import dataclass

from .secrets import SecretStore


@dataclass(frozen=True)
class Options:
    replacement: str = "[REDACTED]"
    min_length: int = 4
    max_depth: int | None = None
    max_items: int | None = None
    hash_secret: bytes | None = None
    hash_length: int = 10
    base_secrets_store: SecretStore | None = None
