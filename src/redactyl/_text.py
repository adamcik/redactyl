import re
from collections.abc import Callable


def substitute(
    pattern: re.Pattern[str],
    value: str,
    replace: Callable[[re.Match[str]], str],
    max_length: int | None,
) -> str:
    """Bound replacement growth before joining, including zero-length matches."""
    if max_length is None:
        return pattern.sub(replace, value)
    pieces: list[str] = []
    end = 0
    size = 0
    for match in pattern.finditer(value):
        replacement = replace(match)
        size += match.start() - end + len(replacement)
        if size > max_length:
            raise ValueError("redacted string limit exceeded")
        pieces.extend((value[end : match.start()], replacement))
        end = match.end()
    if size + len(value) - end > max_length:
        raise ValueError("redacted string limit exceeded")
    pieces.append(value[end:])
    return "".join(pieces)
