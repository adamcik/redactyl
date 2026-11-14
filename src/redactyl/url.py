import re
import urllib.parse
from typing import TypedDict

from .types import JsonValue


class UrlDict(TypedDict):
    scheme: str
    host: str
    port: int | None
    path: str
    fragment: str
    userinfo: dict[str, JsonValue]
    params: dict[str, JsonValue]


def deserialize_url(value: str, *, max_fields: int | None = None) -> UrlDict:
    if re.search(r"%(?![0-9a-fA-F]{2})|[\x00-\x20\x7f]", value):
        raise ValueError("invalid URL escape or whitespace")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme in {"http", "https"} and not parsed.hostname:
        raise ValueError("HTTP URL requires a host")
    params: dict[str, JsonValue] = {}
    for key, item in urllib.parse.parse_qsl(
        parsed.query,
        keep_blank_values=True,
        max_num_fields=max_fields,
        errors="strict",
    ):
        previous = params.get(key)
        if previous is None:
            params[key] = item
        elif isinstance(previous, list):
            previous.append(item)
        else:
            params[key] = [previous, item]
    userinfo: dict[str, JsonValue] = {}
    if parsed.username or parsed.password:
        if parsed.username is not None:
            userinfo["user"] = urllib.parse.unquote(parsed.username, errors="strict")
        if parsed.password is not None:
            userinfo["password"] = urllib.parse.unquote(
                parsed.password, errors="strict"
            )
    return {
        "scheme": parsed.scheme,
        "host": parsed.hostname or "",
        "port": parsed.port,
        "path": parsed.path,
        "fragment": urllib.parse.unquote(parsed.fragment, errors="strict"),
        "userinfo": userinfo,
        "params": params,
    }


def serialize_url(data: UrlDict, *, max_length: int | None = None) -> str:
    scheme = _as_str(data.get("scheme"))
    host = _as_str(data.get("host"))
    path = _as_str(data.get("path"))
    fragment = urllib.parse.quote(_as_str(data.get("fragment")), safe="[]")
    port = data.get("port")
    userinfo = data.get("userinfo")
    params = data.get("params")

    netloc = host
    if ":" in host:
        netloc = f"[{host}]"
    if userinfo:
        user = urllib.parse.quote(_as_str(userinfo.get("user")), safe="[]")
        password = urllib.parse.quote(_as_str(userinfo.get("password")), safe="[]")
        netloc = f"{user}:{password}@{netloc}" if password else f"{user}@{netloc}"
    if isinstance(port, int):
        netloc = f"{netloc}:{port}"

    size = len(urllib.parse.urlunsplit((scheme, netloc, path, "", fragment)))
    if max_length is not None and size > max_length:
        raise ValueError("serialized URL limit exceeded")
    query_parts: list[str] = []
    for key, value in (params or {}).items():
        for item in value if isinstance(value, list) else [value]:
            part = urllib.parse.urlencode([(key, _as_str(item))])
            size += len(part) + 1
            if max_length is not None and size > max_length:
                raise ValueError("serialized URL limit exceeded")
            query_parts.append(part)
    result = urllib.parse.urlunsplit(
        (scheme, netloc, path, "&".join(query_parts), fragment)
    )
    if max_length is not None and len(result) > max_length:
        raise ValueError("serialized URL limit exceeded")
    return result


def _as_str(value: JsonValue) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""
