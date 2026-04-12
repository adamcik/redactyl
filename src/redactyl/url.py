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


def deserialize_url(value: str) -> UrlDict:
    parsed = urllib.parse.urlsplit(value)
    params: dict[str, JsonValue] = {
        key: val
        for key, val in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    }
    userinfo: dict[str, JsonValue] = {}
    if parsed.username or parsed.password:
        if parsed.username is not None:
            userinfo["user"] = parsed.username
        if parsed.password is not None:
            userinfo["password"] = parsed.password
    return {
        "scheme": parsed.scheme,
        "host": parsed.hostname or "",
        "port": parsed.port,
        "path": parsed.path,
        "fragment": parsed.fragment,
        "userinfo": userinfo,
        "params": params,
    }


def serialize_url(data: UrlDict) -> str:
    scheme = _as_str(data.get("scheme"))
    host = _as_str(data.get("host"))
    path = _as_str(data.get("path"))
    fragment = _as_str(data.get("fragment"))
    port = data.get("port")
    userinfo = data.get("userinfo")
    params = data.get("params")

    netloc = host
    if userinfo:
        user = _as_str(userinfo.get("user"))
        password = _as_str(userinfo.get("password"))
        if password:
            netloc = f"{user}:{password}@{netloc}"
        else:
            netloc = f"{user}@{netloc}"
    if isinstance(port, int):
        netloc = f"{netloc}:{port}"

    query = urllib.parse.urlencode(
        {_as_str(key): _as_str(value) for key, value in params.items()}
    )

    return urllib.parse.urlunsplit((scheme, netloc, path, query, fragment))


def _as_str(value: JsonValue) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""
