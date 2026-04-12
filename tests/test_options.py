from redactyl import Action, Options, PathRule, build_redactor


def test_depth_limit_replaces_subtree():
    options = Options(max_depth=1)
    redactor = build_redactor([PathRule("root.secret", Action.REDACT)], options=options)
    payload = {"root": {"secret": "value"}}

    redactor(payload)

    assert payload["root"]["..."] == "[...]"


def test_max_items_replaces_list():
    options = Options(max_items=2)
    redactor = build_redactor([], options=options)
    payload = {"list": ["a", "b", "c"]}

    redactor(payload)

    assert payload["list"] == ["[...]"]
