import redactyl


def test_public_version_attribute_is_exposed():
    assert hasattr(redactyl, "__version__")
    assert isinstance(redactyl.__version__, str)
    assert redactyl.__version__
