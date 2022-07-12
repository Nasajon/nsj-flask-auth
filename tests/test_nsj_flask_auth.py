from nsj_flask_auth import __version__, Auth


def test_version():
    assert __version__ == '0.1.0'


def test_class():
    auth = Auth()
    assert auth._cache is None
