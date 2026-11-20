"""External legacy smoke is explicitly opt-in; the default test run is offline."""
import os
import pytest


def pytest_collection_modifyitems(items):
    if os.getenv('RUN_LEGACY_LIVE_AUTH_TESTS') == '1':
        return
    for item in items:
        if item.path.name == 'test_nsj_flask_auth.py':
            item.add_marker(pytest.mark.skip(reason='Legacy live SSO smoke requires RUN_LEGACY_LIVE_AUTH_TESTS=1'))
