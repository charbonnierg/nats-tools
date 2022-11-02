import pytest

from nats_tools.natsd import NATSD


def test_fixture(nats_server: NATSD) -> None:
    """An NATS server is started before running this test and stopped after running this test"""
    assert isinstance(nats_server, NATSD)


@pytest.mark.parametrize("nats_server", [{"address": "0.0.0.0"}], indirect=True)
def test_parametrize_fixture(nats_server: NATSD) -> None:
    """A configured NATS server is started before running this test and stopped after running this test"""
    assert isinstance(nats_server, NATSD)
