from nats_tools.fixtures import parametrize_nats_server
from nats_tools.natsd import NATSD


@parametrize_nats_server(address="0.0.0.0")
def test_parametrize_fixture_with_decorator(nats_server: NATSD) -> None:
    assert isinstance(nats_server, NATSD)
