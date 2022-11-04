import pytest

from nats_tools.auth import Operator
from nats_tools.natsd import NATSD
from nats_tools.nkeys import create_keypair


def test_fixture(nats_server: NATSD) -> None:
    """An NATS server is started before running this test and stopped after running this test"""
    assert isinstance(nats_server, NATSD)


@pytest.mark.parametrize("nats_server", [{"address": "0.0.0.0"}], indirect=True)
def test_parametrize_fixture(nats_server: NATSD) -> None:
    """A configured NATS server is started before running this test and stopped after running this test"""
    assert isinstance(nats_server, NATSD)


def test_operator_fixture(nats_operator: Operator) -> None:
    """An NATS Operator is generated for the test"""
    assert isinstance(nats_operator, Operator)
    kp = create_keypair("account")
    account_jwt = nats_operator.sign_account("test", kp.public_key)
    account = nats_operator.verify_account(
        account_jwt, subject=kp.public_key.decode("utf-8")
    )
    assert account.name == "test"
