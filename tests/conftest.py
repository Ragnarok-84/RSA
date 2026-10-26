import pytest

from rsasig.core.keys import generate_keypair


@pytest.fixture(scope="session")
def key1024():
    return generate_keypair(1024)


@pytest.fixture(scope="session")
def key2048():
    return generate_keypair(2048)


@pytest.fixture(scope="session")
def other_key():
    return generate_keypair(1024)
