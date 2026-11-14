import pytest

from pcap_triage.decoder import InputError, find_tshark


@pytest.fixture
def tshark():
    try:
        return find_tshark()
    except InputError:
        pytest.skip("Real tshark is required for integration tests")
