import json
import subprocess
import sys

import pytest

from pcap_triage.analysis import analyze
from pcap_triage.decoder import decode, open_capture
from tests.captures import (
    GLOBAL_HEADER,
    corrupt_capture,
    scenario,
    truncated_capture,
    write_capture,
)

pytestmark = pytest.mark.integration


def run(path, tshark):
    with open_capture(path) as handle:
        return analyze(decode(handle, tshark), path.name)


@pytest.mark.parametrize("pcapng", [False, True], ids=["pcap", "pcapng"])
@pytest.mark.parametrize("name,expected", [
    ("healthy", None), ("syn", "tcp.syn_unanswered"), ("reset", "tcp.reset"),
    ("retransmissions", "tcp.retransmissions"), ("zero_window", "tcp.zero_window"),
    ("dns_unanswered", "dns.unanswered"), ("dns_error", "dns.error_response"),
    ("tls_incomplete", "tls.no_server_hello"), ("tls_healthy", None),
    ("tls_fatal", "tls.fatal_alert"), ("dhcp", "dhcp.discover_unanswered"),
    ("dhcp_healthy", None), ("apipa", "ip.apipa"), ("malformed", "capture.malformed"),
])
def test_real_protocol_cases(tmp_path, tshark, pcapng, name, expected):
    packets = scenario(name)
    path = write_capture(tmp_path / ("case.pcapng" if pcapng else "case.pcap"), packets, pcapng)
    report = run(path, tshark)
    assert report.status == "complete", report.limitations
    assert report.packet_count == len(packets)
    rules = {item.rule for item in report.findings}
    if expected:
        assert expected in rules, report.to_dict()
        item = next(item for item in report.findings if item.rule == expected)
        assert item.evidence
        assert all(1 <= e.frame <= len(packets) for e in item.evidence)
    else:
        assert not rules, report.to_dict()


def test_empty_header_only_capture(tmp_path, tshark):
    path = tmp_path / "empty.pcap"
    path.write_bytes(GLOBAL_HEADER)
    report = run(path, tshark)
    assert report.packet_count == 0
    assert report.status == "complete"


def test_truncated_capture(tmp_path, tshark):
    report = run(truncated_capture(tmp_path / "truncated.pcap"), tshark)
    assert "capture.truncated" in {item.rule for item in report.findings}


def test_corrupt_file_is_incomplete_not_clean(tmp_path, tshark):
    report = run(corrupt_capture(tmp_path / "broken.pcap"), tshark)
    assert report.status == "incomplete"
    assert report.packet_count >= 1
    assert "Analysis incomplete" in report.summary


def test_actual_entrypoint_and_report_formats(tmp_path, tshark):
    path = write_capture(tmp_path / "-hostile ; filename.pcap", scenario("dhcp"))
    json_run = subprocess.run(
        [sys.executable, "-m", "pcap_triage", "--format", "json", "--", str(path)],
        capture_output=True, text=True, timeout=15,
    )
    assert json_run.returncode == 0, json_run.stderr
    data = json.loads(json_run.stdout)
    assert data["findings"][0]["rule"] == "dhcp.discover_unanswered"
    for format_name in ("markdown", "terminal"):
        result = subprocess.run(
            [sys.executable, "-m", "pcap_triage", str(path), "--format", format_name],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, result.stderr
        assert data["findings"][0]["title"] in result.stdout
        assert "Next checks:" in result.stdout


def test_payloads_and_credentials_never_enter_report(tmp_path, tshark):
    from scapy.packet import Raw

    from tests.captures import clock, handshake, tcp

    marker = "SYNTHETIC_SENSITIVE_MARKER"
    payload = (
        f"GET /?token={marker} HTTP/1.1\r\nHost: synthetic.example\r\n"
        f"Authorization: Bearer {marker}\r\nCookie: secret={marker}\r\n\r\n"
    ).encode()
    packets = handshake() + [tcp(.1, "PA", payload=Raw(payload)), clock()]
    path = write_capture(tmp_path / "sensitive.pcap", packets)
    report = run(path, tshark)
    assert marker not in json.dumps(report.to_dict())
