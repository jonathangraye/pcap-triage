import pytest

from pcap_triage import analysis
from pcap_triage.analysis import Analyzer, analyze
from pcap_triage.decoder import DecodeError, Packet

A, B = "192.0.2.1", "198.51.100.1"


def packet(frame, time=0, fields=None, src=A, dst=B):
    return Packet(frame, time, src, dst, fields or {})


def tcp(frame, time=0, fields=None, src=A, dst=B):
    base = {"tcp.stream": "0", "tcp.srcport": "50000", "tcp.dstport": "443"}
    base.update(fields or {})
    return packet(frame, time, base, src, dst)


def ids(report):
    return {finding.rule for finding in report.findings}


def test_clean_report_never_claims_network_is_healthy():
    report = analyze([packet(1)], "synthetic.pcap")
    assert report.summary == "No supported issues detected."
    assert report.schema_version == "1.0"
    assert report.status == "complete"
    assert "Encrypted" in " ".join(report.limitations)


def test_empty_capture_is_explicit():
    report = analyze([], "empty.pcap")
    assert report.packet_count == 0
    assert "no decoded packets" in report.summary
    assert report.duration_seconds == 0


def test_syn_threshold_and_boundary():
    syn = {"tcp.flags.syn": "1"}
    assert "tcp.syn_unanswered" not in ids(analyze([tcp(1, fields=syn)], "x"))
    packets = [tcp(i+1, t, syn) for i, t in enumerate((0, .1, .2))]
    assert "tcp.syn_unanswered" not in ids(analyze(packets, "x"))
    report = analyze(packets + [packet(4, 10)], "x")
    item = report.findings[0]
    assert item.rule == "tcp.syn_unanswered"
    assert item.confidence == "low"
    assert item.count == 3
    assert [e.frame for e in item.evidence] == [1, 2, 3]
    assert item.evidence[1].time_seconds == .1


def test_reverse_traffic_suppresses_unanswered_syn():
    packets = [tcp(i+1, i, {"tcp.flags.syn": "1"}) for i in range(3)]
    packets += [tcp(4, 4, {"tcp.srcport": "443"}, src=B, dst=A), packet(5, 10)]
    assert "tcp.syn_unanswered" not in ids(analyze(packets, "x"))


def test_retransmissions_need_count_and_ratio_and_data():
    retrans = {"tcp.len": "100", "tcp.analysis.retransmission": "1"}
    assert "tcp.retransmissions" not in ids(analyze(
        [tcp(i+1, i, retrans) for i in range(2)], "x",
    ))
    packets = [tcp(i+1, i, retrans) for i in range(3)]
    item = analyze(packets, "x").findings[0]
    assert item.metrics["retransmission_fraction"] == 1
    assert item.confidence == "medium"
    packets += [tcp(i+4, i+3, {"tcp.len": "100"}) for i in range(100)]
    assert "tcp.retransmissions" not in ids(analyze(packets, "x"))
    no_data = {"tcp.len": "0", "tcp.analysis.retransmission": "1"}
    assert "tcp.retransmissions" not in ids(analyze(
        [tcp(i+1, i, no_data) for i in range(3)], "x",
    ))


@pytest.mark.parametrize("field,rule", [
    ("tcp.flags.reset", "tcp.reset"),
    ("tcp.analysis.zero_window", "tcp.zero_window"),
])
def test_explicit_tcp_events(field, rule):
    report = analyze([tcp(1, fields={field: "1"})], "x")
    assert report.findings[0].rule == rule
    assert report.findings[0].confidence == "high"
    assert report.findings[0].next_checks
    assert report.findings[0].alternatives


def dns(frame, time=0, response=False, ident=42, port=53000, code=0):
    return packet(frame, time, {
        "udp.srcport": "53" if response else str(port),
        "udp.dstport": str(port) if response else "53",
        "dns.id": str(ident), "dns.flags.response": str(int(response)),
        "dns.flags.rcode": str(code),
    }, B if response else A, A if response else B)


def test_dns_matching_includes_id_and_ports():
    assert "dns.unanswered" not in ids(analyze(
        [dns(1), dns(2, 1, response=True), packet(3, 10)], "x",
    ))
    assert "dns.unanswered" in ids(analyze(
        [dns(1), dns(2, 1, response=True, port=53001), packet(3, 10)], "x",
    ))
    assert "dns.unanswered" in ids(analyze(
        [dns(1), dns(2, 1, response=True, ident=43), packet(3, 10)], "x",
    ))


def test_dns_boundary_and_error_severity():
    assert "dns.unanswered" not in ids(analyze([dns(1), packet(2, 4.9)], "x"))
    report = analyze([dns(1, response=True, code=3)], "x")
    assert report.findings[0].severity == "info"
    assert report.findings[0].metrics == {"rcode": 3}
    assert analyze([dns(1, response=True, code=2)], "x").findings[0].severity == "warning"


def test_repeated_dns_requests():
    report = analyze([dns(i+1, i) for i in range(3)] + [packet(4, 10)], "x")
    item = report.findings[0]
    assert item.count == 3
    assert item.severity == "warning"
    assert item.confidence == "low"


def dhcp(frame, time=0, msg=1, xid=42):
    return packet(frame, time, {
        "dhcp.option.dhcp": str(msg), "dhcp.id": str(xid),
        "dhcp.hw.mac_addr": "02:00:00:00:00:01",
    })


@pytest.mark.parametrize("progress", [2, 3, 5])
def test_dhcp_offer_request_or_ack_suppresses(progress):
    packets = [dhcp(i+1, i*3) for i in range(3)]
    assert "dhcp.discover_unanswered" in ids(analyze(packets, "x"))
    assert "dhcp.discover_unanswered" not in ids(analyze(
        packets + [dhcp(4, 7, progress)], "x",
    ))
    assert "dhcp.discover_unanswered" in ids(analyze(
        packets + [dhcp(4, 7, progress, xid=43)], "x",
    ))


def test_dhcp_boundary_and_apipa_not_proof_of_failure():
    assert not analyze([dhcp(i+1, i) for i in range(3)], "x").findings
    report = analyze([packet(1, src="169.254.1.2")], "x")
    item = report.findings[0]
    assert item.rule == "ip.apipa"
    assert item.severity == "info"
    assert "intentional" in item.alternatives[0]


def test_tls_visibility_and_capture_boundary():
    hello = tcp(1, fields={"tls.handshake.type": "1"})
    assert not analyze([hello, packet(2, 4)], "x").findings
    assert "tls.no_server_hello" in ids(analyze([hello, packet(2, 10)], "x"))
    reply = tcp(2, 1, {"tls.handshake.type": "2"}, src=B, dst=A)
    assert "tls.no_server_hello" not in ids(analyze([hello, reply, packet(3, 10)], "x"))
    alert = tcp(2, 1, {"tls.alert_message.level": "2", "tls.alert_message.desc": "40"})
    report = analyze([hello, alert, packet(3, 10)], "x")
    assert ids(report) == {"tls.fatal_alert"}
    assert "40" in report.findings[0].observed


def test_tls_aggregated_handshake_types():
    assert "tls.no_server_hello" not in ids(analyze([
        tcp(1, fields={"tls.handshake.type": "1,2,11"}), packet(2, 10),
    ], "x"))


def test_capture_quality_and_out_of_order():
    report = analyze([
        packet(1, 2, {"frame.cap_len": "20", "frame.len": "50", "_ws.malformed": "1"}),
        packet(2, 1),
    ], "x")
    assert ids(report) == {"capture.truncated", "capture.malformed"}
    assert report.duration_seconds == 1
    assert any("not in order" in text for text in report.limitations)


def test_one_direction_capture_warning():
    packets = [tcp(i+1, i, {"tcp.stream": str(i // 4)}) for i in range(12)]
    report = analyze(packets, "x")
    assert any("only one direction" in text for text in report.limitations)


def test_samples_and_tracking_are_bounded(monkeypatch):
    monkeypatch.setattr(analysis, "MAX_FLOWS", 2)
    packets = [tcp(i+1, i, {"tcp.stream": str(i), "tcp.flags.reset": "1"}) for i in range(5)]
    report = analyze(packets, "x")
    assert report.status == "incomplete"
    assert len(report.findings) == 2
    assert any("TCP flow tracking" in s for s in report.limitations)
    report = analyze([tcp(i+1, i, {"tcp.flags.reset": "1"}) for i in range(20)], "x")
    assert report.findings[0].count == 20
    assert len(report.findings[0].evidence) == 5


def test_packet_and_report_limits(monkeypatch):
    monkeypatch.setattr(analysis, "MAX_PACKETS", 3)
    report = analyze([packet(i+1) for i in range(5)], "x")
    assert report.packet_count == 3
    assert report.status == "incomplete"
    monkeypatch.setattr(analysis, "MAX_FINDINGS", 1)
    report = analyze([tcp(1, fields={
        "tcp.flags.reset": "1", "tcp.analysis.zero_window": "1",
    })], "x")
    assert len(report.findings) == 1
    assert any("additional findings were omitted" in text for text in report.limitations)


def test_decode_failure_preserves_partial_evidence():
    def packets():
        yield tcp(1, fields={"tcp.flags.reset": "1"})
        raise DecodeError("Decoder failed.")
    report = analyze(packets(), "x")
    assert report.status == "incomplete"
    assert report.packet_count == 1
    assert ids(report) == {"tcp.reset"}
    assert "Analysis incomplete" in report.summary


def test_report_order_is_deterministic():
    a = Analyzer()
    for i in (2, 1):
        a.consume(tcp(i, i, {"tcp.stream": str(i), "tcp.flags.reset": "1"}, src=f"192.0.2.{i}"))
    report = a.report("x")
    assert report.findings[0].endpoints[0].startswith("192.0.2.1:")
    assert report.to_dict() == a.report("x").to_dict()
