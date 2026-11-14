"""Conservative diagnostic rules over bounded flow summaries."""

from collections.abc import Iterable
from dataclasses import dataclass, field

from .decoder import DecodeError, Packet, first
from .models import Evidence, Finding, Report

# Centralized thresholds. These are heuristics, not universal network SLOs.
SYN_ATTEMPTS = 3
SYN_WAIT_SECONDS = 3.0
DNS_ATTEMPTS = 3
DNS_WAIT_SECONDS = 5.0
TLS_WAIT_SECONDS = 5.0
DHCP_DISCOVERS = 3
DHCP_WAIT_SECONDS = 5.0
RETRANSMIT_MIN = 3
RETRANSMIT_RATIO = 0.05
MAX_EXAMPLES = 5
MAX_FLOWS = 20_000
MAX_DNS_TRANSACTIONS = 20_000
MAX_DHCP_TRANSACTIONS = 4_096
MAX_ADDRESSES = 256
MAX_PACKETS = 1_000_000
MAX_FINDINGS = 200

BASE_LIMITATIONS = [
    "A capture shows one observation point, not necessarily both traffic directions. "
    "Missing replies do not prove a remote service failed.",
    "Encrypted TLS payloads, HTTPS/HTTP errors, encrypted DNS, and most TLS 1.3 alerts "
    "are not visible. No decryption is attempted.",
    "Only TCP, visible DNS/TLS, DHCPv4, IPv4 link-local addresses, and capture quality "
    "have diagnostic rules. A clean report does not prove network health.",
    "Protocol recognition depends on tshark. Unusual ports, tunnels, and unsupported "
    "encapsulations may hide traffic. Packet loss cannot be measured from retransmissions alone.",
    "Reports retain endpoint metadata and frame references; treat them as customer-sensitive.",
]


@dataclass
class Samples:
    count: int = 0
    examples: list[Evidence] = field(default_factory=list)
    first_time: float | None = None
    last_time: float = 0.0

    def add(self, packet: Packet) -> None:
        self.count += 1
        if self.first_time is None:
            self.first_time = packet.time
        self.last_time = packet.time
        if len(self.examples) < MAX_EXAMPLES:
            self.examples.append(Evidence(packet.frame, packet.time))


@dataclass
class Flow:
    endpoints: list[str]
    directions: set[tuple[str, int]] = field(default_factory=set)
    packets: int = 0
    data_packets: int = 0
    syn_sender: tuple[str, int] | None = None
    syn: Samples = field(default_factory=Samples)
    syn_ack: bool = False
    peer_after_syn: bool = False
    resets: Samples = field(default_factory=Samples)
    retransmits: Samples = field(default_factory=Samples)
    zero_windows: Samples = field(default_factory=Samples)
    hello: Samples = field(default_factory=Samples)
    server_hello: bool = False
    fatal: Samples = field(default_factory=Samples)
    alert_codes: set[int] = field(default_factory=set)


@dataclass
class Transaction:
    endpoints: list[str]
    requests: Samples = field(default_factory=Samples)
    progressed: bool = False


def endpoint(ip: str, port: int) -> str:
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def finding(
    rule: str, severity: str, confidence: str, title: str, observed: str, meaning: str,
    endpoints: list[str], samples: Samples, checks: list[str], alternatives: list[str],
    metrics: dict[str, int | float] | None = None,
) -> Finding:
    return Finding(
        rule, severity, confidence, title, observed, meaning, endpoints,
        samples.count, samples.examples.copy(), checks, alternatives, metrics or {},
    )


class Analyzer:
    def __init__(self) -> None:
        self.flows: dict[str, Flow] = {}
        self.dns: dict[tuple, Transaction] = {}
        self.dns_errors: dict[tuple[str, int], Samples] = {}
        self.dhcp: dict[tuple[str, int], Transaction] = {}
        self.link_local: dict[str, Samples] = {}
        self.truncated = Samples()
        self.malformed = Samples()
        self.packet_count = 0
        self.first_time: float | None = None
        self.last_time = 0.0
        self.limits: set[str] = set()
        self.errors: list[str] = []
        self.out_of_order = False
        self.previous_time: float | None = None

    def slot(self, mapping: dict, key: object, maximum: int, label: str) -> bool:
        if key in mapping or len(mapping) < maximum:
            return True
        self.limits.add(label)
        return False

    def consume(self, packet: Packet) -> None:
        self.packet_count += 1
        if self.previous_time is not None and packet.time < self.previous_time:
            self.out_of_order = True
        self.previous_time = packet.time
        self.first_time = (
            packet.time if self.first_time is None else min(self.first_time, packet.time)
        )
        self.last_time = (
            packet.time if self.packet_count == 1 else max(self.last_time, packet.time)
        )
        if packet.n("frame.cap_len") < packet.n("frame.len"):
            self.truncated.add(packet)
        if packet.has("_ws.malformed"):
            self.malformed.add(packet)
        for ip in sorted({packet.src, packet.dst}):
            if ip.startswith("169.254.") and self.slot(
                self.link_local, ip, MAX_ADDRESSES, "link-local address tracking",
            ):
                self.link_local.setdefault(ip, Samples()).add(packet)
        if packet.has("tcp.stream"):
            self.consume_tcp(packet)
        if packet.has("dns.id") and packet.src and packet.dst:
            self.consume_dns(packet)
        if packet.has("dhcp.option.dhcp"):
            self.consume_dhcp(packet)

    def consume_tcp(self, p: Packet) -> None:
        # Without IP endpoints, do not conflate non-IP TCP conversations.
        if not p.src or not p.dst:
            return
        key = first(p.fields["tcp.stream"])
        if not self.slot(self.flows, key, MAX_FLOWS, "TCP flow tracking"):
            return
        flow = self.flows.setdefault(key, Flow([
            endpoint(p.src, p.n("tcp.srcport")), endpoint(p.dst, p.n("tcp.dstport")),
        ]))
        source = (p.src, p.n("tcp.srcport"))
        flow.directions.add(source)
        flow.packets += 1
        if flow.syn_sender and source != flow.syn_sender:
            flow.peer_after_syn = True
        if p.n("tcp.flags.syn") and not p.n("tcp.flags.ack"):
            if flow.syn_sender is None:
                flow.syn_sender = source
            if source == flow.syn_sender:
                flow.syn.add(p)
        if p.n("tcp.flags.syn") and p.n("tcp.flags.ack"):
            flow.syn_ack = True
        if p.n("tcp.flags.reset"):
            flow.resets.add(p)
        if p.n("tcp.len") > 0:
            flow.data_packets += 1
            if any(p.has(name) for name in (
                "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
                "tcp.analysis.spurious_retransmission",
            )):
                flow.retransmits.add(p)
        if p.has("tcp.analysis.zero_window"):
            flow.zero_windows.add(p)
        types = p.values("tls.handshake.type")
        if 1 in types:
            flow.hello.add(p)
        if 2 in types:
            flow.server_hello = True
        if 2 in p.values("tls.alert_message.level"):
            flow.fatal.add(p)
            flow.alert_codes.update(p.values("tls.alert_message.desc"))

    def consume_dns(self, p: Packet) -> None:
        # Match UDP DNS responses to the exact outstanding transaction. TCP uses its stream.
        tcp = first(p.fields.get("tcp.stream", ""))
        source_port = p.n("udp.srcport") or p.n("tcp.srcport")
        dest_port = p.n("udp.dstport") or p.n("tcp.dstport")
        request = (p.src, source_port, p.dst, dest_port, p.n("dns.id"), tcp)
        response = (p.dst, dest_port, p.src, source_port, p.n("dns.id"), tcp)
        if p.n("dns.flags.response"):
            self.dns.pop(response, None)
            code = p.n("dns.flags.rcode")
            error_key = (p.src, code)
            if code and self.slot(
                self.dns_errors, error_key, MAX_DNS_TRANSACTIONS, "DNS error tracking",
            ):
                self.dns_errors.setdefault(error_key, Samples()).add(p)
        elif self.slot(self.dns, request, MAX_DNS_TRANSACTIONS, "DNS transaction tracking"):
            txn = self.dns.setdefault(request, Transaction([
                endpoint(p.src, source_port), endpoint(p.dst, dest_port),
            ]))
            txn.requests.add(p)

    def consume_dhcp(self, p: Packet) -> None:
        mac = first(p.fields.get("dhcp.hw.mac_addr", ""))
        # Limit raw identifiers to valid hardware-address characters.
        if not mac or len(mac) > 47 or any(c not in "0123456789abcdefABCDEF:" for c in mac):
            return
        key = (mac.lower(), p.n("dhcp.id"))
        if not self.slot(self.dhcp, key, MAX_DHCP_TRANSACTIONS, "DHCP transaction tracking"):
            return
        txn = self.dhcp.setdefault(key, Transaction([f"DHCP client {mac.lower()}"]))
        msg = p.n("dhcp.option.dhcp")
        if msg == 1:
            txn.requests.add(p)
        elif msg in (2, 3, 5):
            txn.progressed = True

    def old_enough(self, samples: Samples, seconds: float) -> bool:
        return (
            samples.first_time is not None
            and self.last_time - samples.first_time >= seconds
        )

    def tcp_findings(self) -> list[Finding]:
        result = []
        for flow in self.flows.values():
            ends = flow.endpoints
            if (
                flow.syn.count >= SYN_ATTEMPTS and not flow.peer_after_syn
                and self.old_enough(flow.syn, SYN_WAIT_SECONDS)
            ):
                result.append(finding(
                    "tcp.syn_unanswered", "warning", "low",
                    "Repeated TCP connection attempts have no observed reply",
                    f"{flow.syn.count} SYN packets were sent without reverse traffic in this flow.",
                    "A TCP connection may not be reaching or receiving a reply "
                    "from its destination.",
                    ends, flow.syn,
                    ["Confirm both directions were captured.",
                     "Check the destination listener, routing, firewall rules, and return path.",
                     "Capture at the server or firewall to locate missing SYNs or replies."],
                    ["Replies may be outside the capture or missing from a one-sided capture."],
                ))
            if flow.resets.count:
                establishing = bool(flow.syn.count and not flow.syn_ack)
                result.append(finding(
                    "tcp.reset", "warning" if establishing else "info", "high",
                    "TCP reset observed",
                    f"{flow.resets.count} TCP reset packet(s) were observed.",
                    "A connection attempt was rejected or aborted." if establishing else
                    "An endpoint or intermediary abruptly ended a TCP connection.",
                    ends, flow.resets,
                    ["Use the evidence frames to identify which side sent the reset.",
                     "Check listener, application, load balancer, and firewall logs at that time."],
                    ["Resets can be intentional cleanup, scans, or responses to stale connections; "
                     "a reset alone does not prove an outage."],
                ))
            ratio = flow.retransmits.count / max(flow.data_packets, 1)
            if flow.retransmits.count >= RETRANSMIT_MIN and ratio >= RETRANSMIT_RATIO:
                result.append(finding(
                    "tcp.retransmissions", "warning", "medium",
                    "Repeated TCP data retransmissions",
                    f"tshark marked {flow.retransmits.count} of {flow.data_packets} data-bearing "
                    f"packets ({ratio:.1%}) as retransmissions.",
                    "Delivery or acknowledgment delays may be slowing this connection.",
                    ends, flow.retransmits,
                    ["Compare captures at both endpoints to separate loss from capture artifacts.",
                     "Check interface drops, congestion, latency, and the reverse ACK path."],
                    ["Reordering, duplicate SPAN packets, offload, or missing capture packets can "
                     "trigger retransmission analysis. This percentage is not packet loss."],
                    {"data_packets": flow.data_packets,
                     "retransmission_fraction": round(ratio, 6)},
                ))
            if flow.zero_windows.count:
                result.append(finding(
                    "tcp.zero_window", "warning", "high",
                    "A TCP receiver advertised no receive space",
                    f"{flow.zero_windows.count} zero-window advertisement(s) were observed.",
                    "The receiving side could not accept more TCP data at those moments.",
                    ends, flow.zero_windows,
                    ["Identify the zero-window sender, which is the constrained receiver.",
                     "Check its application read rate, CPU, memory, and socket buffers."],
                    ["A brief zero window can be normal backpressure; this is not proof of "
                     "network congestion."],
                ))
            if flow.fatal.count:
                codes = ", ".join(str(code) for code in sorted(flow.alert_codes)) or "unspecified"
                result.append(finding(
                    "tls.fatal_alert", "warning", "high",
                    "A visible fatal TLS alert ended a TLS exchange",
                    f"{flow.fatal.count} fatal TLS alert(s) were observed; "
                    f"description codes: {codes}.",
                    "The alert sender rejected or terminated the TLS exchange.",
                    ends, flow.fatal,
                    ["Identify the alert sender and check its TLS/application logs.",
                     "Compare TLS versions, cipher support, trust settings, and any mutual-TLS "
                     "requirements. Use the alert code to narrow these checks."],
                    ["The alert alone may not identify the root cause. Most TLS 1.3 alerts "
                     "are encrypted and cannot be checked here."],
                ))
            if (
                flow.hello.count and not flow.server_hello and not flow.fatal.count
                and not flow.resets.count and self.old_enough(flow.hello, TLS_WAIT_SECONDS)
            ):
                result.append(finding(
                    "tls.no_server_hello", "warning", "low",
                    "A TLS ClientHello has no observed ServerHello",
                    f"{flow.hello.count} ClientHello packet(s) had no visible "
                    "ServerHello in this flow.",
                    "TLS setup may have stalled, or the server's reply is not visible.",
                    ends, flow.hello,
                    ["Confirm reverse traffic and the beginning of the connection were captured.",
                     "Check TLS termination, server logs, and intervening firewalls."],
                    ["Capture boundaries, missing segments, unusual protocol decoding, or "
                     "encrypted traffic can hide handshake messages."],
                ))
        return result

    def other_findings(self) -> list[Finding]:
        result = []
        names = {1: "format error", 2: "server failure", 3: "name not found",
                 4: "not implemented", 5: "refused"}
        for (server, code), samples in self.dns_errors.items():
            label = names.get(code, f"response code {code}")
            result.append(finding(
                "dns.error_response", "info" if code == 3 else "warning", "high",
                f"DNS returned {label}",
                f"{samples.count} DNS error response(s) came from {server} (rcode {code}).",
                "The DNS server explicitly reported that it could not answer the request "
                "successfully; the exact implication depends on the response code.",
                [server], samples,
                ["Check whether the requested name is expected to exist.",
                 "Check resolver health, upstream DNS, zone data, and query-access policy."],
                ["Name-not-found responses can be legitimate, including negative lookups "
                 "and service-discovery probes."],
                {"rcode": code},
            ))
        for txn in self.dns.values():
            if not self.old_enough(txn.requests, DNS_WAIT_SECONDS):
                continue
            repeated = txn.requests.count >= DNS_ATTEMPTS
            result.append(finding(
                "dns.unanswered", "warning" if repeated else "info", "low",
                "Repeated DNS queries have no observed reply" if repeated else
                "A DNS query has no observed reply",
                f"{txn.requests.count} request(s) for one DNS transaction "
                "had no matching response.",
                "DNS resolution may be delayed or blocked.",
                txn.endpoints, txn.requests,
                ["Confirm both directions were captured and the configured resolver is reachable.",
                 "Check UDP/TCP port 53 policy, resolver logs, and the return route."],
                ["The reply may be outside this capture. Retries with different IDs or source "
                 "ports are tracked separately."],
            ))
        for txn in self.dhcp.values():
            if (
                txn.requests.count >= DHCP_DISCOVERS and not txn.progressed
                and self.old_enough(txn.requests, DHCP_WAIT_SECONDS)
            ):
                result.append(finding(
                    "dhcp.discover_unanswered", "warning", "low",
                    "Repeated DHCP Discover messages show no lease negotiation progress",
                    f"{txn.requests.count} Discovers for one client/transaction had no observed "
                    "Offer, Request, or ACK.",
                    "The client may be unable to obtain an IPv4 lease.",
                    txn.endpoints, txn.requests,
                    ["Check the DHCP scope for available leases and review server logs.",
                     "Check VLAN placement, DHCP relay/helper settings, broadcast forwarding, "
                     "and DHCP-snooping policy.",
                     "Capture on the client VLAN and at the relay/server to check both sides."],
                    ["Offers may be missing from this capture. Transactions with different "
                     "IDs are evaluated separately."],
                ))
        for ip, samples in self.link_local.items():
            result.append(finding(
                "ip.apipa", "info", "high",
                "An IPv4 link-local (APIPA) address is present",
                f"{ip} appeared in {samples.count} IP packet(s).",
                "169.254.0.0/16 is link-local and is not normally routed. A host may have "
                "self-assigned this address after DHCP failed.",
                [ip], samples,
                ["Identify the address owner and whether link-local operation is intended.",
                 "If a routed address is expected, check the host's DHCP lease, VLAN, relay, "
                 "and address configuration."],
                ["Link-local addressing may be intentional; the address alone does not prove "
                 "a DHCP failure."],
            ))
        for rule, samples, title, meaning in [
            ("capture.truncated", self.truncated, "Some packets were captured only in part",
             "The capture snap length omitted bytes. Higher-layer decoding may be incomplete."),
            ("capture.malformed", self.malformed, "tshark marked packets as malformed",
             "Some packets could not be decoded normally."),
        ]:
            if samples.count:
                result.append(finding(
                    rule, "info", "high", title,
                    f"{samples.count} affected packet(s) were observed.", meaning, [], samples,
                    ["Inspect the evidence frames in Wireshark.",
                     "Recapture with full snap length and check capture drops if appropriate."],
                    ["Truncation, offload, unsupported protocols, or dissector limitations "
                     "can resemble malformed traffic."],
                ))
        return result

    def report(self, capture: str) -> Report:
        findings = self.tcp_findings() + self.other_findings()
        limitations = BASE_LIMITATIONS.copy()
        if self.out_of_order:
            limitations.append(
                "Packet timestamps are not in order. "
                "Timing-based interpretations are less reliable."
            )
        flows = list(self.flows.values())
        if (
            len(flows) >= 3 and sum(f.packets for f in flows) >= 10
            and all(len(f.directions) == 1 for f in flows)
        ):
            limitations.append(
                "All tracked TCP flows have traffic in only one direction. Check the SPAN/TAP "
                "configuration; this can also occur when all connection attempts get no reply."
            )
        limitations.extend(self.errors)
        for label in sorted(self.limits):
            limitations.append(f"Resource limit reached: {label}; some analysis was omitted.")
        rank = {"critical": 0, "warning": 1, "info": 2}
        confidence = {"high": 0, "medium": 1, "low": 2}
        findings.sort(key=lambda f: (
            rank[f.severity], confidence[f.confidence], f.rule, tuple(f.endpoints),
            f.evidence[0].frame if f.evidence else 0,
        ))
        if len(findings) > MAX_FINDINGS:
            limitations.append(
                f"Report limited to the first {MAX_FINDINGS} ranked findings; "
                f"{len(findings) - MAX_FINDINGS} additional findings were omitted."
            )
            findings = findings[:MAX_FINDINGS]
        status = "incomplete" if self.errors or self.limits else "complete"
        warnings = sum(f.severity == "warning" for f in findings)
        if not self.packet_count:
            summary = "Capture contains no decoded packets; no traffic diagnosis is possible."
        elif not findings:
            summary = "No supported issues detected."
        else:
            summary = (
                f"{len(findings)} finding(s): {warnings} warning(s), "
                f"{len(findings) - warnings} informational observation(s). "
                "Review the evidence and next checks; these are not confirmed root causes."
            )
        if status == "incomplete":
            summary = "Analysis incomplete. " + summary
        return Report(
            capture, status, summary, self.packet_count,
            round(self.last_time - (self.first_time or 0.0), 6),
            findings, limitations,
        )


def analyze(packets: Iterable[Packet], capture: str) -> Report:
    analyzer = Analyzer()
    iterator = iter(packets)
    try:
        for packet in iterator:
            if analyzer.packet_count >= MAX_PACKETS:
                analyzer.limits.add("packet analysis (1,000,000 packets)")
                break
            analyzer.consume(packet)
    except DecodeError as exc:
        analyzer.errors.append(str(exc))
    finally:
        close = getattr(iterator, "close", None)
        if close:
            close()
    return analyzer.report(capture)
