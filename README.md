# pcap-triage

First-pass packet capture troubleshooting for support engineers. Runs locally,
uses Wireshark's `tshark` to decode packets, and explains observations with
deterministic rules. No AI service or runtime Python dependencies.

**Evidence, not a verdict:** findings distinguish what the capture shows from
possible causes, give frame references, and suggest concrete next checks.

## Install

Requires Python 3.11+ and a current `tshark` (validated with Wireshark 4.6.9).

```sh
brew install wireshark
git clone https://github.com/jonathangraye/pcap-triage.git
cd pcap-triage
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
pcap-triage --help
```

On Linux, install `tshark` using your distribution's package manager. On Windows,
install Wireshark and add its executable directory to `PATH`. The standard macOS
Wireshark application bundle is also recognized. Live capture permissions, root,
and ChmodBPF are **not** needed. The CLI never installs anything automatically.

## Use

```sh
pcap-triage capture.pcapng
pcap-triage capture.pcapng --format json --output report.json
pcap-triage capture.pcapng --format markdown --output report.md
pcap-triage capture.pcapng --timeout 180
```

Supports uncompressed pcap (including nanosecond timestamps) and pcapng, up to
**100,000,000 bytes**, checked using the open input file. Files are identified by
magic bytes, not their extension. For filenames starting with `-`, use `--` before
the capture argument. The default decoder timeout is 120 seconds.

Existing output files require `--force`. New reports are created with owner-only
permissions where supported. Output symlinks, special files, and the input
capture itself (including hard links) are not valid overwrite targets.

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Analysis completed, even when findings exist or the capture contains no packets |
| `2` | Invalid input/arguments, missing dependency, or output-file error |
| `3` | Decoder failure/timeout or analysis resource limit; any report is explicitly incomplete |
| `130` | Interrupted by the user |

Partial reports retain decoded evidence and state why analysis stopped. Do not
treat exit `3` or a zero-packet capture as a clean bill of health.

## What it checks

| Rule | Evidence and default trigger |
| --- | --- |
| `tcp.syn_unanswered` | At least 3 SYNs in a flow, no reverse traffic observed, at least 3 seconds since the first SYN |
| `tcp.reset` | Any observed RST; warning during an uncompleted observed TCP setup, otherwise informational |
| `tcp.retransmissions` | At least 3 data-bearing packets flagged by tshark as retransmissions, comprising at least 5% of data-bearing packets |
| `tcp.zero_window` | A receiver advertised a zero TCP receive window |
| `dns.error_response` | Nonzero DNS response code; NXDOMAIN is informational because negative answers may be expected |
| `dns.unanswered` | An outstanding DNS transaction with at least 5 seconds of subsequent capture; 3+ requests make it a warning |
| `tls.fatal_alert` | A visible TLS alert with fatal level |
| `tls.no_server_hello` | A ClientHello without a visible ServerHello after at least 5 seconds; suppressed when a fatal alert or reset explains termination |
| `dhcp.discover_unanswered` | At least 3 DHCPv4 Discovers for the same client/transaction, no observed Offer, Request, or ACK, and at least 5 seconds since the first Discover |
| `ip.apipa` | An IPv4 source or destination in `169.254.0.0/16`, informational, not proof of failed DHCP |
| `capture.truncated` | Captured packet length is less than original packet length |
| `capture.malformed` | tshark marked a packet as malformed |

These thresholds are heuristics, centralized in `src/pcap_triage/analysis.py`.
Missing-reply findings always have **low confidence**. Their wait windows avoid
flagging a request seen only at the very end of a capture, but cannot eliminate
capture-boundary or asymmetric-capture uncertainty.

DNS matches client/server addresses, ports, transaction ID, and TCP stream when
applicable. It deliberately does not retain DNS names. Retries with different
IDs/ports are separate transactions; duplicate capture packets can resemble
retries. DHCP uses client hardware address and transaction ID, so a successful
transaction does not hide a failed one with a different ID.

### Reading a finding

For repeated DHCP Discovers, the report explains that the client may not be
obtaining a lease, lists the evidence frames, and suggests checking scope
capacity, VLAN placement, DHCP relay/helper settings, and DHCP snooping. It also
notes that missing Offers could be a capture-visibility problem.

**Severity** is troubleshooting priority (`warning` or `info`), not impact proven
by the capture. **Confidence** rates the interpretation, not certainty of a root
cause. High confidence in a reset, alert, or APIPA address does not establish why
it occurred. A quiet report says **“No supported issues detected.”**

## Reports and automation

Terminal, Markdown, and JSON share the same report model. JSON `schema_version`
is `1.0`; consumers should ignore unknown fields. The top level contains:

- `capture`: input basename only, with unsafe control characters removed.
- `status`: `complete` or `incomplete` (completion is not protocol coverage).
- `summary`, `packet_count`, `duration_seconds`, `findings`, and `limitations`.
- Each finding has `rule`, `severity`, `confidence`, `title`, `observed`,
  `meaning`, `endpoints`, `count`, `evidence`, `next_checks`, `alternatives`,
  and rule-specific numeric `metrics`.
- Evidence contains `frame` (1-based original capture frame) and `time_seconds`
  (relative to tshark's capture origin). Up to five representative frames are
  retained per finding. Counts include all tracked occurrences.

Findings are sorted deterministically by severity, confidence, rule, and
endpoints. Duration is the range of decoded packet timestamps, not wall-clock
analysis time. A warning appears if timestamps are out of order or several TCP
flows all lack reverse traffic.

## Privacy, safety, and limitations

- Analysis makes no uploads, AI calls, telemetry requests, or DNS lookups.
  Dependency installation is the only setup step requiring downloads.
- tshark receives a metadata field allowlist, with name resolution off, an
  isolated temporary user configuration, and TLS key-log use disabled.
  Python never loads complete payloads or extracts HTTP headers, cookies,
  credentials, URL query strings, or DNS names into reports.
- **This is not anonymization.** Reports contain IP/MAC endpoints, ports, timing,
  and the capture basename. Filenames can themselves contain sensitive data.
  Inspect reports before sharing them. The original capture is never altered.
- Terminal control characters and bidirectional controls are removed from report
  strings. Markdown additionally escapes markup and HTML. JSON is serialized,
  not interpolated.
- Encrypted application traffic and most TLS 1.3 alerts remain invisible. No
  decryption, HTTP diagnosis, live capture, or VPN/VoIP-specific diagnosis.
  DHCP rules cover DHCPv4 only; APIPA checks use IP packets, not ARP-only probes.
- Missing traffic may mean a partial capture, asymmetric routing, SPAN drops,
  or a genuine failure. No capture-only result proves a network is healthy.
  Retransmission percentages are **not** packet-loss measurements.
- Protocol decoding depends on tshark version, port recognition, reassembly, and
  encapsulation. For nested packets the first decoded occurrence of endpoint
  fields is used; complex tunnels may need manual analysis.
- Python streams metadata with bounded state: 1,000,000 packets, 20,000 TCP
  flows, 20,000 outstanding DNS transactions, 20,000 DNS error groups, 4,096
  DHCP transactions, 256 link-local addresses, five evidence examples per rule/
  group, and 200 ranked report findings. Tracking limits mark analysis
  incomplete. A report-only finding limit is disclosed in `limitations`.
  tshark maintains its own protocol state; its memory use varies with traffic.
- Captures are untrusted parser input. Keep tshark patched and run without
  elevated privileges. The CLI is not a substitute for an OS sandbox.

## Development and synthetic examples

```sh
python -m pip install -e '.[dev]'
python -m tests.generate_examples
pcap-triage examples/synthetic-dhcp.pcapng
python -m pytest -q
ruff check .
```

Scapy and its TLS cryptography support are development-only. Fixtures use
documentation IP ranges and explicit synthetic MAC addresses. Generation writes
files, never sends traffic, and does not need root. Integration tests use real
tshark for both file formats and skip explicitly if it is absent.

Run the separate scale check (generates temporary captures, deletes only its own
temporary directory, and prints JSON measurements):

```sh
python -m tests.benchmark
```

It checks approximately 99.5 MB in **each format**, verifies all expected packets
were analyzed, and records runtime plus separate Python/tshark peak RSS in
decimal MB. This single-flow UDP workload checks streaming, not worst-case
protocol complexity. Resource-cap behavior is also covered by unit tests.
