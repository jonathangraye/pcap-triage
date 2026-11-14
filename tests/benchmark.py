"""Reproducible near-limit capture benchmark, not part of the default test suite."""

import argparse
import json
import platform
import resource
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def generate(path: Path, target_bytes: int, pcapng: bool) -> int:
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    from tests.captures import GLOBAL_HEADER

    raw = bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/
                IP(src="192.0.2.1", dst="198.51.100.1")/
                UDP(sport=50000, dport=50001)/Raw(b"x"*1400))
    padding = b"\0" * (-len(raw) % 4)
    header = GLOBAL_HEADER
    record_bytes = 16 + len(raw)
    if pcapng:
        header = (
            struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
            + struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20)
        )
        record_bytes = 32 + len(raw) + len(padding)
    count = (target_bytes - len(header)) // record_bytes
    with path.open("xb") as handle:
        handle.write(header)
        for i in range(count):
            if pcapng:
                stamp = 1_700_000_000_000_000 + i*1000
                handle.write(struct.pack(
                    "<IIIIIII", 6, record_bytes, 0, stamp >> 32, stamp & 0xFFFFFFFF,
                    len(raw), len(raw),
                ))
                handle.write(raw + padding)
                handle.write(struct.pack("<I", record_bytes))
            else:
                handle.write(struct.pack(
                    "<IIII", 1_700_000_000 + i//1000, (i % 1000)*1000, len(raw), len(raw),
                ))
                handle.write(raw)
    return count


def peak_mb(usage):
    divisor = 1_000_000 if sys.platform == "darwin" else 1_000_000/1024
    return round(usage.ru_maxrss / divisor, 2)


def worker(path: Path):
    from pcap_triage.analysis import analyze
    from pcap_triage.decoder import decode, find_tshark, open_capture

    started = time.monotonic()
    with open_capture(path) as handle:
        report = analyze(decode(handle, find_tshark()), path.name)
    return {
        "bytes": path.stat().st_size, "packets": report.packet_count,
        "seconds": round(time.monotonic() - started, 3),
        "python_peak_rss_mb": peak_mb(resource.getrusage(resource.RUSAGE_SELF)),
        "tshark_peak_rss_mb": peak_mb(resource.getrusage(resource.RUSAGE_CHILDREN)),
        "status": report.status, "findings": len(report.findings),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--megabytes", type=float, default=99.5)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.worker)))
        return
    if not 0.1 <= args.megabytes <= 100:
        parser.error("--megabytes must be between 0.1 and 100")
    results = []
    with tempfile.TemporaryDirectory(prefix="pcap-triage-bench-") as directory:
        for pcapng in (False, True):
            path = Path(directory) / ("bench.pcapng" if pcapng else "bench.pcap")
            count = generate(path, int(args.megabytes * 1_000_000), pcapng)
            result = subprocess.run(
                [sys.executable, "-m", "tests.benchmark", "--worker", str(path)],
                capture_output=True, text=True, check=True, timeout=150,
            )
            data = json.loads(result.stdout)
            if data["packets"] != count or data["status"] != "complete" or data["findings"]:
                raise RuntimeError(f"Scale validation failed: {data}")
            data["format"] = "pcapng" if pcapng else "pcap"
            results.append(data)
    print(json.dumps({
        "platform": platform.platform(), "python": platform.python_version(),
        "traffic": "Synthetic 1,442-byte Ethernet/IPv4/UDP packets in one conversation",
        "results": results,
        "caveat": "Observed process RSS, not a memory guarantee; complex traffic uses more state.",
    }, indent=2))


if __name__ == "__main__":
    main()
