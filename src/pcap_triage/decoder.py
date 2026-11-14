"""Stream a small metadata allowlist from tshark, without shell or name resolution."""

import ipaddress
import math
import os
import shutil
import stat
import subprocess
import tempfile
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

MAX_CAPTURE_BYTES = 100_000_000
MAX_LINE_BYTES = 65_536
DEFAULT_TIMEOUT = 120.0
MAGIC = {
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a",
}

# No HTTP headers, URLs, DNS names, decrypted content, or raw payload fields.
FIELDS = (
    "frame.number", "frame.time_relative", "frame.len", "frame.cap_len",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.flags.syn",
    "tcp.flags.ack", "tcp.flags.reset", "tcp.len",
    "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
    "tcp.analysis.spurious_retransmission", "tcp.analysis.zero_window",
    "udp.srcport", "udp.dstport", "dns.id", "dns.flags.response",
    "dns.flags.rcode", "tls.handshake.type", "tls.alert_message.level",
    "tls.alert_message.desc", "dhcp.id", "dhcp.hw.mac_addr", "dhcp.option.dhcp",
    "_ws.malformed",
)


class InputError(Exception):
    """Invalid input or unavailable dependency (exit 2)."""


class DecodeError(Exception):
    """Decoder failed, timed out, or returned invalid metadata (exit 3)."""


def open_capture(path: Path) -> BinaryIO:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        # tshark inherits the descriptor, so its OS offset must match Python's offset.
        handle = os.fdopen(descriptor, "rb", buffering=0)
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise InputError("The capture must be a regular file.")
        if info.st_size > MAX_CAPTURE_BYTES:
            raise InputError("The capture exceeds the 100 MB (100,000,000 byte) limit.")
        if handle.read(4) not in MAGIC:
            raise InputError("Expected an uncompressed pcap or pcapng file with a valid header.")
        handle.seek(0)
        return handle
    except (OSError, InputError) as exc:
        if "handle" in locals():
            handle.close()
        if isinstance(exc, InputError):
            raise
        raise InputError("Cannot open the capture. Check its path and permissions.") from exc


def find_tshark() -> str:
    executable = shutil.which("tshark")
    bundled = Path("/Applications/Wireshark.app/Contents/MacOS/tshark")
    if executable:
        return executable
    if bundled.is_file() and os.access(bundled, os.X_OK):
        return str(bundled)
    raise InputError(
        "tshark is required. Install Wireshark's CLI (macOS: brew install wireshark), "
        "then ensure tshark is on PATH."
    )


def first(value: str) -> str:
    return value.split(",", 1)[0]


def number(value: str, default: int = 0) -> int:
    value = first(value)
    if not value:
        return default
    if value.lower() in ("true", "false"):
        return int(value.lower() == "true")
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError as exc:
        raise DecodeError("tshark returned invalid numeric metadata.") from exc


def numbers(value: str) -> tuple[int, ...]:
    return tuple(number(item) for item in value.split(",") if item)


def address(value: str) -> str:
    value = first(value)
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise DecodeError("tshark returned an invalid IP address.") from exc


@dataclass(frozen=True)
class Packet:
    frame: int
    time: float
    src: str = ""
    dst: str = ""
    fields: dict[str, str] = field(default_factory=dict)

    def n(self, key: str, default: int = 0) -> int:
        return number(self.fields.get(key, ""), default)

    def has(self, key: str) -> bool:
        return bool(self.fields.get(key, ""))

    def values(self, key: str) -> tuple[int, ...]:
        return numbers(self.fields.get(key, ""))


def parse_packet(line: str) -> Packet:
    values = line.rstrip("\r\n").split("\t")
    if len(values) != len(FIELDS):
        raise DecodeError("tshark returned an unexpected metadata format.")
    fields = dict(zip(FIELDS, values, strict=True))
    try:
        timestamp = float(first(fields["frame.time_relative"]))
    except ValueError as exc:
        raise DecodeError("tshark returned an invalid packet timestamp.") from exc
    frame = number(fields["frame.number"])
    if not math.isfinite(timestamp) or frame < 1:
        raise DecodeError("tshark returned an invalid packet reference.")
    return Packet(
        frame, timestamp,
        address(fields["ip.src"] or fields["ipv6.src"]),
        address(fields["ip.dst"] or fields["ipv6.dst"]),
        fields,
    )


def decode(
    handle: BinaryIO, executable: str, timeout: float = DEFAULT_TIMEOUT,
) -> Iterator[Packet]:
    # Ignore personal decryption preferences/key logs and avoid writing user config.
    with tempfile.TemporaryDirectory(prefix="pcap-triage-") as config:
        environment = os.environ.copy()
        environment.pop("SSLKEYLOGFILE", None)
        environment["WIRESHARK_CONFIG_DIR"] = config
        yield from _decode(handle, executable, timeout, environment)


def _decode(
    handle: BinaryIO, executable: str, timeout: float, environment: dict[str, str],
) -> Iterator[Packet]:
    command = [
        executable, "-n", "-l", "-r", "-", "-T", "fields",
        "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,",
        "-o", "tcp.analyze_sequence_numbers:TRUE",
        "-o", "tls.keylog_file:",
    ]
    for name in FIELDS:
        command.extend(("-e", name))
    try:
        process = subprocess.Popen(
            command, stdin=handle, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=environment,
        )
    except OSError as exc:
        raise InputError("Cannot start tshark. Check its installation and permissions.") from exc
    expired = threading.Event()

    def terminate() -> None:
        expired.set()
        try:
            process.kill()
        except ProcessLookupError:
            pass

    timer = threading.Timer(timeout, terminate)
    timer.daemon = True
    timer.start()
    try:
        assert process.stdout is not None
        while True:
            line = process.stdout.readline(MAX_LINE_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_LINE_BYTES:
                raise DecodeError("Packet metadata exceeded the safe per-packet size limit.")
            try:
                yield parse_packet(line.decode("utf-8", errors="strict"))
            except UnicodeDecodeError as exc:
                raise DecodeError("tshark returned invalid metadata encoding.") from exc
        code = process.wait()
        if expired.is_set():
            raise DecodeError("Analysis timed out. Findings cover only the packets decoded so far.")
        if code:
            raise DecodeError(
                f"tshark did not finish successfully (exit {code}). The capture may be "
                "damaged, or this tshark version may not support the required fields."
            )
    finally:
        timer.cancel()
        if process.poll() is None:
            process.kill()
        process.wait()
        if process.stdout:
            process.stdout.close()
        timer.join()
