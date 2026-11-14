"""Synthetic traffic only. Nothing in this module sends packets."""

import struct
from pathlib import Path

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.layers.tls.record import TLS, TLSAlert
from scapy.packet import Raw
from scapy.utils import PcapNgWriter, PcapWriter

CLIENT = "192.0.2.10"
SERVER = "198.51.100.20"
MAC = b"\x02\x00\x00\x00\x00\x01"
EPOCH = 1_700_000_000
GLOBAL_HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def at(packet, seconds):
    packet.time = EPOCH + seconds
    return packet


def ether():
    # Explicit MACs prevent Scapy from attempting ARP while serializing synthetic packets.
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def clock(seconds=10):
    return at(ether()/IP(src="203.0.113.1", dst="203.0.113.2")/
              UDP(sport=50001, dport=50002)/Raw(b"clock"), seconds)


def tcp(seconds, flags="A", reverse=False, seq=1001, ack=2001, payload=None, window=8192):
    src, dst = (SERVER, CLIENT) if reverse else (CLIENT, SERVER)
    sport, dport = (443, 50000) if reverse else (50000, 443)
    packet = ether()/IP(src=src, dst=dst)/TCP(
        sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=window,
    )
    if payload is not None:
        packet = packet/payload
    return at(packet, seconds)


def handshake():
    return [
        tcp(0, "S", seq=1000, ack=0),
        tcp(.01, "SA", reverse=True, seq=2000, ack=1001),
        tcp(.02),
    ]


def dns(seconds=0, response=False, rcode=0, ident=123, port=53000):
    src, dst = (SERVER, CLIENT) if response else (CLIENT, SERVER)
    sport, dport = (53, port) if response else (port, 53)
    data = DNS(
        id=ident, qr=int(response), rcode=rcode, qd=DNSQR(qname="synthetic.example."),
    )
    if response and not rcode:
        data.an = DNSRR(rrname="synthetic.example.", rdata="203.0.113.20", ttl=60)
        data.ancount = 1
    return at(ether()/IP(src=src, dst=dst)/UDP(sport=sport, dport=dport)/data, seconds)


def dhcp(seconds=0, msg="discover", xid=0x12345678):
    reply = msg in ("offer", "ack")
    data = Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")/IP(
        src=SERVER if reply else "0.0.0.0", dst="255.255.255.255",
    )/UDP(sport=67 if reply else 68, dport=68 if reply else 67)/BOOTP(
        op=2 if reply else 1, xid=xid, chaddr=MAC, flags=0x8000,
        yiaddr="192.0.2.100" if reply else "0.0.0.0",
    )/DHCP(options=[("message-type", msg), "end"])
    return at(data, seconds)


def scenario(name):
    if name == "healthy":
        return handshake() + [dns(.1), dns(.2, response=True), clock()]
    if name == "syn":
        return [tcp(t, "S", seq=1000, ack=0) for t in (0, 1, 3)] + [clock()]
    if name == "reset":
        return [tcp(0, "S", seq=1000, ack=0),
                tcp(.1, "RA", reverse=True, seq=0, ack=1001), clock()]
    if name == "retransmissions":
        return handshake() + [
            tcp(t, "PA", payload=Raw(b"x" * 100)) for t in (.1, 1, 2, 4)
        ] + [clock()]
    if name == "zero_window":
        return handshake() + [tcp(.1, reverse=True, seq=2001, ack=1001, window=0), clock()]
    if name == "dns_unanswered":
        return [dns(t) for t in (0, 1, 3)] + [clock()]
    if name == "dns_error":
        return [dns(), dns(.1, response=True, rcode=2), clock()]
    if name in ("tls_incomplete", "tls_healthy"):
        hello = TLS(msg=[TLSClientHello(gmt_unix_time=0, random_bytes=b"c" * 28)])
        packets = handshake() + [tcp(.1, "PA", payload=hello)]
        if name == "tls_healthy":
            reply = TLS(msg=[TLSServerHello(gmt_unix_time=0, random_bytes=b"s" * 28)])
            packets.append(tcp(
                .2, "PA", reverse=True, seq=2001, ack=1001 + len(bytes(hello)), payload=reply,
            ))
        return packets + [clock()]
    if name == "tls_fatal":
        return handshake() + [
            tcp(.1, "PA", reverse=True, seq=2001, ack=1001,
                payload=TLS(msg=[TLSAlert(level=2, descr=40)])), clock(),
        ]
    if name == "dhcp":
        return [dhcp(t) for t in (0, 3, 7)] + [clock()]
    if name == "dhcp_healthy":
        return [dhcp(), dhcp(.1, "offer"), dhcp(.2, "request"), dhcp(.3, "ack"), clock()]
    if name == "apipa":
        return [at(ether()/IP(src="169.254.20.30", dst="192.0.2.1")/
                   UDP(sport=50000, dport=50001), 0)]
    if name == "malformed":
        return [at(ether()/IP(src=CLIENT, dst=SERVER)/
                   UDP(sport=53000, dport=53)/Raw(b"\x01"), 0)]
    raise ValueError(name)


def write_capture(path: Path, packets, pcapng=False):
    if pcapng:
        with PcapNgWriter(str(path)) as writer:
            for packet in packets:
                writer.write(packet)
    else:
        with PcapWriter(str(path), linktype=1, sync=True) as writer:
            writer.write_header(None)
            for packet in packets:
                writer.write(packet)
    return path


def truncated_capture(path):
    raw = bytes(ether()/IP(src=CLIENT, dst=SERVER)/UDP(sport=50000, dport=50001)/Raw(b"x"*40))
    path.write_bytes(GLOBAL_HEADER + struct.pack("<IIII", EPOCH, 0, 34, len(raw)) + raw[:34])
    return path


def corrupt_capture(path):
    raw = bytes(clock())
    path.write_bytes(
        GLOBAL_HEADER + struct.pack("<IIII", EPOCH, 0, len(raw), len(raw)) + raw
        + struct.pack("<IIII", EPOCH+1, 0, 100, 100) + b"bad"
    )
    return path
