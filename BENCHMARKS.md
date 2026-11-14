# Scale validation

Measured on 2026-11-14 with Python 3.11.6, tshark 4.6.9, and an Apple M1 Pro
running macOS 27.0.1. Command:

```sh
.venv/bin/python -m tests.benchmark
```

| Format | File bytes | Packets analyzed | Decode + analysis | Python peak RSS | tshark peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| pcap | 99,499,776 | 68,244 | 1.931 s | 19.50 MB | 109.15 MB |
| pcapng | 99,498,684 | 67,411 | 2.039 s | 19.69 MB | 108.99 MB |

Both completed with all expected packets analyzed and no findings. RSS uses
decimal MB and is measured separately for Python and its decoder child. Runtime
includes decoder startup but excludes synthetic file generation.

This is a single-conversation synthetic Ethernet/IPv4/UDP workload with
1,442-byte packets, not a guarantee of performance for complex captures.
Many TCP flows, reassembly, tiny packets, or unusual dissectors can use more
time and memory. The 100 MB input cap, timeout, bounded Python trackers, and
explicit incomplete-report status are independent safeguards, not an OS sandbox.
