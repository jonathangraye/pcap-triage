"""Generate small, synthetic demonstration captures. Never sends traffic."""

import argparse
from pathlib import Path

from tests.captures import scenario, write_capture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("examples"))
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name in ("healthy", "syn", "dns_error", "tls_fatal", "dhcp", "dhcp_healthy", "apipa"):
        path = args.output_dir / f"synthetic-{name}.pcapng"
        if path.exists():
            parser.error(f"Refusing to replace {path}")
        write_capture(path, scenario(name), pcapng=True)
        print(path)


if __name__ == "__main__":
    main()
