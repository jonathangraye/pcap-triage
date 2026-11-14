# Repository Guidelines

## Project Structure & Module Organization

- `src/pcap_triage/` contains the runtime package: `cli.py` handles arguments and
  files, `decoder.py` streams tshark metadata, and `analysis.py` owns diagnostic
  rules and thresholds.
- `models.py` defines the shared, versioned report contract; `render.py` provides
  terminal, JSON, and Markdown output.
- `tests/` contains pytest tests, Scapy capture builders, example generation,
  and the standalone benchmark. Generated captures live in ignored `examples/`.
- `README.md` documents behavior and limitations; `BENCHMARKS.md` records measured
  performance. Packaging and lint configuration live in `pyproject.toml`.

## Build, Test, and Development Commands

Requires Python 3.11+ and tshark on `PATH`.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'  # Editable install and development dependencies
python -m pytest -q              # Unit and real-decoder integration tests
ruff check .                    # Configured Python lint checks
python -m tests.generate_examples
pcap-triage examples/synthetic-dhcp.pcapng
python -m tests.benchmark        # Separate near-100 MB checks for both formats
```

Example generation refuses to replace existing files. Integration tests explicitly
skip when tshark is unavailable; disclose those skips rather than claiming full
validation.

## Coding Style & Naming Conventions

Use four-space indentation, a 100-character line limit, `snake_case` functions
and modules, and `PascalCase` classes. Follow existing type hints and dataclasses.
Keep runtime Python dependencies standard-library-only; Scapy and cryptography
are development-only. Keep rules separate from decoding and rendering. Preserve
deterministic finding order and report-schema compatibility.

## Testing Guidelines

Name tests `test_*` in `tests/test_*.py`. Add synthetic healthy, failure, and
capture-boundary cases for rule changes. Verify evidence references, confidence,
and alternative explanations. Exercise pcap and pcapng through real tshark for
decoder changes. Cover safe rendering, timeouts, resource limits, and overwrite
protection when affected. No coverage-percentage threshold is configured.

## Commit & Pull Request Guidelines

No Git history existed at initialization, so no established message convention
was available. Use concise, imperative subjects such as `Add DHCP retry checks`.
PRs should explain behavior changes, list validation commands and skipped checks,
and link relevant issues. Update documentation for changed thresholds, formats,
exit codes, or limitations.

## Customer Data & Safety

Never commit customer captures, reports, credentials, or payloads. Use synthetic
fixtures only, with explicit MAC addresses to avoid Scapy ARP lookups. Preserve
local-only analysis, disabled name resolution, bounded tracking, and decoder
timeouts. Never modify input captures or silently overwrite reports. Missing
traffic is not proof of failure, and a quiet report does not prove network health.
