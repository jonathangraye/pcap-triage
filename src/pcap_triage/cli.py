"""Command-line entry point. Analysis never makes network requests."""

import argparse
import math
import os
import stat
import sys
from pathlib import Path

from . import __version__
from .analysis import analyze
from .decoder import DEFAULT_TIMEOUT, InputError, decode, find_tshark, open_capture
from .render import render, safe_text


def positive_seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Timeout must be a positive number of seconds.") from exc
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError("Timeout must be a finite, positive number of seconds.")
    return seconds


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Local, evidence-backed first-pass triage of pcap and pcapng captures.",
    )
    result.add_argument("capture", type=Path)
    result.add_argument("--format", choices=("terminal", "json", "markdown"), default="terminal")
    result.add_argument("--output", type=Path, help="Save a report instead of printing it.")
    result.add_argument("--force", action="store_true", help="Overwrite an existing report file.")
    result.add_argument(
        "--timeout", type=positive_seconds, default=DEFAULT_TIMEOUT,
        help=f"Maximum decoder runtime in seconds (default: {DEFAULT_TIMEOUT:g}).",
    )
    result.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return result


def check_output(capture: Path, output: Path | None, force: bool) -> None:
    if output is None:
        return
    try:
        if output.is_symlink():
            raise InputError("Report output must not be a symlink.")
        if output.resolve() == capture.resolve() or (
            output.exists() and os.path.samefile(capture, output)
        ):
            raise InputError("The report output must not be the capture file or a link to it.")
        if output.exists() and not force:
            raise InputError("The report already exists. Use --force to overwrite it.")
    except (OSError, RuntimeError) as exc:
        raise InputError("Cannot inspect the report output path.") from exc


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        with open_capture(args.capture) as handle:
            capture_info = os.fstat(handle.fileno())
            check_output(args.capture, args.output, args.force)
            executable = find_tshark()
            report = analyze(decode(handle, executable, args.timeout), args.capture.name)
        body = render(report, args.format)
        if args.output is None:
            sys.stdout.write(body)
        else:
            # Exclusive creation also protects against a file appearing during analysis.
            try:
                flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                flags |= getattr(os, "O_NONBLOCK", 0)
                if not args.force:
                    flags |= os.O_EXCL
                descriptor = os.open(args.output, flags, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                    info = os.fstat(output.fileno())
                    if not stat.S_ISREG(info.st_mode) or (
                        info.st_dev, info.st_ino
                    ) == (capture_info.st_dev, capture_info.st_ino):
                        raise InputError("Report output must be a regular file, not the capture.")
                    os.ftruncate(output.fileno(), 0)
                    output.write(body)
            except OSError as exc:
                raise InputError("Cannot write the report. Check its path, permissions, and "
                                 "whether it already exists.") from exc
        return 0 if report.status == "complete" else 3
    except InputError as exc:
        print(f"pcap-triage: {safe_text(str(exc))}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        print("pcap-triage: interrupted; no complete report was produced.", file=sys.stderr)
        return 130
