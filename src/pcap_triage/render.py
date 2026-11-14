"""Plain terminal, Markdown, and JSON views of exactly the same report."""

import json
import re
import unicodedata
from typing import Any

from .models import Report

ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))")


def safe_text(value: str) -> str:
    value = ANSI.sub("", value)
    return "".join(
        c if not unicodedata.category(c).startswith("C") else " " for c in value
    )


def clean(value: Any) -> Any:
    if isinstance(value, str):
        return safe_text(value)
    if isinstance(value, list):
        return [clean(item) for item in value]
    if isinstance(value, dict):
        return {safe_text(str(k)): clean(v) for k, v in value.items()}
    return value


def markdown_text(value: str) -> str:
    value = safe_text(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"([\\`*_{}\[\]()#+.!|~-])", r"\\\1", value)


def render(report: Report, format_name: str) -> str:
    data = clean(report.to_dict())
    if format_name == "json":
        return json.dumps(data, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
    md = format_name == "markdown"
    text = markdown_text if md else safe_text
    lines = [
        "# pcap-triage" if md else "pcap-triage",
        "", text(data["summary"]), "",
        f"Capture: {text(data['capture'])}",
        f"Status: {data['status']} | Packets: {data['packet_count']} | "
        f"Duration: {data['duration_seconds']:.6f}s",
    ]
    for index, item in enumerate(data["findings"], 1):
        lines.extend([
            "", f"{'## ' if md else ''}{index}. [{item['severity'].upper()}] "
            f"{text(item['title'])}",
            f"Rule: {item['rule']} | Confidence: {item['confidence']} | Count: {item['count']}",
            f"Observed: {text(item['observed'])}", f"Meaning: {text(item['meaning'])}",
            f"Endpoints: {', '.join(text(e) for e in item['endpoints']) or 'capture-wide'}",
            "Evidence: " + ", ".join(
                f"frame {e['frame']} at {e['time_seconds']:.6f}s" for e in item["evidence"]
            ),
            "Next checks:",
        ])
        lines.extend(f"- {text(check)}" for check in item["next_checks"])
        lines.append("Other explanations:")
        lines.extend(f"- {text(alt)}" for alt in item["alternatives"])
        if item["metrics"]:
            lines.append("Metrics: " + ", ".join(
                f"{key}={value}" for key, value in item["metrics"].items()
            ))
    lines.extend(["", "## Limitations" if md else "Limitations:"])
    lines.extend(f"- {text(limit)}" for limit in data["limitations"])
    return "\n".join(lines) + "\n"
