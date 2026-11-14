import json
import os
import struct
import sys
import time

import pytest

from pcap_triage import cli, decoder
from pcap_triage.analysis import analyze
from pcap_triage.decoder import DecodeError, InputError, decode, open_capture, parse_packet
from pcap_triage.render import render
from tests.captures import GLOBAL_HEADER
from tests.test_analysis import tcp


def line(**overrides):
    fields = {"frame.number": "1", "frame.time_relative": "0", "ip.src": "192.0.2.1"}
    fields.update(overrides)
    return "\t".join(fields.get(key, "") for key in decoder.FIELDS) + "\n"


def fake_decoder(tmp_path, code=""):
    path = tmp_path / "fake-tshark"
    path.write_text(f"#!{sys.executable}\n" + code)
    path.chmod(0o700)
    return str(path)


def capture(tmp_path):
    path = tmp_path / "input.pcap"
    path.write_bytes(GLOBAL_HEADER)
    return path


@pytest.mark.parametrize("magic", decoder.MAGIC)
def test_capture_magics(tmp_path, magic):
    path = tmp_path / "input"
    path.write_bytes(magic + b"\0"*20)
    with open_capture(path) as handle:
        assert handle.read(4) == magic


@pytest.mark.parametrize("contents", [b"", b"hello", b"\x1f\x8bxxx"])
def test_invalid_input(tmp_path, contents):
    path = tmp_path / "bad"
    path.write_bytes(contents)
    with pytest.raises(InputError, match="valid header"):
        open_capture(path)


def test_missing_directory_and_oversized_input(tmp_path):
    with pytest.raises(InputError):
        open_capture(tmp_path / "missing")
    with pytest.raises(InputError):
        open_capture(tmp_path)
    path = tmp_path / "large"
    with path.open("wb") as handle:
        handle.write(GLOBAL_HEADER)
        handle.truncate(decoder.MAX_CAPTURE_BYTES + 1)
    with pytest.raises(InputError, match="100 MB"):
        open_capture(path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="Requires POSIX")
def test_fifo_input_does_not_block(tmp_path):
    path = tmp_path / "fifo"
    os.mkfifo(path)
    with pytest.raises(InputError, match="regular file"):
        open_capture(path)


@pytest.mark.parametrize("values", [
    {"frame.time_relative": "nan"}, {"frame.number": "0"},
    {"frame.time_relative": "oops"}, {"ip.src": "not-an-ip"},
    {"frame.number": "oops"},
])
def test_invalid_metadata(values):
    with pytest.raises(DecodeError):
        parse_packet(line(**values))


def test_hex_and_aggregated_numbers():
    p = parse_packet(line(**{"dns.id": "0x1234", "tls.handshake.type": "1,2"}))
    assert p.n("dns.id") == 0x1234
    assert p.values("tls.handshake.type") == (1, 2)
    assert decoder.number("True") == 1
    assert decoder.number("False") == 0
    with pytest.raises(DecodeError):
        parse_packet("bad\n")


def test_missing_tshark(monkeypatch):
    monkeypatch.setattr(decoder.shutil, "which", lambda _: None)
    monkeypatch.setattr(decoder.Path, "is_file", lambda _: False)
    with pytest.raises(InputError, match="brew install wireshark"):
        decoder.find_tshark()


def test_spawn_failure(tmp_path):
    with open_capture(capture(tmp_path)) as handle, pytest.raises(InputError):
        list(decode(handle, str(tmp_path / "missing")))


def test_decoder_timeout(tmp_path):
    executable = fake_decoder(tmp_path, "import time\ntime.sleep(10)\n")
    started = time.monotonic()
    with open_capture(capture(tmp_path)) as handle, pytest.raises(DecodeError, match="timed out"):
        list(decode(handle, executable, .1))
    assert time.monotonic() - started < 3


def test_partial_decode_failure(tmp_path):
    executable = fake_decoder(
        tmp_path, f"print({line()!r}, end='', flush=True)\nraise SystemExit(2)\n",
    )
    with open_capture(capture(tmp_path)) as handle:
        report = analyze(decode(handle, executable), "x")
    assert report.status == "incomplete"
    assert report.packet_count == 1


def test_per_line_output_bound(tmp_path):
    executable = fake_decoder(tmp_path, "print('x' * 70000)\n")
    with open_capture(capture(tmp_path)) as handle, pytest.raises(DecodeError, match="size limit"):
        list(decode(handle, executable))


def test_sanitized_environment_and_safe_arguments(tmp_path, monkeypatch):
    executable = fake_decoder(tmp_path)
    popen = decoder.subprocess.Popen
    observed = {}

    def track(command, **kwargs):
        observed.update(command=command, **kwargs)
        return popen(command, **kwargs)

    monkeypatch.setattr(decoder.subprocess, "Popen", track)
    monkeypatch.setenv("SSLKEYLOGFILE", "/private/keylog")
    with open_capture(capture(tmp_path)) as handle:
        list(decode(handle, executable))
    assert "-n" in observed["command"]
    assert observed["command"][observed["command"].index("-r")+1] == "-"
    assert "tls.keylog_file:" in observed["command"]
    assert "SSLKEYLOGFILE" not in observed["env"]
    assert observed["env"]["WIRESHARK_CONFIG_DIR"] != os.environ.get("WIRESHARK_CONFIG_DIR")
    assert not observed.get("shell")


def test_render_formats_share_findings_and_escape_text():
    report = analyze([tcp(1, fields={"tcp.flags.reset": "1"})],
                     "\x1b[31m[click](https://example.test)<script>\u202e.pcap")
    data = json.loads(render(report, "json"))
    for format_name in ("terminal", "markdown"):
        body = render(report, format_name)
        for item in data["findings"]:
            assert item["rule"] in body
        assert "\x1b" not in body
        assert "\u202e" not in body
    markdown = render(report, "markdown")
    assert "<script>" not in markdown
    assert "&lt;script&gt;" in markdown
    assert "\\[click\\]" in markdown


def test_cli_outputs_and_file_safety(tmp_path, monkeypatch, capsys):
    path = capture(tmp_path)
    executable = fake_decoder(tmp_path, f"print({line()!r}, end='')\n")
    monkeypatch.setattr(cli, "find_tshark", lambda: executable)
    assert cli.main([str(path), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["packet_count"] == 1
    target = tmp_path / "report.json"
    assert cli.main([str(path), "--format", "json", "--output", str(target)]) == 0
    assert target.stat().st_mode & 0o777 == 0o600
    original = target.read_bytes()
    assert cli.main([str(path), "--output", str(target)]) == 2
    assert target.read_bytes() == original
    assert cli.main([str(path), "--output", str(target), "--force"]) == 0
    assert target.read_text().startswith("pcap-triage")
    assert cli.main([str(path), "--output", str(path), "--force"]) == 2
    assert path.read_bytes() == GLOBAL_HEADER
    hardlink = tmp_path / "hardlink"
    os.link(path, hardlink)
    assert cli.main([str(path), "--output", str(hardlink), "--force"]) == 2
    assert path.read_bytes() == GLOBAL_HEADER


def test_output_symlink_is_not_followed(tmp_path, monkeypatch):
    path = capture(tmp_path)
    target = tmp_path / "target"
    target.write_text("unchanged")
    link = tmp_path / "link"
    link.symlink_to(target)
    executable = fake_decoder(tmp_path)
    monkeypatch.setattr(cli, "find_tshark", lambda: executable)
    assert cli.main([str(path), "--output", str(link), "--force"]) == 2
    assert target.read_text() == "unchanged"


def test_output_symlink_loop_is_a_clear_input_error(tmp_path, capsys):
    path = capture(tmp_path)
    link = tmp_path / "loop"
    link.symlink_to(link)
    assert cli.main([str(path), "--output", str(link), "--force"]) == 2
    assert "symlink" in capsys.readouterr().err


@pytest.mark.parametrize("force", [False, True])
def test_output_appearing_during_analysis_does_not_destroy_input(
    tmp_path, monkeypatch, force,
):
    path = capture(tmp_path)
    target = tmp_path / "late-output"
    executable = fake_decoder(tmp_path)
    monkeypatch.setattr(cli, "find_tshark", lambda: executable)
    real_analyze = cli.analyze

    def create_output(*args):
        report = real_analyze(*args)
        if force:
            os.link(path, target)
        else:
            target.write_text("user work")
        return report

    monkeypatch.setattr(cli, "analyze", create_output)
    flags = ["--force"] if force else []
    assert cli.main([str(path), "--output", str(target), *flags]) == 2
    assert path.read_bytes() == GLOBAL_HEADER
    assert target.read_bytes() == (GLOBAL_HEADER if force else b"user work")


def test_capture_descriptor_stays_at_start_after_validation(tmp_path):
    with open_capture(capture(tmp_path)) as handle:
        assert os.lseek(handle.fileno(), 0, os.SEEK_CUR) == 0


def test_timeout_report_retains_partial_packet_count(tmp_path, monkeypatch, capsys):
    executable = fake_decoder(
        tmp_path, f"import time\nprint({line()!r}, end='', flush=True)\ntime.sleep(10)\n",
    )
    monkeypatch.setattr(cli, "find_tshark", lambda: executable)
    assert cli.main([str(capture(tmp_path)), "--format", "json", "--timeout", ".2"]) == 3
    report = json.loads(capsys.readouterr().out)
    assert report["packet_count"] == 1
    assert any("timed out" in text for text in report["limitations"])


def test_output_path_failure_and_missing_dependency(tmp_path, monkeypatch):
    path = capture(tmp_path)
    monkeypatch.setattr(cli, "find_tshark", lambda: fake_decoder(tmp_path))
    assert cli.main([str(path), "--output", str(tmp_path / "absent" / "x")]) == 2

    def missing():
        raise InputError("tshark is required.")
    monkeypatch.setattr(cli, "find_tshark", missing)
    assert cli.main([str(path)]) == 2


def test_cli_decoder_failure_exit_three(tmp_path, monkeypatch, capsys):
    executable = fake_decoder(tmp_path, "raise SystemExit(2)\n")
    monkeypatch.setattr(cli, "find_tshark", lambda: executable)
    assert cli.main([str(capture(tmp_path)), "--format", "json"]) == 3
    assert json.loads(capsys.readouterr().out)["status"] == "incomplete"


@pytest.mark.parametrize("timeout", ["0", "-1", "nan", "inf", "no"])
def test_invalid_timeout(timeout):
    with pytest.raises(SystemExit) as exc:
        cli.main(["capture.pcap", "--timeout", timeout])
    assert exc.value.code == 2


def test_broken_capture_header_is_deferred_to_tshark(tmp_path):
    path = tmp_path / "short.pcap"
    path.write_bytes(struct.pack("<I", 0xA1B2C3D4))
    with open_capture(path) as handle:
        assert len(handle.read()) == 4
