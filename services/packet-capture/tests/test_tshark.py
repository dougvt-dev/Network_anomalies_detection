import asyncio

import pytest

from capture.sources import LocalInterfaceSource, PcapFileSource, create_source
from capture.tshark import TSHARK_FIELDS, TsharkProcess, build_command, parse_line
from conftest import requires_tshark


def test_build_command_local_with_filters():
    source = LocalInterfaceSource("eth0", bpf_filter="not port 22")
    cmd = build_command("tshark", source.tshark_input_args(), display_filter="ip")
    assert cmd[:5] == ["tshark", "-i", "eth0", "-f", "not port 22"]
    assert ["-Y", "ip"] == cmd[cmd.index("-Y"):cmd.index("-Y") + 2]
    assert cmd.count("-e") == len(TSHARK_FIELDS)


def test_parse_line_drops_empty_fields():
    values = [""] * len(TSHARK_FIELDS)
    values[0] = "1700000000.5"
    values[TSHARK_FIELDS.index("ip.src")] = "10.0.0.1"
    assert parse_line("\t".join(values) + "\n") == {"frame.time_epoch": "1700000000.5", "ip.src": "10.0.0.1"}


def test_parse_line_rejects_wrong_field_count():
    assert parse_line("only\tthree\tfields\n") is None


def test_create_source_validation(tmp_path):
    with pytest.raises(ValueError):
        create_source("local", interface="does-not-exist0")
    with pytest.raises(ValueError):
        create_source("pcap", pcap_file=str(tmp_path / "missing.pcap"))
    with pytest.raises(ValueError):
        create_source("ssh")
    assert isinstance(create_source("local", interface="lo"), LocalInterfaceSource)


@requires_tshark
def test_tshark_reads_pcap(sample_pcap):
    async def run():
        proc = TsharkProcess(build_command("tshark", PcapFileSource(sample_pcap).tshark_input_args()))
        await proc.start()
        lines = [line async for line in proc.lines()]
        return lines, await proc.wait()

    lines, returncode = asyncio.run(run())
    assert returncode == 0
    parsed = [parse_line(line) for line in lines]
    assert len(parsed) == 7 and all(parsed)
    assert parsed[0]["dns.qry.name"] == "example.com"
