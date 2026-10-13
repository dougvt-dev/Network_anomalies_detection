from capture.sources.base import CaptureSource
from capture.sources.local import LocalInterfaceSource
from capture.sources.pcap import PcapFileSource

SOURCE_TYPES = ("local", "pcap")


def create_source(
    kind: str,
    interface: str = "",
    bpf_filter: str = "",
    pcap_file: str = "",
) -> CaptureSource:
    if kind == "local":
        source = LocalInterfaceSource(interface, bpf_filter)
    elif kind == "pcap":
        source = PcapFileSource(pcap_file)
    else:
        raise ValueError(f"Unknown capture source '{kind}', expected one of {SOURCE_TYPES}")
    source.validate()
    return source


__all__ = ["CaptureSource", "LocalInterfaceSource", "PcapFileSource", "SOURCE_TYPES", "create_source"]
