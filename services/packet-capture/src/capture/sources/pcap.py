from pathlib import Path

from capture.sources.base import CaptureSource


class PcapFileSource(CaptureSource):
    """Replay file .pcap/.pcapng (test pipeline, dữ liệu train ML)."""

    name = "pcap"
    is_live = False

    def __init__(self, path: str):
        self.path = path

    def validate(self) -> None:
        if not self.path:
            raise ValueError("PCAP file path is empty")
        if not Path(self.path).is_file():
            raise ValueError(f"PCAP file '{self.path}' not found")

    def tshark_input_args(self) -> list[str]:
        return ["-r", self.path]

    def describe(self) -> dict:
        return {"type": self.name, "path": self.path}
