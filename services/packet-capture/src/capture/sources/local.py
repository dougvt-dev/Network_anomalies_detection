from pathlib import Path

from capture.sources.base import CaptureSource


class LocalInterfaceSource(CaptureSource):
    """Bắt gói trực tiếp trên card mạng của máy thu.

    Khi máy thu làm gateway: chọn card phía LAN (trước NAT) để thấy IP thật của thiết bị.
    Cũng dùng cho card nhận traffic SPAN/ERSPAN, hoặc eth0 khi dev.
    """

    name = "local"
    is_live = True

    def __init__(self, interface: str, bpf_filter: str = ""):
        self.interface = interface
        self.bpf_filter = bpf_filter

    def validate(self) -> None:
        if not self.interface:
            raise ValueError("Capture interface is empty")
        if self.interface != "any" and not Path(f"/sys/class/net/{self.interface}").exists():
            raise ValueError(f"Network interface '{self.interface}' not found")

    def tshark_input_args(self) -> list[str]:
        args = ["-i", self.interface]
        if self.bpf_filter:
            args += ["-f", self.bpf_filter]
        return args

    def describe(self) -> dict:
        return {"type": self.name, "interface": self.interface, "bpf_filter": self.bpf_filter}
