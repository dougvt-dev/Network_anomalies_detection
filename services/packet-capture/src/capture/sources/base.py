from abc import ABC, abstractmethod


class CaptureSource(ABC):
    """Nguồn dữ liệu gói tin, quy về tham số đầu vào của tshark."""

    name: str
    # live: tshark dừng bất thường thì tự khởi động lại; offline (file): dừng là hoàn tất
    is_live: bool
    interface: str | None = None

    @abstractmethod
    def validate(self) -> None:
        """Raise ValueError nếu nguồn không dùng được (sai interface, thiếu file...)."""

    @abstractmethod
    def tshark_input_args(self) -> list[str]:
        """Tham số đầu vào cho tshark, ví dụ ['-i', 'eth0'] hoặc ['-r', 'file.pcap']."""

    @abstractmethod
    def describe(self) -> dict:
        """Thông tin hiển thị trên API status."""
