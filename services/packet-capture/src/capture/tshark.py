"""Chạy tshark ở chế độ `-T fields`: mỗi gói tin là một dòng, các trường cách nhau bằng tab."""
import asyncio
import logging
from collections import deque
from typing import AsyncIterator

logger = logging.getLogger(__name__)

# Thứ tự trường xuất ra từ tshark (nội dung `fields` của raw.v1).
# Thêm trường mới: thêm vào đây, xử lý ở packet-normalizer, sinh lại fixture của packet-normalizer.
TSHARK_FIELDS: tuple[str, ...] = (
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    "_ws.col.protocol",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ip.ttl",
    "ip.proto",
    "ipv6.src",
    "ipv6.dst",
    "ipv6.hlim",
    "ipv6.nxt",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "tcp.window_size_value",
    "tcp.len",
    "tcp.stream",
    "udp.srcport",
    "udp.dstport",
    "icmp.type",
    "icmp.code",
    "icmpv6.type",
    "icmpv6.code",
    "dns.qry.name",
    "dns.qry.type",
    "dns.flags.response",
    "dns.flags.rcode",
    "tls.handshake.extensions_server_name",
    "http.host",
    "http.request.method",
    "arp.opcode",
    "arp.src.proto_ipv4",
    "arp.src.hw_mac",
    "arp.dst.proto_ipv4",
    "arp.dst.hw_mac",
)


def build_command(tshark_path: str, input_args: list[str], display_filter: str = "") -> list[str]:
    cmd = [
        tshark_path, *input_args,
        "-n",                 # không phân giải tên (DNS lookup rất chậm)
        "-l",                 # flush stdout sau mỗi gói
        "-T", "fields",
        "-E", "separator=/t",
        "-E", "occurrence=f",  # chỉ lấy lần xuất hiện đầu (lớp ngoài cùng)
        "-E", "quote=n",
    ]
    if display_filter:
        cmd += ["-Y", display_filter]
    for field in TSHARK_FIELDS:
        cmd += ["-e", field]
    return cmd


def parse_line(line: str) -> dict[str, str] | None:
    """Tách một dòng output thành {field: value}, bỏ các trường rỗng."""
    values = line.rstrip("\r\n").split("\t")
    if len(values) != len(TSHARK_FIELDS):
        return None
    return {field: value for field, value in zip(TSHARK_FIELDS, values) if value}


class TsharkProcess:
    """Tiến trình tshark chạy bất đồng bộ, đọc stdout từng dòng mà không chặn event loop."""

    def __init__(self, cmd: list[str]):
        self.cmd = cmd
        self.process: asyncio.subprocess.Process | None = None
        self.stderr_tail: deque[str] = deque(maxlen=20)
        self._stderr_task: asyncio.Task | None = None

    async def start(self) -> None:
        logger.info(f"Starting tshark: {' '.join(self.cmd)}")
        self.process = await asyncio.create_subprocess_exec(
            *self.cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._stderr_task = asyncio.create_task(self._read_stderr())

    async def lines(self) -> AsyncIterator[str]:
        assert self.process and self.process.stdout
        while True:
            line = await self.process.stdout.readline()
            if not line:
                break
            yield line.decode("utf-8", errors="replace")

    async def wait(self) -> int:
        assert self.process
        returncode = await self.process.wait()
        if self._stderr_task:
            await self._stderr_task
        return returncode

    async def stop(self, timeout: float = 5.0) -> None:
        if not self.process or self.process.returncode is not None:
            return
        self.process.terminate()
        try:
            await asyncio.wait_for(self.process.wait(), timeout)
        except asyncio.TimeoutError:
            self.process.kill()
            await self.process.wait()

    async def _read_stderr(self) -> None:
        assert self.process and self.process.stderr
        async for raw in self.process.stderr:
            line = raw.decode("utf-8", errors="replace").strip()
            if line:
                self.stderr_tail.append(line)
                logger.info(f"tshark: {line}")
