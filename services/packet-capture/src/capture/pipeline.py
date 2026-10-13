"""Pipeline capture: CaptureSource → tshark → bản ghi raw → Kafka (packets_raw).

Service này chỉ làm việc nhẹ (tách trường, đóng gói); chuẩn hóa do service packet-normalizer đảm nhận.
"""
import asyncio
import json
import logging
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum

from capture.sources import CaptureSource
from capture.tshark import TsharkProcess, build_command, parse_line

logger = logging.getLogger(__name__)

RAW_SCHEMA = "raw.v1"


class CaptureState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    RESTARTING = "restarting"   # live source: tshark dừng bất thường, đang chờ khởi động lại
    STOPPED = "stopped"
    COMPLETED = "completed"     # pcap source: đã đọc hết file
    ERROR = "error"


@dataclass
class CaptureStats:
    packets_read: int = 0
    packets_published: int = 0   # Kafka đã xác nhận
    parse_errors: int = 0
    buffer_full_drops: int = 0   # bộ đệm producer đầy (Kafka chậm/không kết nối được)
    delivery_errors: int = 0
    tshark_restarts: int = 0


class CapturePipeline:

    def __init__(
        self,
        producer,
        topic: str,
        sensor_id: str,
        tshark_path: str = "tshark",
        display_filter: str = "",
        restart_backoff_max: float = 30.0,
    ):
        self.producer = producer
        self.topic = topic
        self.sensor_id = sensor_id
        self.tshark_path = tshark_path
        self.display_filter = display_filter
        self.restart_backoff_max = restart_backoff_max

        self.state = CaptureState.IDLE
        self.source: CaptureSource | None = None
        self.stats = CaptureStats()
        self.started_at: float | None = None
        self.finished_at: float | None = None
        self.last_packet_at: float | None = None
        self.last_error: str | None = None

        self._task: asyncio.Task | None = None
        self._tshark: TsharkProcess | None = None
        self._stop_event = asyncio.Event()

    @property
    def is_active(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self, source: CaptureSource) -> None:
        if self.is_active:
            raise RuntimeError("Capture is already running")
        self.source = source
        self.stats = CaptureStats()
        self.started_at = time.time()
        self.finished_at = None
        self.last_packet_at = None
        self.last_error = None
        self.state = CaptureState.RUNNING
        self._stop_event.clear()
        self._task = asyncio.create_task(self._supervise(), name="capture-pipeline")

    async def stop(self) -> None:
        if not self.is_active:
            return
        self._stop_event.set()
        if self._tshark:
            await self._tshark.stop()
        await self._task

    async def wait(self) -> None:
        """Chờ pipeline kết thúc (dùng cho nguồn pcap và test)."""
        if self._task:
            await self._task

    def status(self) -> dict:
        now = time.time()
        uptime = ((self.finished_at or now) - self.started_at) if self.started_at else 0.0
        return {
            "state": self.state.value,
            "sensor_id": self.sensor_id,
            "source": self.source.describe() if self.source else None,
            "kafka_topic": self.topic,
            "started_at": _iso(self.started_at),
            "finished_at": _iso(self.finished_at),
            "last_packet_at": _iso(self.last_packet_at),
            "uptime_seconds": round(uptime, 1),
            "packets_per_second": round(self.stats.packets_read / uptime, 1) if uptime > 0 else 0.0,
            **asdict(self.stats),
            "last_error": self.last_error,
            "tshark_stderr": list(self._tshark.stderr_tail) if self._tshark else [],
        }

    # ---------- internals ----------

    async def _supervise(self) -> None:
        poller = asyncio.create_task(self._poll_loop())
        backoff = 1.0
        try:
            while not self._stop_event.is_set():
                run_started = time.monotonic()
                returncode = None
                try:
                    returncode = await self._run_once()
                except Exception as e:
                    logger.exception("Capture run failed")
                    self.last_error = str(e)

                if self._stop_event.is_set():
                    break

                if returncode not in (0, None):
                    tail = self._tshark.stderr_tail[-1] if self._tshark and self._tshark.stderr_tail else ""
                    self.last_error = f"tshark exited with code {returncode}: {tail}"

                if not self.source.is_live:
                    self.state = CaptureState.COMPLETED if returncode == 0 else CaptureState.ERROR
                    break

                # Nguồn live mà tshark dừng => khởi động lại với exponential backoff
                if time.monotonic() - run_started > 60:
                    backoff = 1.0
                self.stats.tshark_restarts += 1
                self.state = CaptureState.RESTARTING
                logger.warning(f"Capture stopped unexpectedly ({self.last_error}), restarting in {backoff:.0f}s")
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=backoff)
                except TimeoutError:
                    pass
                backoff = min(backoff * 2, self.restart_backoff_max)

            if self._stop_event.is_set():
                self.state = CaptureState.STOPPED
        finally:
            poller.cancel()
            self.finished_at = time.time()
            remaining = await asyncio.to_thread(self.producer.flush, 10)
            if remaining:
                logger.warning(f"{remaining} messages were not delivered to Kafka before timeout")
            logger.info(f"Capture finished: state={self.state.value}, stats={asdict(self.stats)}")

    async def _run_once(self) -> int:
        cmd = build_command(self.tshark_path, self.source.tshark_input_args(), self.display_filter)
        tshark = TsharkProcess(cmd)
        self._tshark = tshark
        await tshark.start()
        if self._stop_event.is_set():
            await tshark.stop()
        self.state = CaptureState.RUNNING

        try:
            count = 0
            async for line in tshark.lines():
                self._handle_line(line)
                count += 1
                if count % 500 == 0:
                    # Phục vụ delivery callback và nhường event loop khi đọc file pcap tốc độ cao
                    self.producer.poll(0)
                    await asyncio.sleep(0)
        finally:
            await tshark.stop()

        returncode = await tshark.wait()
        self.producer.poll(0)
        return returncode

    def _handle_line(self, line: str) -> None:
        fields = parse_line(line)
        if fields is None:
            self.stats.parse_errors += 1
            return

        now = time.time()
        self.stats.packets_read += 1
        self.last_packet_at = now

        message = {
            "schema": RAW_SCHEMA,
            "sensor_id": self.sensor_id,
            "source": self.source.name,
            "iface": self.source.interface,
            "captured_at": now,
            "fields": fields,
        }
        # Key theo IP nguồn: gói của cùng một thiết bị vào cùng partition, giữ thứ tự
        key = fields.get("ip.src") or fields.get("ipv6.src") or fields.get("eth.src") or ""
        value = json.dumps(message, separators=(",", ":")).encode()

        try:
            self.producer.produce(self.topic, value=value, key=key.encode(), on_delivery=self._on_delivery)
        except BufferError:
            self.producer.poll(0.05)
            try:
                self.producer.produce(self.topic, value=value, key=key.encode(), on_delivery=self._on_delivery)
            except BufferError:
                self.stats.buffer_full_drops += 1

    def _on_delivery(self, err, msg) -> None:
        if err is None:
            self.stats.packets_published += 1
            return
        self.stats.delivery_errors += 1
        if self.stats.delivery_errors % 1000 == 1:
            logger.warning(f"Kafka delivery failed ({self.stats.delivery_errors} total): {err}")

    async def _poll_loop(self) -> None:
        while True:
            self.producer.poll(0)
            await asyncio.sleep(1)


def _iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts).isoformat(timespec="seconds") if ts else None
