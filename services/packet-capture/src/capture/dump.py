"""Replay file pcap và in raw record (raw.v1) ra stdout dạng JSONL, không cần Kafka.

Dùng để xem dữ liệu capture tạo ra, hoặc sinh fixture cho test của packet-normalizer:
    python -m capture.dump /path/file.pcap > raw.jsonl
"""
import argparse
import asyncio
import sys

from capture.pipeline import CapturePipeline, CaptureState
from capture.sources import PcapFileSource
from common.config import settings


class StdoutProducer:
    """Thay Kafka producer: ghi mỗi message thành một dòng trên stdout."""

    def produce(self, topic, value=None, key=None, on_delivery=None):
        sys.stdout.write(value.decode() + "\n")
        if on_delivery:
            on_delivery(None, None)

    def poll(self, timeout=0):
        return 0

    def flush(self, timeout=None):
        sys.stdout.flush()
        return 0


async def dump(pcap_file: str, sensor_id: str) -> CaptureState:
    source = PcapFileSource(pcap_file)
    source.validate()
    pipeline = CapturePipeline(StdoutProducer(), topic="stdout", sensor_id=sensor_id, tshark_path=settings.TSHARK_PATH)
    await pipeline.start(source)
    await pipeline.wait()
    return pipeline.state


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pcap_file")
    parser.add_argument("--sensor-id", default=settings.SENSOR_ID)
    args = parser.parse_args()

    try:
        state = asyncio.run(dump(args.pcap_file, args.sensor_id))
    except ValueError as e:
        parser.error(str(e))
    sys.exit(0 if state == CaptureState.COMPLETED else 1)


if __name__ == "__main__":
    main()
