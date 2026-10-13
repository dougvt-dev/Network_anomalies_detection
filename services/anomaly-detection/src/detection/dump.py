"""Chạy phát hiện trên gói tin chuẩn hóa (JSONL) từ stdin, in cảnh báo (JSONL, định dạng topic anomalies) ra stdout.

Không cần Kafka. Dùng để thử ngưỡng trên dữ liệu có sẵn, hoặc sinh fixture cho service phía sau:
    zcat tests/fixtures/attack_scenarios.normalized.jsonl.gz | python -m detection.dump > anomalies.jsonl
"""
import argparse
import json
import sys

from common.config import settings
from detection.engine import DetectionEngine, load_detection_config


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=settings.DETECTION_CONFIG, help="file ngưỡng (mặc định: DETECTION_CONFIG)")
    args = parser.parse_args()

    engine = DetectionEngine(load_detection_config(args.config))
    invalid = 0

    def emit(output):
        for anomaly in output.anomalies:
            sys.stdout.write(anomaly.model_dump_json(exclude_none=True) + "\n")

    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            packet = json.loads(line)
        except ValueError:
            packet = None
        if not isinstance(packet, dict):
            invalid += 1
            continue
        engine.ingest(packet)
        emit(engine.advance())
    emit(engine.flush())

    print(f"packets={engine.stats['packets']} windows={engine.stats['windows']} "
          f"anomalies={engine.stats['anomalies']} invalid={invalid}", file=sys.stderr)


if __name__ == "__main__":
    main()
