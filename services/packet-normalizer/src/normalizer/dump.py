"""Chuẩn hóa raw record (raw.v1, JSONL) từ stdin, in NormalizedPacket (JSONL) ra stdout. Không cần Kafka.

Dùng cùng `capture.dump` của packet-capture để xem dữ liệu, hoặc sinh fixture cho service phía sau:
    python -m capture.dump file.pcap | python -m normalizer.dump > normalized.jsonl
"""
import argparse
import json
import sys

from common.config import settings
from normalizer.normalizer import NormalizationError, PacketNormalizer


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lan-cidrs", default=",".join(settings.LAN_CIDRS),
                        help="dải mạng LAN, cách nhau bằng dấu phẩy (mặc định: LAN_CIDRS)")
    args = parser.parse_args()

    normalizer = PacketNormalizer([c.strip() for c in args.lan_cidrs.split(",") if c.strip()])
    invalid = 0
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            packet = normalizer.normalize(json.loads(line))
        except (ValueError, NormalizationError):
            invalid += 1
            continue
        sys.stdout.write(packet.model_dump_json(exclude_none=True) + "\n")
    if invalid:
        print(f"Skipped {invalid} invalid records", file=sys.stderr)


if __name__ == "__main__":
    main()
