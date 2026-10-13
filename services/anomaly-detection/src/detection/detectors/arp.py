"""ARP spoofing: một IP được khai báo bởi MAC khác với MAC đã biết. Chạy theo từng gói, không chờ cửa sổ."""
from detection.detectors.base import Finding
from detection.state import StateStore

NAMESPACE = "arp_binding"


class ArpSpoofDetector:
    name = "arp.spoofing"

    def __init__(self, cfg: dict, store: StateStore):
        self.ttl = cfg["binding_ttl_seconds"]
        self.score = cfg["score"]
        self.store = store

    def observe(self, packet: dict) -> Finding | None:
        if packet.get("arp_opcode") not in (1, 2):
            return None
        ip, mac, ts = packet.get("arp_sender_ip"), packet.get("arp_sender_mac"), packet.get("ts")
        # 0.0.0.0 là ARP probe (thiết bị đang kiểm tra IP trước khi dùng), không phải khai báo
        if not ip or not mac or ip == "0.0.0.0" or ts is None:
            return None

        previous = self.store.get(NAMESPACE, ip)
        self.store.set(NAMESPACE, ip, (mac, ts))
        if not previous:
            return None
        old_mac, old_ts = previous
        if old_mac == mac or ts - old_ts > self.ttl:
            return None

        return Finding(
            self.name, "arp_spoofing", self.score,
            f"IP {ip} is now claimed by {mac}, previously {old_mac} ({ts - old_ts:.0f}s ago)",
            {"ip": ip, "new_mac": mac, "previous_mac": old_mac, "seconds_since_previous": round(ts - old_ts, 1)},
            entity_ip=ip, entity_mac=mac, ts=ts, sensor_id=packet.get("sensor_id"),
        )
