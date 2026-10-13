"""Sinh pcap chứa traffic bình thường + các kịch bản tấn công, mỗi kịch bản từ một thiết bị riêng.

Mọi gói nằm trong cùng một cửa sổ 60s (bắt đầu tại BASE_TS).
Sinh lại fixture tests/fixtures/attack_scenarios.normalized.jsonl.gz: xem README, mục "Dữ liệu test".

Chạy:  python tests/attack_traffic.py /tmp/attacks.pcap
"""
import logging
import random
import string
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

BASE_TS = 1_700_000_040          # chia hết cho 60: đầu một cửa sổ
DNS_SERVER = "8.8.8.8"
GATEWAY_IP, GATEWAY_MAC = "192.168.1.1", "aa:bb:cc:00:00:fe"

# Thiết bị -> kịch bản (đối chiếu trong test_scenarios.py)
NORMAL = "192.168.1.10"
PORT_SCANNER = "192.168.1.66"
SWEEPER = "192.168.1.67"
FLOODER = "192.168.1.68"
BRUTE_FORCER = "192.168.1.69"
DNS_TUNNELER = "192.168.1.70"
DGA_INFECTED = "192.168.1.71"
SCAN_VICTIM = "192.168.1.30"       # bị IP bên ngoài quét
EXTERNAL_SCANNER = "203.0.113.50"
ARP_SPOOFER_MAC = "de:ad:be:ef:00:01"

SCAN_TARGET = "192.168.1.20"
SSH_SERVER = "192.168.1.5"
WEB_SERVER = "93.184.216.34"


def mac_of(ip: str) -> str:
    return "aa:bb:cc:00:01:%02x" % int(ip.rsplit(".", 1)[1])


def build_packets(seed: int = 7) -> list:
    from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether

    rng = random.Random(seed)
    packets = []

    def at(offset: float, pkt):
        pkt.time = BASE_TS + offset
        packets.append(pkt)

    def eth(src_ip, dst_ip):
        return Ether(src=mac_of(src_ip), dst=mac_of(dst_ip))

    def rand_label(n, alphabet=string.ascii_lowercase + "234567"):
        return "".join(rng.choice(alphabet) for _ in range(n))

    # --- Bình thường: vài DNS query, bắt tay TCP đầy đủ, ping 1 máy ---
    for i, (domain, server) in enumerate([("example.com", WEB_SERVER), ("www.wikipedia.org", "208.80.154.224"),
                                          ("api.github.com", "140.82.112.6")]):
        t = 1 + i * 5
        at(t, eth(NORMAL, GATEWAY_IP) / IP(src=NORMAL, dst=DNS_SERVER) / UDP(sport=50000 + i, dport=53)
           / DNS(rd=1, qd=DNSQR(qname=domain)))
        at(t + 0.05, eth(GATEWAY_IP, NORMAL) / IP(src=DNS_SERVER, dst=NORMAL) / UDP(sport=53, dport=50000 + i)
           / DNS(qr=1, qd=DNSQR(qname=domain)))
        sport = 41000 + i
        at(t + 0.1, eth(NORMAL, GATEWAY_IP) / IP(src=NORMAL, dst=server) / TCP(sport=sport, dport=443, flags="S"))
        at(t + 0.15, eth(GATEWAY_IP, NORMAL) / IP(src=server, dst=NORMAL) / TCP(sport=443, dport=sport, flags="SA"))
        at(t + 0.2, eth(NORMAL, GATEWAY_IP) / IP(src=NORMAL, dst=server) / TCP(sport=sport, dport=443, flags="A"))
        for k in range(5):
            at(t + 0.3 + k * 0.1, eth(GATEWAY_IP, NORMAL) / IP(src=server, dst=NORMAL)
               / TCP(sport=443, dport=sport, flags="PA") / (b"x" * 1200))
    at(20, eth(NORMAL, GATEWAY_IP) / IP(src=NORMAL, dst=GATEWAY_IP) / ICMP(type=8))
    at(20.01, eth(GATEWAY_IP, NORMAL) / IP(src=GATEWAY_IP, dst=NORMAL) / ICMP(type=0))

    # --- Port scan: SYN tới 150 port của SCAN_TARGET, máy đích trả RST ---
    for port in range(1, 151):
        t = 2 + port * 0.1
        at(t, eth(PORT_SCANNER, SCAN_TARGET) / IP(src=PORT_SCANNER, dst=SCAN_TARGET) / TCP(sport=60000, dport=port, flags="S"))
        at(t + 0.01, eth(SCAN_TARGET, PORT_SCANNER) / IP(src=SCAN_TARGET, dst=PORT_SCANNER)
           / TCP(sport=port, dport=60000, flags="RA"))

    # --- Host sweep: SYN tới port 445 của 60 máy, không máy nào trả lời ---
    for i in range(60):
        dst = f"192.168.1.{100 + i}"
        at(3 + i * 0.5, eth(SWEEPER, dst) / IP(src=SWEEPER, dst=dst) / TCP(sport=61000 + i, dport=445, flags="S"))

    # --- SYN flood: 250 SYN tới web server, không bắt tay (test dùng ngưỡng 3 SYN/s) ---
    for i in range(250):
        at(5 + i * 0.1, eth(FLOODER, GATEWAY_IP) / IP(src=FLOODER, dst=WEB_SERVER)
           / TCP(sport=rng.randint(1024, 65535), dport=80, flags="S"))

    # --- Brute force: 30 lần kết nối SSH tới cùng một máy, server có trả lời ---
    for i in range(30):
        t = 4 + i * 1.2
        sport = 62000 + i
        at(t, eth(BRUTE_FORCER, SSH_SERVER) / IP(src=BRUTE_FORCER, dst=SSH_SERVER) / TCP(sport=sport, dport=22, flags="S"))
        at(t + 0.01, eth(SSH_SERVER, BRUTE_FORCER) / IP(src=SSH_SERVER, dst=BRUTE_FORCER)
           / TCP(sport=22, dport=sport, flags="SA"))

    # --- DNS tunneling: 80 query với subdomain ngẫu nhiên dài dưới một domain ---
    for i in range(80):
        qname = f"{rand_label(45)}.t.evil-tunnel.com"
        at(6 + i * 0.5, eth(DNS_TUNNELER, GATEWAY_IP) / IP(src=DNS_TUNNELER, dst=DNS_SERVER)
           / UDP(sport=53000 + i, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT")))

    # --- DGA: 40 domain ngẫu nhiên, đều NXDOMAIN ---
    for i in range(40):
        qname = f"{rand_label(14, string.ascii_lowercase)}.com"
        t = 7 + i * 1.0
        at(t, eth(DGA_INFECTED, GATEWAY_IP) / IP(src=DGA_INFECTED, dst=DNS_SERVER) / UDP(sport=54000 + i, dport=53)
           / DNS(rd=1, qd=DNSQR(qname=qname)))
        at(t + 0.05, eth(GATEWAY_IP, DGA_INFECTED) / IP(src=DNS_SERVER, dst=DGA_INFECTED) / UDP(sport=53, dport=54000 + i)
           / DNS(qr=1, rcode=3, qd=DNSQR(qname=qname)))

    # --- Inbound scan: IP bên ngoài dò 80 port của SCAN_VICTIM ---
    for port in range(1, 81):
        at(8 + port * 0.2, Ether(src=GATEWAY_MAC, dst=mac_of(SCAN_VICTIM)) / IP(src=EXTERNAL_SCANNER, dst=SCAN_VICTIM)
           / TCP(sport=33333, dport=port, flags="S"))

    # --- ARP spoofing: gateway khai báo MAC thật, sau đó máy khác nhận là gateway ---
    at(1, Ether(src=GATEWAY_MAC, dst="ff:ff:ff:ff:ff:ff")
       / ARP(op=2, hwsrc=GATEWAY_MAC, psrc=GATEWAY_IP, hwdst="ff:ff:ff:ff:ff:ff", pdst=GATEWAY_IP))
    at(30, Ether(src=ARP_SPOOFER_MAC, dst=mac_of(NORMAL))
       / ARP(op=2, hwsrc=ARP_SPOOFER_MAC, psrc=GATEWAY_IP, hwdst=mac_of(NORMAL), pdst=NORMAL))

    packets.sort(key=lambda p: p.time)
    return packets


def write_attack_pcap(path: str) -> str:
    from scapy.all import wrpcap
    wrpcap(path, build_packets())
    return path


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python tests/attack_traffic.py <output.pcap>")
    print(write_attack_pcap(sys.argv[1]))
