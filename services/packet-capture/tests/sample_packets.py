"""Bộ 7 gói mẫu dùng chung cho test packet-capture và fixture của packet-normalizer.

Gồm: DNS query/response, TCP SYN, HTTP GET, IPv6/UDP, ICMP echo (nội bộ), ARP.
Chạy trực tiếp để ghi ra file pcap:  python tests/sample_packets.py /tmp/sample.pcap
"""
import logging
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

MAC_CLIENT = "aa:bb:cc:00:00:01"
MAC_GATEWAY = "aa:bb:cc:00:00:fe"


def write_sample_pcap(path: str) -> str:
    from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, IPv6, Raw, wrpcap

    eth_out = Ether(src=MAC_CLIENT, dst=MAC_GATEWAY)
    eth_in = Ether(src=MAC_GATEWAY, dst=MAC_CLIENT)
    packets = [
        eth_out / IP(src="192.168.1.10", dst="8.8.8.8", ttl=64) / UDP(sport=5353, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com")),
        eth_in / IP(src="8.8.8.8", dst="192.168.1.10", ttl=117) / UDP(sport=53, dport=5353)
        / DNS(qr=1, qd=DNSQR(qname="example.com")),
        eth_out / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=40000, dport=80, flags="S"),
        eth_out / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=40000, dport=80, flags="PA")
        / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        eth_out / IPv6(src="fe80::1", dst="2001:4860:4860::8888", hlim=255) / UDP(sport=1234, dport=443),
        eth_out / IP(src="192.168.1.10", dst="192.168.1.20") / ICMP(type=8),
        Ether(src=MAC_CLIENT, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=MAC_CLIENT, psrc="192.168.1.10", pdst="192.168.1.1"),
    ]
    for i, packet in enumerate(packets):
        packet.time = 1_700_000_000 + i * 0.5

    wrpcap(path, packets)
    return path


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python tests/sample_packets.py <output.pcap>")
    print(write_sample_pcap(sys.argv[1]))
