"""Test end-to-end không cần Kafka: pcap → tshark → CapturePipeline → FakeProducer."""
import asyncio
import json

from capture.pipeline import RAW_SCHEMA, CapturePipeline, CaptureState
from capture.sources import PcapFileSource
from conftest import MAC_CLIENT, requires_tshark


@requires_tshark
def test_pcap_to_raw_records(sample_pcap, fake_producer):
    async def run():
        pipeline = CapturePipeline(fake_producer, topic="packets_raw", sensor_id="test-sensor")
        await pipeline.start(PcapFileSource(sample_pcap))
        await pipeline.wait()
        return pipeline.status()

    status = asyncio.run(run())
    assert status["state"] == CaptureState.COMPLETED.value
    assert status["packets_read"] == status["packets_published"] == 7
    assert status["parse_errors"] == 0

    assert {topic for topic, _, _ in fake_producer.messages} == {"packets_raw"}
    assert fake_producer.messages[0][1] == b"192.168.1.10"   # key = IP nguồn
    assert fake_producer.messages[4][1] == b"fe80::1"        # IPv6
    assert fake_producer.messages[6][1] == MAC_CLIENT.encode()  # ARP: không có IP → MAC

    raws = [json.loads(value) for _, _, value in fake_producer.messages]
    assert all(r["schema"] == RAW_SCHEMA and r["sensor_id"] == "test-sensor" and r["source"] == "pcap" for r in raws)
    dns_q, dns_r, syn, http, ipv6, icmp, arp = [r["fields"] for r in raws]

    assert dns_q["frame.time_epoch"].startswith("1700000000")
    assert dns_q["dns.qry.name"] == "example.com" and dns_q["udp.dstport"] == "53"
    assert dns_r["dns.flags.response"] == "True"
    assert syn["tcp.flags"] == "0x0002"
    assert http["http.host"] == "example.com" and http["http.request.method"] == "GET"
    assert ipv6["ipv6.hlim"] == "255" and "ip.src" not in ipv6
    assert icmp["icmp.type"] == "8"
    assert arp["_ws.col.protocol"] == "ARP" and arp["eth.src"] == MAC_CLIENT
    assert (arp["arp.src.proto_ipv4"], arp["arp.src.hw_mac"]) == ("192.168.1.10", MAC_CLIENT)
    assert arp["arp.dst.proto_ipv4"] == "192.168.1.1"
