# Network AI Agent Monitoring System
## 📌 **Tóm Tắt Dự Án**
 
### **Mục Tiêu**
Xây dựng hệ thống **AI Agent giám sát mạng real-time** dùng microservice, có khả năng:
- ✅ Bắt toàn bộ traffic từ interface `eth0`
- ✅ Phát hiện bất thường tự động (ML)
- ✅ Suy luận thông minh (ReAct + LLM)
- ✅ Thực thi hành động tự động (Block IP, Alert, etc.)
- ✅ Lưu trữ & phân tích dữ liệu
### **Kết Quả Cuối Cùng**
```
┌─────────────┐
│   eth0      │  Raw Traffic
└──────┬──────┘
       │
       ▼
┌──────────────────────────────────────────┐
│   Microservice Architecture              │
│  - 8 Services + Infrastructure           │
│  - Real-time Event Processing            │
│  - AI-powered Decision Making            │
└──────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────┐
│  Real-time Monitoring Dashboard     │
│  - Web UI (React)                   │
│  - Grafana (Metrics)                │
│  - Alert System                     │
└─────────────────────────────────────┘
```
 
---
## 1️⃣ High-Level System Overview
 
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         NETWORK AI AGENT SYSTEM                             │
└─────────────────────────────────────────────────────────────────────────────┘
 
┌──────────────────────┐
│    eth0 Interface    │  (Raw network traffic)
│   10,000+ pkt/sec    │
└──────────┬───────────┘
           │
           │ TShark
           ▼
┌──────────────────────────────────────────────────────────────┐
│         PACKET CAPTURE SERVICE (Port 5001)                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ - Parse packets to JSON                             │    │
│  │ - Quick ML filter (Isolation Forest)                │    │
│  │ - Drop 95% normal packets                           │    │
│  │ - Send 5% suspicious → Kafka                        │    │
│  └─────────────────────────────────────────────────────┘    │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     │ Kafka topic: "packets_raw"
                     ▼
┌──────────────────────────────────────────────────────────────┐
│      ANOMALY DETECTION SERVICE (Port 5002)                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ - Isolation Forest model (sklearn)                  │    │
│  │ - Score: 0.0 ~ 1.0                                 │    │
│  │ - Send anomalies (score > 0.7) → Kafka            │    │
│  └─────────────────────────────────────────────────────┘    │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     │ Kafka topic: "anomalies"
                     ▼
         ┌───────────────────────┐
         │  AI AGENT SERVICE     │  (Port 5003)
         │                       │
         │   ╔═════════════════╗ │
         │   ║  ReAct Loop     ║ │
         │   ╠═════════════════╣ │
         │   ║ 1. Receive      ║ │
         │   ║ 2. Think        ║ │
         │   ║ 3. Act (→ KB)   ║ │
         │   ║ 4. Observe      ║ │
         │   ║ 5. Decide       ║ │
         │   ╚═════════════════╝ │
         │                       │
         │   LLM: Mistral-7B    │
         └───────────┬───────────┘
                     │
        ┌────────────┴────────────┐
        │                         │
        ▼                         ▼
    ┌─────────────┐      ┌──────────────────┐
    │ Knowledge   │      │  Log Storage     │
    │   Base      │      │  (Historical)    │
    │ (ChromaDB)  │      │  (Query previous)│
    │  CVE, TTI   │      │  anomalies)      │
    └─────────────┘      └──────────────────┘
        │                         │
        └────────────┬────────────┘
                     │
                     │ Kafka topic: "decisions"
                     ▼
┌──────────────────────────────────────────────────────────────┐
│        ACTION SERVICE (Port 5006)                            │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Executes decisions:                                 │    │
│  │ - Block IP (iptables)                              │    │
│  │ - Alert (Slack/Email)                              │    │
│  │ - Log (ClickHouse)                                 │    │
│  │ - Monitor (increase level)                         │    │
│  └─────────────────────────────────────────────────────┘    │
└────────────────────┬─────────────────────────────────────────┘
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
    ┌────────┐  ┌───────┐  ┌──────────┐
    │Firewall│  │Alerts │  │Database  │
    │(Linux) │  │(Slack)│  │(Storage) │
    └────────┘  └───────┘  └──────────┘
```
 
---
 
## 2️⃣ Detailed Service Communication
 
```
                    ┌─────────────────┐
                    │  API Gateway    │
                    │  (Port 8000)    │
                    └────────┬────────┘
                             │
                ┌────────────┼────────────┐
                │            │            │
        ┌───────▼───┐ ┌──────▼──┐ ┌─────▼──────┐
        │ Packet    │ │ AI      │ │ Log        │
        │ Service   │ │ Agent   │ │ Storage    │
        │ (5001)    │ │ (5003)  │ │ (5005)     │
        └───────┬───┘ └──────┬──┘ └─────┬──────┘
                │            │          │
                │    ┌───────┼──────┐   │
                │    │       │      │   │
                ▼    ▼       ▼      ▼   ▼
        ┌──────────────────────────────────────┐
        │      Apache Kafka (Event Bus)        │
        │  ┌─────────────────────────────┐    │
        │  │ Topic: packets_raw (5%)     │    │
        │  │ Topic: anomalies            │    │
        │  │ Topic: decisions            │    │
        │  │ Topic: alerts               │    │
        │  │ Topic: logs                 │    │
        │  └─────────────────────────────┘    │
        └──────────────────────────────────────┘
                │    │    │    │
                │    │    │    └──────────────┐
                │    │    │                   │
                ▼    ▼    ▼                   ▼
        ┌──────────────────┐         ┌──────────────┐
        │ Data Storage     │         │ Monitoring   │
        ├──────────────────┤         ├──────────────┤
        │ - InfluxDB       │         │ - Prometheus │
        │ - Elasticsearch  │         │ - Grafana    │
        │ - ClickHouse     │         │ - AlertMgr   │
        └──────────────────┘         └──────────────┘
```
 
---
 
## 3️⃣ Data Flow - Detailed
 
```
┌────────────────────────────────────────────────────────────────────────┐
│                         PACKET LIFECYCLE                               │
└────────────────────────────────────────────────────────────────────────┘
 
T=0ms
┌─────────────────┐
│ Raw eth0 packet │ (e.g., TCP 192.168.1.100:52341 → 8.8.8.8:443)
└────────┬────────┘
         │
         │ tshark -i eth0 -T json
         │ 1ms processing
         ▼
T=1ms
┌──────────────────────────┐
│ Structured JSON packet   │
│ {                        │
│   "src_ip": "192.168...", │
│   "dst_ip": "8.8.8.8",   │
│   "dst_port": 443,       │
│   "protocol": "TCP",     │
│   "size": 1234,          │
│   "flags": [...],        │
│   "timestamp": "..."     │
│ }                        │
└──────────┬───────────────┘
           │
           │ Kafka: packets_raw
           │ 1ms latency
           ▼
T=2ms
┌─────────────────────────┐
│ Anomaly Detector (ML)   │
│                         │
│ Features extracted:     │
│ - Packet frequency      │
│ - Packet size dist      │
│ - Port pattern          │
│ - Time-series pattern   │
│                         │
│ Model: Isolation Forest │
│ Score = 0.45 (Normal!)  │
└──────────┬──────────────┘
           │
        95% │ (Normal packets - DROPPED)
           │
           │ 5% (Anomalous - score > 0.7)
           │ 3ms processing
           ▼
T=5ms
┌──────────────────────────┐
│ Anomaly: DETECTED        │
│ {                        │
│   "score": 0.82,         │
│   "reason": "Port spike",│
│   "packet": {...},       │
│   "severity": "HIGH"     │
│ }                        │
└──────────┬───────────────┘
           │
           │ Kafka: anomalies
           │ 1ms latency
           ▼
T=6ms
┌──────────────────────────────────────┐
│ AI Agent - ReAct Loop                │
│                                      │
│ THOUGHT:                             │
│ "Weird port 443 spike from 192.168"  │
│                                      │
│ ACTION 1: Query Knowledge Base       │
│ KB: "No known CVE for this pattern"  │
│                                      │
│ ACTION 2: Query historical logs      │
│ Logs: "Same IP does this daily 10am" │
│                                      │
│ OBSERVATION:                         │
│ "Normal business traffic (cloud backup)"│
│                                      │
│ DECISION:                            │
│ "ALLOW - Normal behavior"            │
│                                      │
│ Processing: 2ms (LLM inference)      │
└──────────┬───────────────────────────┘
           │
           │ Kafka: decisions
           │ 1ms latency
           ▼
T=10ms
┌──────────────────────────┐
│ Action Service           │
│                          │
│ Decision: ALLOW          │
│ Action: LOG ONLY         │
│                          │
│ - Store to ClickHouse    │
│ - Update Prometheus      │
│ - Return to API          │
│                          │
│ Processing: 1ms          │
└──────────┬───────────────┘
           │
      ┌────┴─────┬─────────┬──────────┐
      │           │         │          │
      ▼           ▼         ▼          ▼
  ┌────────┐  ┌─────┐  ┌────────┐  ┌──────┐
  │Database│  │Cache│  │Logs    │  │API   │
  │Storage │  │Redis│  │Store   │  │Return│
  └────────┘  └─────┘  └────────┘  └──────┘
 
TOTAL LATENCY: ~10ms (acceptable)
```
 
---
 
## 4️⃣ Service Dependencies
 
```
                        ┌─────────────────┐
                        │  API Gateway    │
                        │  (5000)         │
                        └────────┬────────┘
                                 │
                ┌────────────────┼─────────────┐
                │                │             │
        ┌───────▼────┐   ┌──────▼────┐  ┌────▼──────┐
        │  Packet    │   │   AI      │  │  Log      │
        │  Capture   │   │  Agent    │  │ Storage   │
        │  (5001)    │   │  (5003)   │  │  (5005)   │
        └───────┬────┘   └──────┬────┘  └────┬──────┘
                │               │             │
                ├──depends on──→ Kafka        │
                │               ├─depends on→ InfluxDB
                │               │             ├─depends on→ Elasticsearch
                │               │             └─depends on→ ClickHouse
                │    ┌──────────▼──────────┐
                │    │  Knowledge Base    │
                │    │  (5004)            │
                │    └──────────┬─────────┘
                │               │
                │    ┌──────────▼──────────┐
                │    │  Redis (Cache)     │
                │    └────────────────────┘
                │
        ┌───────▼────┐
        │  Anomaly   │
        │ Detection  │
        │  (5002)    │
        └───────┬────┘
                │
        ┌───────▼────┐
        │   Action   │
        │  Service   │
        │  (5006)    │
        └────────────┘
```
 
---
 
## 5️⃣ Docker Container Architecture
 
```
┌────────────────────────────────────────────────────────┐
│                  docker-compose network                │
└────────────────────────────────────────────────────────┘
 
┌─────────────────────────────────────────────────────┐
│ External (Host)                                     │
│                                                     │
│  eth0 ◄────── network_ai_agent container ────► │
│              (host network mode)                   │
└─────────────────────────────────────────────────────┘
 
        │
        ▼ (Shared Network)
 
  Container Network: 172.18.0.0/16
 
┌───────────────────────────┬──────────────────────────────┐
│   Infrastructure          │   Microservices             │
│                           │                             │
│ ┌─────────────────────┐   │ ┌───────────────────────┐   │
│ │ Zookeeper           │   │ │ Packet Capture        │   │
│ │ Port: 2181          │   │ │ Port: 5001           │   │
│ │ Container IP: ...   │   │ │ Container IP: ...    │   │
│ └─────────────────────┘   │ └───────────────────────┘   │
│                           │                             │
│ ┌─────────────────────┐   │ ┌───────────────────────┐   │
│ │ Kafka               │   │ │ Anomaly Detection     │   │
│ │ Port: 9092 (→29092) │   │ │ Port: 5002           │   │
│ │ Container IP: ...   │   │ │ Container IP: ...    │   │
│ └─────────────────────┘   │ └───────────────────────┘   │
│                           │                             │
│ ┌─────────────────────┐   │ ┌───────────────────────┐   │
│ │ Redis               │   │ │ AI Agent              │   │
│ │ Port: 6379          │   │ │ Port: 5003           │   │
│ │ Container IP: ...   │   │ │ Container IP: ...    │   │
│ └─────────────────────┘   │ └───────────────────────┘   │
│                           │                             │
│ ┌─────────────────────┐   │ ┌───────────────────────┐   │
│ │ InfluxDB            │   │ │ Knowledge Base        │   │
│ │ Port: 8086          │   │ │ Port: 5004           │   │
│ │ Container IP: ...   │   │ │ Container IP: ...    │   │
│ └─────────────────────┘   │ └───────────────────────┘   │
│                           │                             │
│ ┌─────────────────────┐   │ ┌───────────────────────┐   │
│ │ Elasticsearch       │   │ │ Log Storage           │   │
│ │ Port: 9200          │   │ │ Port: 5005           │   │
│ │ Container IP: ...   │   │ │ Container IP: ...    │   │
│ └─────────────────────┘   │ └───────────────────────┘   │
│                           │                             │
│ ┌─────────────────────┐   │ ┌───────────────────────┐   │
│ │ ClickHouse          │   │ │ Action Service        │   │
│ │ Port: 8123, 9000    │   │ │ Port: 5006           │   │
│ │ Container IP: ...   │   │ │ Container IP: ...    │   │
│ └─────────────────────┘   │ └───────────────────────┘   │
│                           │                             │
│ ┌─────────────────────┐   │ ┌───────────────────────┐   │
│ │ Prometheus          │   │ │ Metrics Monitor       │   │
│ │ Port: 9090          │   │ │ Port: 5007           │   │
│ │ Container IP: ...   │   │ │ Container IP: ...    │   │
│ └─────────────────────┘   │ └───────────────────────┘   │
│                           │                             │
│ ┌─────────────────────┐   │ ┌───────────────────────┐   │
│ │ Grafana             │   │ │ API Gateway           │   │
│ │ Port: 3000          │   │ │ Port: 8000           │   │
│ │ Container IP: ...   │   │ │ Container IP: ...    │   │
│ └─────────────────────┘   │ └───────────────────────┘   │
│                           │                             │
│ ┌─────────────────────┐   │                             │
│ │ Kafka UI            │   │                             │
│ │ Port: 8080          │   │                             │
│ │ Container IP: ...   │   │                             │
│ └─────────────────────┘   │                             │
└───────────────────────────┴──────────────────────────────┘
```
 
---
 
## 6️⃣ ReAct Loop - AI Agent Flow
 
```
┌─────────────────────────────────────────────────────────┐
│              AI AGENT - ReAct Loop                      │
└─────────────────────────────────────────────────────────┘
 
Anomaly Alert Received:
{
  "packet": {
    "src_ip": "192.168.1.100",
    "dst_ip": "1.2.3.4",
    "dst_port": 8080,
    "protocol": "TCP",
    "size": 1024
  },
  "score": 0.82,
  "reason": "Unknown destination, unusual port"
}
 
    ▼
 
┌────────────────────────────────────────┐
│  STEP 1: THOUGHT                       │
│                                        │
│ "This traffic is unusual:              │
│  - IP is not in known list             │
│  - Port 8080 is uncommon               │
│  - Could be malware C&C                │
│  - Or could be legitimate app update   │
│                                        │
│ I need more information before deciding"│
└────────────────┬───────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────┐
│  STEP 2: ACTION                        │
│                                        │
│  Tools available:                      │
│  1. query_knowledge_base(payload)      │
│  2. lookup_geolocation(ip)             │
│  3. check_threat_intelligence(ip)      │
│  4. query_historical_logs(ip)          │
│  5. dns_reverse_lookup(ip)             │
│                                        │
│  Choosing: query_knowledge_base()      │
│  Query: "Port 8080 TCP malware"        │
└────────────────┬───────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────┐
│  STEP 3: OBSERVATION                   │
│                                        │
│  Knowledge Base returned:              │
│  - Matches: "Zeus botnet C&C"          │
│  - Risk: CRITICAL                      │
│  - Confidence: 73%                     │
│  - IOCs: [similar IPs]                 │
└────────────────┬───────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────┐
│  STEP 4: ACTION (continued)            │
│                                        │
│  Too risky! Need to verify.            │
│  Choosing: lookup_geolocation(1.2.3.4)│
└────────────────┬───────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────┐
│  STEP 5: OBSERVATION (continued)       │
│                                        │
│  GeoIP returned:                       │
│  - Country: CN (China)                 │
│  - ASN: Suspicious (known botnet)      │
│  - Reputation: MALICIOUS               │
└────────────────┬───────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────┐
│  STEP 6: ACTION (continued)            │
│                                        │
│  Still need to check: is this user     │
│  supposed to connect to China?         │
│  Choosing: query_historical_logs()     │
│  Query: "192.168.1.100 connections"    │
└────────────────┬───────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────┐
│  STEP 7: OBSERVATION (final)           │
│                                        │
│  Historical logs show:                 │
│  - No previous connections to China    │
│  - All traffic usually to US CDN       │
│  - Sudden change is suspicious         │
│  - Confidence: 95%                     │
└────────────────┬───────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────┐
│  STEP 8: FINAL ANSWER                  │
│                                        │
│  DECISION: BLOCK                       │
│                                        │
│  Reasoning:                            │
│  1. Matches malware signature (KB)     │
│  2. GeoIP shows malicious region       │
│  3. No historical precedent            │
│  4. High confidence (95%)              │
│                                        │
│  Actions to take:                      │
│  ├─ BLOCK: Add to firewall blacklist   │
│  ├─ ALERT: Notify security team        │
│  ├─ MONITOR: Increase logging          │
│  └─ FORENSIC: Deep packet inspection   │
│                                        │
│  Confidence Score: 0.95                │
│  Risk Level: CRITICAL                  │
└────────────────┬───────────────────────┘
                 │
                 ▼
    Decision published to Kafka
    Action Service executes decision
```
 
---
 
## 7️⃣ Performance Timeline (Per Packet)
 
```
Timeline: T=0 → T=10ms (Target)
 
T=0ms     ├─ TShark captures packet from eth0
          │
T=1ms     ├─ JSON parsing complete → Kafka (packets_raw)
          │
T=2ms     ├─ Anomaly Detection begins
          │  ├─ Feature extraction
          │  ├─ Model inference (Isolation Forest)
          │  └─ Score calculation (0.82)
          │
T=5ms     ├─ Anomaly detected → Kafka (anomalies)
          │
T=6ms     ├─ AI Agent receives anomaly
          │  ├─ Load prompt & context
          │  ├─ Query Knowledge Base
          │  ├─ Query historical logs
          │  └─ LLM inference (2ms)
          │
T=10ms    ├─ Decision published → Kafka (decisions)
          │
T=11ms    ├─ Action Service receives decision
          │  ├─ Execute action (firewall, alert)
          │  └─ Log to storage
          │
T=12ms    └─ Complete! Ready for next packet
 
Total: ~10-12ms per packet (handling ~100+ anomalies/sec)
```
 
---
 
## 8️⃣ Storage & Persistence
 
```
                    ┌───────────────────┐
                    │ Incoming Decisions │
                    └──────────┬────────┘
                               │
                  ┌────────────┼────────────┐
                  │            │            │
                  ▼            ▼            ▼
        ┌──────────────┐ ┌────────────┐ ┌──────────────┐
        │ InfluxDB     │ │ Elasticsearch│ │ ClickHouse   │
        │ (Time-Series)│ │ (Search)   │ │ (Analytics)  │
        ├──────────────┤ ├────────────┤ ├──────────────┤
        │              │ │            │ │              │
        │ Stores:      │ │ Stores:    │ │ Stores:      │
        │ - Metrics    │ │ - Alerts   │ │ - Summaries  │
        │ - Packets    │ │ - Logs     │ │ - Reports    │
        │ - Anomalies  │ │ - Actions  │ │ - Trends     │
        │ - Latencies  │ │            │ │              │
        │              │ │ Retention: │ │ Retention:   │
        │ Retention:   │ │ 30 days    │ │ 1 year       │
        │ 7 days       │ │            │ │              │
        │              │ │ Speed: <1s │ │ Speed: <5s   │
        │ Speed:       │ │            │ │              │
        │ ~50ms        │ │ Query type:│ │ Query type:  │
        │              │ │ Full text  │ │ Aggregations │
        │ Query type:  │ │ search     │ │ Reports      │
        │ Time-range   │ │            │ │              │
        │              │ │            │ │              │
        └──────────────┘ └────────────┘ └──────────────┘
```
 
---
 
**This architecture provides:**
- ✅ Real-time packet processing
- ✅ Low latency (< 10ms per packet)
- ✅ High throughput (100+ anomalies/sec)
- ✅ Scalable microservices
- ✅ AI-powered decisions
- ✅ Comprehensive logging
- ✅ Easy monitoring & visualization
 
 