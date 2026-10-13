# System Architecture

## Services
- Packet Capture: eth0 traffic capture & parsing
- Anomaly Detection: ML-based anomaly scoring
- AI Agent: LLM-based reasoning
- Knowledge Base: Vector DB + RAG
- Log Storage: Time-series & log persistence
- Action Service: Execution layer
- API Gateway: Single entry point

## Data Flow
TShark → Kafka → Anomaly Detection → AI Agent → Action Service

## Deployment
Docker Compose with 8 services + infrastructuređa