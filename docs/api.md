# API Reference

## Base URL
http://localhost:8000

## Endpoints

### Health Check
GET /health

### Packets
POST /api/packets/capture/start
POST /api/packets/capture/stop
GET /api/packets/status

### Anomalies
GET /api/anomalies/list
GET /api/anomalies/details/:id

### Logs
GET /api/logs/packets
GET /api/logs/alerts