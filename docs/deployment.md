# Deployment Guide

## Requirements
- Docker 20.10+
- Docker Compose 2.0+
- Python 3.10+
- 8GB RAM minimum
- 20GB disk space

## Installation
1. Clone repository
2. Run: docker-compose up -d
3. Wait for services to start (2-3 minutes)
4. Access: http://localhost:8000

## Logs
docker-compose logs -f [service-name]

## Monitoring
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000