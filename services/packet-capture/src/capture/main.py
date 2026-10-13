"""Capture worker + API điều khiển.

Chạy (từ thư mục src/):  uvicorn capture.main:app --host 0.0.0.0 --port 5001
"""
import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Literal

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from capture.pipeline import CapturePipeline
from capture.sources import create_source
from common.config import settings
from common.kafka import ensure_topics, make_producer
from common.log import setup_logging

setup_logging()
logger = logging.getLogger(__name__)

pipeline: CapturePipeline | None = None


class StartRequest(BaseModel):
    """Ghi đè cấu hình mặc định trong .env cho lần capture này (bỏ trống = dùng mặc định)."""
    source: Literal["local", "pcap"] | None = None
    interface: str | None = None
    bpf_filter: str | None = None
    pcap_file: str | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pipeline
    await asyncio.to_thread(ensure_topics, {settings.KAFKA_RAW_TOPIC: settings.KAFKA_RAW_RETENTION_MS})
    pipeline = CapturePipeline(
        producer=make_producer(f"packet-capture-{settings.SENSOR_ID}"),
        topic=settings.KAFKA_RAW_TOPIC,
        sensor_id=settings.SENSOR_ID,
        tshark_path=settings.TSHARK_PATH,
        display_filter=settings.CAPTURE_DISPLAY_FILTER,
        restart_backoff_max=settings.RESTART_BACKOFF_MAX,
    )
    if settings.CAPTURE_AUTOSTART:
        try:
            await pipeline.start(_build_source(StartRequest()))
        except ValueError as e:
            logger.error(f"Autostart failed: {e}")
    logger.info("Packet capture service ready")

    yield

    await pipeline.stop()
    logger.info("Packet capture service stopped")


app = FastAPI(
    title="Packet Capture Service",
    description="Capture packets with tshark and publish raw records to Kafka",
    version="2.0.0",
    lifespan=lifespan,
)


def _build_source(req: StartRequest):
    return create_source(
        kind=req.source or settings.CAPTURE_SOURCE,
        interface=req.interface or settings.CAPTURE_INTERFACE,
        bpf_filter=req.bpf_filter if req.bpf_filter is not None else settings.CAPTURE_BPF_FILTER,
        pcap_file=req.pcap_file or settings.PCAP_FILE,
    )


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "packet-capture",
        "version": app.version,
        "capture_state": pipeline.state.value if pipeline else None,
    }


@app.post("/api/capture/start")
async def start_capture(req: StartRequest | None = None):
    if pipeline.is_active:
        raise HTTPException(status_code=409, detail="Capture is already running")
    try:
        source = _build_source(req or StartRequest())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    await pipeline.start(source)
    return {"status": "started", "source": source.describe(), "kafka_topic": settings.KAFKA_RAW_TOPIC}


@app.post("/api/capture/stop")
async def stop_capture():
    if not pipeline.is_active:
        return {"status": "not_running", "capture": pipeline.status()}
    await pipeline.stop()
    return {"status": "stopped", "capture": pipeline.status()}


@app.get("/api/capture/status")
async def capture_status():
    return pipeline.status()


if __name__ == "__main__":
    uvicorn.run(app, host=settings.API_HOST, port=settings.API_PORT, log_level=settings.LOG_LEVEL.lower())
