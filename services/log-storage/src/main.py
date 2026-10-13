from fastapi import FastAPI
from pydantic import BaseModel
import os
from dotenv import load_dotenv
import uvicorn

load_dotenv()

app = FastAPI(
    title="ai agent",
    version="1.0.0"
)

#health check endpoint
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "api gateway",
        "version": "1.0.0"
    }

@app.get("/api/api_gateway/status")
async def get_status():
    return {
        "status": "running"
    }
    
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "5005")),
        reload=True
    )