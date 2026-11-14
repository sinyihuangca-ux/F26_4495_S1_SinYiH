import datetime
from typing import List, Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from app.parser import parse_log_batch
from app.ml_engine import run_ml_inference

app = FastAPI(title="AI-Powered Ransomware & Zero-Day Threat Mitigation API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PERSISTENT_LOG_LEDGER: List[Dict[str, Any]] = []

class LogIngestRequest(BaseModel):
    logs: List[Dict[str, Any]]

class ConnectionManager:
    """Manages active WebSocket connections for real-time threat alert broadcasting."""
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

@app.get("/")
def health_check():
    return {"status": "online", "service": "Layer 3 Threat Detection Engine"}

@app.post("/api/logs/ingest")
async def ingest_logs(payload: LogIngestRequest, model_type: str = Query("isolation_forest")):
    parsed_logs = parse_log_batch(payload.logs)
    analyzed_logs = run_ml_inference(parsed_logs, model_type=model_type)

    anomalies_count = 0
    for item in analyzed_logs:
        item["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        PERSISTENT_LOG_LEDGER.insert(0, item)

        if item["is_anomaly"]:
            anomalies_count += 1
            await manager.broadcast({
                "type": "ATTACK_DETECTED",
                "timestamp": item["timestamp"],
                "label": item["label"],
                "source_ip": item["source_ip"],
                "destination_ip": item["destination_ip"],
                "destination_port": item["destination_port"],
                "score": item["anomaly_score"],
                "model": item["detection_model"]
            })

    del PERSISTENT_LOG_LEDGER[1000:]

    return {
        "status": "success",
        "processed_count": len(analyzed_logs),
        "anomalies_detected": anomalies_count
    }

@app.post("/analyze-logs")
async def analyze_stored_logs(model_type: str = Query("isolation_forest")):
    if not PERSISTENT_LOG_LEDGER:
        from attack_simulator import generate_synthetic_batch
        sample_raw = generate_synthetic_batch("Mixed", batch_size=15)
        parsed = parse_log_batch(sample_raw)
    else:
        parsed = PERSISTENT_LOG_LEDGER[:50]

    results = run_ml_inference(parsed, model_type=model_type)
    flagged = [r for r in results if r["is_anomaly"]]

    for item in flagged:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        item["timestamp"] = ts
        await manager.broadcast({
            "type": "ATTACK_DETECTED",
            "timestamp": ts,
            "label": item["label"],
            "source_ip": item["source_ip"],
            "destination_ip": item["destination_ip"],
            "destination_port": item["destination_port"],
            "score": item["anomaly_score"],
            "model": item["detection_model"]
        })

    return {
        "status": "success",
        "model_used": model_type,
        "total_parsed": len(results),
        "anomalies_flagged": len(flagged),
        "sample_results": results[:10]
    }

@app.get("/api/logs/history")
def get_log_history():
    return {"logs": PERSISTENT_LOG_LEDGER}

@app.websocket("/ws/alerts")
async def websocket_alerts_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)