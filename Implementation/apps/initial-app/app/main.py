import datetime
from typing import List, Dict, Any

# Import FastAPI components for API and WebSocket support
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query

# Import CORS middleware to allow frontend access
from fastapi.middleware.cors import CORSMiddleware

# Import Pydantic model for request validation
from pydantic import BaseModel

# Custom parser that converts raw logs into structured records
from app.parser import parse_log_batch

# Machine learning engine for anomaly detection
from app.ml_engine import run_ml_inference


# Create FastAPI application
app = FastAPI(
    title="AI-Powered Ransomware & Zero-Day Threat Mitigation API"
)

# Enable Cross-Origin Resource Sharing (CORS)
# Allows web dashboards and external applications to access the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Allow all domains
    allow_credentials=True,       # Allow authentication cookies
    allow_methods=["*"],          # Allow all HTTP methods
    allow_headers=["*"],          # Allow all request headers
)

# In-memory storage for processed log records
# Keeps the latest analyzed logs available for review
PERSISTENT_LOG_LEDGER: List[Dict[str, Any]] = []


# Request model for log ingestion endpoint
class LogIngestRequest(BaseModel):
    logs: List[Dict[str, Any]]


class ConnectionManager:
    """
    Manages active WebSocket connections and
    broadcasts real-time threat alerts to all clients.
    """

    def __init__(self):
        # Store connected WebSocket clients
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """
        Accept a new WebSocket connection and
        add it to the active connection list.
        """
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        """
        Remove a disconnected WebSocket client.
        """
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        """
        Send a JSON message to all connected clients.
        """
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                # Remove dead connections automatically
                self.disconnect(connection)


# Create a global WebSocket manager instance
manager = ConnectionManager()


@app.get("/")
def health_check():
    """
    Health check endpoint.
    Used to verify that the API service is running.
    """
    return {
        "status": "online",
        "service": "Layer 3 Threat Detection Engine"
    }


@app.post("/api/logs/ingest")
async def ingest_logs(
    payload: LogIngestRequest,
    model_type: str = Query("isolation_forest")
):
    """
    Receives raw logs, parses them, runs ML analysis,
    stores the results, and broadcasts alerts if anomalies are found.
    """

    # Convert raw logs into structured format
    parsed_logs = parse_log_batch(payload.logs)

    # Analyze logs using the selected ML model
    analyzed_logs = run_ml_inference(
        parsed_logs,
        model_type=model_type
    )

    anomalies_count = 0

    for item in analyzed_logs:

        # Attach processing timestamp
        item["timestamp"] = datetime.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # Store newest logs at the beginning of the ledger
        PERSISTENT_LOG_LEDGER.insert(0, item)

        # Check whether this log was flagged as malicious
        if item["is_anomaly"]:
            anomalies_count += 1

            # Broadcast threat alert to all WebSocket clients
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

    # Keep only the latest 1000 log entries
    del PERSISTENT_LOG_LEDGER[1000:]

    return {
        "status": "success",
        "processed_count": len(analyzed_logs),
        "anomalies_detected": anomalies_count
    }


@app.post("/analyze-logs")
async def analyze_stored_logs(
    model_type: str = Query("isolation_forest")
):
    """
    Re-analyze stored logs or generate synthetic logs
    if no data currently exists.
    """

    if not PERSISTENT_LOG_LEDGER:

        # Generate sample attack data for testing
        from attack_simulator import generate_synthetic_batch

        sample_raw = generate_synthetic_batch(
            "Mixed",
            batch_size=15
        )

        # Convert synthetic logs to structured format
        parsed = parse_log_batch(sample_raw)

    else:
        # Analyze the latest 50 stored logs
        parsed = PERSISTENT_LOG_LEDGER[:50]

    # Perform ML inference
    results = run_ml_inference(
        parsed,
        model_type=model_type
    )

    # Extract only anomalous records
    flagged = [
        r for r in results
        if r["is_anomaly"]
    ]

    # Broadcast alerts for detected anomalies
    for item in flagged:

        ts = datetime.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

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
    """
    Returns the current stored log history.
    Useful for dashboards and investigations.
    """
    return {
        "logs": PERSISTENT_LOG_LEDGER
    }


@app.websocket("/ws/alerts")
async def websocket_alerts_endpoint(websocket: WebSocket):
    """
    Real-time WebSocket endpoint for threat alert streaming.
    Security dashboards can subscribe to this endpoint
    to receive immediate attack notifications.
    """

    # Register new client connection
    await manager.connect(websocket)

    try:
        while True:

            # Keep WebSocket connection active
            await websocket.receive_text()

    except WebSocketDisconnect:

        # Remove disconnected client
        manager.disconnect(websocket)