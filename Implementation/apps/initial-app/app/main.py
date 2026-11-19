import datetime
import json
from typing import List, Dict, Any

# Import FastAPI components for API and WebSocket support
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException

# Import CORS middleware to allow frontend access
from fastapi.middleware.cors import CORSMiddleware

# Import Pydantic model for request validation
from pydantic import BaseModel

# HTTP client for calling external AI providers (Groq / Gemini / OpenAI)
import httpx

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


# Request model for multi-model AI threat analysis endpoint
class ThreatAnalysisRequest(BaseModel):
    threat_counts: Dict[str, int]
    keys: List[Dict[str, str]]


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


def _build_advisor_prompt(threat_counts: Dict[str, int]) -> str:
    return (
        "You are a Senior Cybersecurity SOC AI Advisor. "
        f"Analyze these active network threats captured by our ML detection engine: {json.dumps(threat_counts)}. "
        "Return ONLY a raw valid JSON array (no markdown code blocks, no backticks) "
        "sorted strictly by severity (CRITICAL first, then HIGH, MEDIUM, LOW) in this exact structure:\n"
        "[\n"
        "  {\n"
        '    "attack_type": "Ransomware",\n'
        '    "severity": "CRITICAL",\n'
        '    "count": 3,\n'
        '    "advice": "Isolate affected hosts immediately, block suspicious outbound ports, and verify backups."\n'
        "  }\n"
        "]"
    )


async def _call_groq(api_key: str, prompt: str) -> str:
    async with httpx.AsyncClient(timeout=25.0) as client:
        resp = await client.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


async def _call_gemini(api_key: str, prompt: str) -> str:
    async with httpx.AsyncClient(timeout=25.0) as client:
        resp = await client.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}",
            headers={"Content-Type": "application/json"},
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2},
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]


async def _call_openai(api_key: str, prompt: str) -> str:
    async with httpx.AsyncClient(timeout=25.0) as client:
        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


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


@app.post("/api/analyze-threats")
async def analyze_threats(payload: ThreatAnalysisRequest):
    """
    Analyzes active ML-detected threat counts using configured AI keys
    with automatic failover across providers (Groq -> Gemini -> OpenAI).
    """
    if not payload.threat_counts:
        raise HTTPException(
            status_code=400,
            detail="No threat_counts provided for analysis."
        )

    if not payload.keys:
        raise HTTPException(
            status_code=400,
            detail="No AI API keys provided."
        )

    prompt = _build_advisor_prompt(payload.threat_counts)
    errors = []

    for entry in payload.keys:
        provider = (entry.get("provider") or "").lower().strip()
        api_key = (entry.get("key") or "").strip()
        if not api_key:
            continue

        try:
            if provider == "groq":
                raw_text = await _call_groq(api_key, prompt)
            elif provider == "gemini":
                raw_text = await _call_gemini(api_key, prompt)
            elif provider == "openai":
                raw_text = await _call_openai(api_key, prompt)
            else:
                continue

            cleaned = raw_text.replace("```json", "").replace("```", "").strip()
            # Validate JSON structure before returning to frontend
            parsed_json = json.loads(cleaned)

            return {
                "status": "success",
                "provider_used": provider,
                "result": json.dumps(parsed_json)
            }
        except Exception as exc:
            errors.append(f"{provider}: {str(exc)}")
            continue

    raise HTTPException(
        status_code=502,
        detail=f"All configured AI providers failed: {' | '.join(errors)}"
    )


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