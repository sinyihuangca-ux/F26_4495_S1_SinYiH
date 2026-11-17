from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any
import json
import httpx
from app.ml_engine import ml_engine

app = FastAPI( 
    title="AI Cyber Threat Mitigation Platform", 
    description="Real-time ML Anomaly Detection & WebSocket Pipeline", 
    version="1.0.0" 
)

# Enable CORS so your Next.js frontend can communicate with FastAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this to your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# WEBSOCKET CONNECTION MANAGER
# ==========================================
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"[*] Dashboard client connected. Active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        print(f"[-] Dashboard client disconnected. Active connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                print(f"[-] Error broadcasting to client: {e}")

manager = ConnectionManager()

# ==========================================
# PYDANTIC SCHEMAS FOR AI FAILOVER
# ==========================================
class KeyItem(BaseModel):
    provider: str
    key: str

class ThreatAnalysisRequest(BaseModel):
    threat_counts: Dict[str, int]
    keys: List[KeyItem]

# ==========================================
# ROUTES
# ==========================================
@app.get("/") 
def read_root(): 
    return {"status": "System Running", "platform": "AI Security Threat Mitigation"} 

@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time dashboard threat alerts."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep the connection alive listening for client pings/messages
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.post("/api/logs/ingest")
async def ingest_log_stream(logs: list[dict]):
    """
    Receives batches of streamed logs from the external attacker PC,
    runs ML inference, and broadcasts real-time alerts if anomalies are found.
    """
    anomalies_detected = 0
    
    for row in logs:
        # Run inference using our updated ml_engine instance
        is_attack, score = ml_engine.predict_log(row)
        
        # Check if model flags it OR dataset explicitly notes an attack label
        label = str(row.get("Label", "BENIGN"))
        if is_attack or label != "BENIGN":
            anomalies_detected += 1
            
            alert_payload = {
                "type": "ATTACK_DETECTED",
                "label": label if label != "BENIGN" else "Anomalous Traffic / DDoS",
                "score": score,
                "destination_port": int(row.get("Destination Port", 0)),
                "timestamp": str(row.get("Timestamp", "Live Stream"))
            }
            
            # Broadcast instantly via WebSocket to the dashboard
            await manager.broadcast(alert_payload)
            
    return {
        "status": "success", 
        "processed": len(logs), 
        "anomalies_flagged": anomalies_detected
    }

@app.post("/api/analyze-threats")
async def analyze_threats(payload: ThreatAnalysisRequest):
    """
    Multi-model AI advisor endpoint with automatic failover across provided API keys.
    """
    if not payload.keys:
        raise HTTPException(status_code=400, detail="No API keys provided for failover analysis.")

    last_error = None

    for item in payload.keys:
        provider = item.provider.lower()
        api_key = item.key

        prompt = f"""
        You are an elite cybersecurity SOC analyst. Analyze the following aggregated network threat counts:
        {json.dumps(payload.threat_counts, indent=2)}

        Return a valid JSON array containing objects with these exact keys:
        - "attack_type": string name of the threat
        - "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
        - "count": integer occurrences
        - "advice": actionable technical mitigation recommendation

        Return ONLY raw JSON, without markdown formatting blocks like ```json or ```.
        """

        try:
            # 1. Groq Free Tier (Replaces Claude)
            if provider == "groq":
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.post(
                        "https://api.groq.com/openai/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {api_key}",
                            "Content-Type": "application/json"
                        },
                        json={
                            "model": "llama-3.3-70b-versatile",
                            "messages": [{"role": "user", "content": prompt}],
                            "temperature": 0.2
                        }
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        text_result = data["choices"][0]["message"]["content"]
                        return {"provider_used": "Groq (Free Tier)", "result": text_result}
                    else:
                        last_error = f"Groq API Error {resp.status_code}: {resp.text}"

            # 2. Gemini
            elif provider == "gemini":
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.post(
                        f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}",
                        json={"contents": [{"parts": [{"text": prompt}]}]}
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        text_result = data["candidates"][0]["content"]["parts"][0]["text"]
                        return {"provider_used": "Gemini", "result": text_result}
                    else:
                        last_error = f"Gemini API Error {resp.status_code}: {resp.text}"

            # 3. OpenAI
            elif provider == "openai":
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.post(
                        "https://api.openai.com/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {api_key}",
                            "Content-Type": "application/json"
                        },
                        json={
                            "model": "gpt-4o-mini",
                            "messages": [{"role": "user", "content": prompt}],
                            "temperature": 0.2
                        }
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        text_result = data["choices"][0]["message"]["content"]
                        return {"provider_used": "OpenAI", "result": text_result}
                    else:
                        last_error = f"OpenAI API Error {resp.status_code}: {resp.text}"

        except Exception as e:
            last_error = str(e)
            continue

    raise HTTPException(status_code=502, detail=f"All failover AI models failed. Last error: {last_error}")