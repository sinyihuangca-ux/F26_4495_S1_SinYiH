from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
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