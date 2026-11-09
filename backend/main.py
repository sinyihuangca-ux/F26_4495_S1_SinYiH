import asyncio
import random
import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict

app = FastAPI()

# Enable CORS for Next.js frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 1. WebSocket Live Threat Simulator Stream ---
@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await websocket.accept()
    print("[+] Frontend client connected to WebSocket stream")
    
    attack_types = ["DDoS Attack", "SQL Injection", "Brute Force Login", "XSS Payload", "Port Scanning", "Malware C2 Beacon"]
    
    try:
        while True:
            await asyncio.sleep(3)
            attack = {
                "type": "ATTACK_DETECTED",
                "label": random.choice(attack_types),
                "destination_port": random.choice([80, 443, 22, 3306, 8080]),
                "score": round(random.uniform(0.75, 0.99), 4),
                "timestamp": asyncio.get_event_loop().time()
            }
            await websocket.send_json(attack)
    except WebSocketDisconnect:
        print("[-] Frontend client disconnected from WebSocket stream")


# --- 2. Multi-Model AI Failover Endpoint (Handles Errors, Invalid Keys & High Demand 429/503) ---
class AIKey(BaseModel):
    provider: str  # "gemini", "claude", "openai"
    key: str

class AnalysisRequest(BaseModel):
    threat_counts: Dict[str, int]
    keys: List[AIKey]

@app.post("/api/analyze-threats")
async def analyze_threats_with_failover(req: AnalysisRequest):
    if not req.keys:
        raise HTTPException(status_code=400, detail="No AI keys provided.")

    prompt = f"""You are a Senior Cybersecurity AI Advisor. Analyze these active network threats captured in real time: {req.threat_counts}. 
    Return ONLY a raw valid JSON array (no markdown code blocks, no backticks) sorted strictly by severity (CRITICAL first, then HIGH, MEDIUM, LOW) in this exact structure:
    [
      {{
        "attack_type": "DDoS",
        "severity": "CRITICAL",
        "count": 15,
        "advice": "Apply rate-limiting rules at firewall and enable cloud scrubbing."
      }}
    ]"""

    last_error = None

    for item in req.keys:
        provider = item.provider.lower()
        key = item.key.strip()
        if not key:
            continue

        try:
            print(f"[+] Attempting AI analysis with provider: {provider}")

            # 1. Gemini
            if provider == "gemini":
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key={key}"
                async with httpx.AsyncClient(timeout=10.0) as client:
                    res = await client.post(
                        url,
                        json={
                            "contents": [{"parts": [{"text": prompt}]}],
                            "generationConfig": {"temperature": 0.2},
                        },
                    )
                    if res.status_code in [429, 503]:
                        raise Exception(f"Provider overloaded / High demand (HTTP {res.status_code})")
                    
                    data = res.json()
                    if "error" in data:
                        raise Exception(data["error"]["message"])
                    text = data["candidates"][0]["content"]["parts"][0]["text"]
                    return {"provider_used": "gemini", "result": text}

            # 2. Claude (Anthropic)
            elif provider == "claude":
                url = "https://api.anthropic.com/v1/messages"
                async with httpx.AsyncClient(timeout=10.0) as client:
                    res = await client.post(
                        url,
                        headers={
                            "x-api-key": key,
                            "anthropic-version": "2023-06-01",
                            "content-type": "application/json",
                        },
                        json={
                            "model": "claude-3-5-sonnet-20241022",
                            "max_tokens": 1000,
                            "messages": [{"role": "user", "content": prompt}],
                        },
                    )
                    if res.status_code in [429, 503]:
                        raise Exception(f"Provider overloaded / High demand (HTTP {res.status_code})")

                    data = res.json()
                    if "error" in data:
                        raise Exception(data["error"]["message"])
                    text = data["content"][0]["text"]
                    return {"provider_used": "claude", "result": text}

            # 3. OpenAI / Codex
            elif provider == "openai":
                url = "https://api.openai.com/v1/chat/completions"
                async with httpx.AsyncClient(timeout=10.0) as client:
                    res = await client.post(
                        url,
                        headers={
                            "Authorization": f"Bearer {key}",
                            "content-type": "application/json",
                        },
                        json={
                            "model": "gpt-4o",
                            "messages": [{"role": "user", "content": prompt}],
                            "temperature": 0.2,
                        },
                    )
                    if res.status_code in [429, 503]:
                        raise Exception(f"Provider overloaded / High demand (HTTP {res.status_code})")

                    data = res.json()
                    if "error" in data:
                        raise Exception(data["error"]["message"])
                    text = data["choices"][0]["message"]["content"]
                    return {"provider_used": "openai", "result": text}

        except Exception as e:
            print(f"[-] Provider {provider} failed ({str(e)}). Cycling to next key...")
            last_error = str(e)
            continue

    raise HTTPException(status_code=500, detail=f"All AI providers failed or are under high demand. Last error: {last_error}")