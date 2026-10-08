from fastapi import FastAPI 
from app.parser import process_log_file 
from app.ml_engine import detect_anomalies 
 
app = FastAPI( 
    title="AI Cyber Threat Mitigation Platform", 
    description="Week 1-4 Complete MVP Infrastructure", 
    version="1.0.0" 
)
@app.get("/") 
def read_root(): 
    return {"status": "System Running", "platform": "AI Security Threat Mitigation"} 
 
@app.post("/analyze-logs") 
def analyze_logs(): 
    parsed_logs = process_log_file("data/sample_syslog.log") 
    analyzed_logs = detect_anomalies(parsed_logs) 
     
    return { 
        "status": "success", 
        "total_parsed": len(analyzed_logs), 
        "data": analyzed_logs 
    }