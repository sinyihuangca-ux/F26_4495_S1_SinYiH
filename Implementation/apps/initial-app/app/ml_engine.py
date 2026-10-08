import numpy as np 
from sklearn.ensemble import IsolationForest 
 
def detect_anomalies(parsed_logs: list) -> list: 
    if not parsed_logs: 
        return [] 
 
    severity_map = {"LOW": 1, "MEDIUM": 5, "HIGH": 10} 
    features = np.array([[severity_map.get(log["severity"], 1)] for log in parsed_logs]) 
 
    model = IsolationForest(contamination=0.2, random_state=42) 
    model.fit(features) 
     
    predictions = model.predict(features) 
 
    for idx, log in enumerate(parsed_logs): 
        log["is_anomaly"] = True if predictions[idx] == -1 else False 
 
    return parsed_logs