
import numpy as np 
from sklearn.ensemble import IsolationForest 

# Define the main function that takes a list of parsed logs and returns the analyzed logs 
def detect_anomalies(parsed_logs: list) -> list: 
    if not parsed_logs: 
        return [] 
 
    # Create a dictionary to map textual severity labels to numerical values 
    severity_map = {"LOW": 1, "MEDIUM": 5, "HIGH": 10} 
    features = np.array([[severity_map.get(log["severity"], 1)] for log in parsed_logs]) 

    # Initialize the Isoationforest model with 20% expected anomaly rate and a 
    model = IsolationForest(contamination=0.2, random_state=42) 
    model.fit(features) 
     
    predictions = model.predict(features) 
 
    for idx, log in enumerate(parsed_logs): 
        log["is_anomaly"] = True if predictions[idx] == -1 else False 

 
    return parsed_logs