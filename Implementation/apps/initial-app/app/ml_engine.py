# Implementation/apps/initial-app/app/ml_engine.py
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM

def detect_anomalies(parsed_logs: list, model_type: str = "isolation_forest") -> list:
    """
    Analyzes log features using either Isolation Forest or One-Class SVM.
    
    :param parsed_logs: List of parsed log dictionaries
    :param model_type: 'isolation_forest' or 'one_class_svm'
    :return: Analyzed logs with is_anomaly flags
    """
    if not parsed_logs:
        return []

    # Map textual severity labels to numerical feature vectors
    severity_map = {"LOW": 1, "MEDIUM": 5, "HIGH": 10}
    features = np.array([[severity_map.get(log.get("severity", "LOW"), 1)] for log in parsed_logs])

    # Select and fit model based on configuration
    if model_type == "one_class_svm":
        # One-Class SVM with RBF kernel for non-linear boundary detection
        model = OneClassSVM(nu=0.1, kernel="rbf", gamma="scale")
    else:
        # Default Isolation Forest model
        model = IsolationForest(contamination=0.2, random_state=42)

    model.fit(features)
    predictions = model.predict(features)  # -1 represents an anomaly, 1 represents normal

    # Annotate logs with anomaly detection output
    for idx, log in enumerate(parsed_logs):
        log["is_anomaly"] = True if predictions[idx] == -1 else False
        log["detection_model"] = "One-Class SVM" if model_type == "one_class_svm" else "Isolation Forest"

    return parsed_logs