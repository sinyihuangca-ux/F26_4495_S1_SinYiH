print("=== ML Engine Script Started ===")

import os 
import pandas as pd 
import numpy as np 
from sklearn.ensemble import IsolationForest 
# ==========================================
# [Extension 1/4] Import One-Class SVM model and StandardScaler for normalization
# ==========================================
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import joblib 

# Define dataset paths (pointing to the root data/ directory)
MONDAY_CSV = os.path.join("data", "Monday-WorkingHours.pcap_ISCX.csv") 
FRIDAY_CSV = os.path.join("data", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv") 

# Define base directory (app/) and model output paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) 
MODEL_DIR = os.path.join(BASE_DIR, "models") 
MODEL_SAVE_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib") 
# ==========================================
# [Extension 2/4] Define paths for the second model (One-Class SVM) and feature scaler
# ==========================================
SVM_MODEL_SAVE_PATH = os.path.join(MODEL_DIR, "one_class_svm.joblib")
SCALER_SAVE_PATH = os.path.join(MODEL_DIR, "feature_scaler.joblib")

# Select key network flow features for Layer 3 threat detection 
SELECTED_FEATURES = [ 
    'Destination Port', 
    'Flow Duration', 
    'Total Fwd Packets', 
    'Total Backward Packets', 
    'Flow Bytes/s', 
    'Flow Packets/s', 
    'Packet Length Mean', 
    'ACK Flag Count' 
] 

def load_and_clean_data(): 
    """Load and preprocess CIC-IDS-2017 dataset files.""" 
    print("[*] Loading datasets...") 
    df_list = [] 

    for file_path in [MONDAY_CSV, FRIDAY_CSV]: 
        if os.path.exists(file_path): 
            print(f"[*] Reading file: {file_path} (loading 20,000 rows)...") 
            df_temp = pd.read_csv(file_path, nrows=20000) 
            df_list.append(df_temp) 
            print(f"[+] Loaded {len(df_temp)} rows successfully.")
        else: 
            print(f"[!] Warning: File not found at {file_path}. Please check the data/ directory.") 

    if not df_list: 
        raise FileNotFoundError("No valid CSV files found in the data/ directory.") 

    print("[*] Combining and preprocessing data...")
    df = pd.concat(df_list, ignore_index=True) 
    df.columns = df.columns.str.strip() 

    X = df[SELECTED_FEATURES].copy() 
    X.replace([np.inf, -np.inf], np.nan, inplace=True) 
    X.fillna(X.median(), inplace=True) 

    print(f"[+] Data preprocessing complete. Total samples: {len(X)}, Features: {X.shape[1]}") 
    return X 

def train_isolation_forest(): 
    """Train Isolation Forest and One-Class SVM models, then save artifacts to disk.""" 
    X_train = load_and_clean_data() 
     
    # ==========================================
    # [Extension 3/4] Standardize features since One-Class SVM is sensitive to feature scales
    # ==========================================
    print("[*] Fitting StandardScaler for SVM feature normalization...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    # 1. Train original Isolation Forest model
    print("[*] Training Isolation Forest model (this takes ~5-10 seconds)...") 
    model_if = IsolationForest( 
        n_estimators=100, 
        contamination=0.05, 
        random_state=42, 
        n_jobs=1 
    ) 
    model_if.fit(X_train) # Isolation Forest can take raw numerical values directly
    print("[+] Isolation Forest model training successful!") 

    # 2. Train added One-Class SVM model (as the second comparison model)
    print("[*] Training One-Class SVM model...")
    model_svm = OneClassSVM(
        kernel='rbf', 
        gamma='scale', 
        nu=0.05 # Outlier proportion corresponding to original contamination
    )
    model_svm.fit(X_train_scaled) # One-Class SVM uses standardized data
    print("[+] One-Class SVM model training successful!")

    # Save all models and scaler artifacts
    os.makedirs(MODEL_DIR, exist_ok=True) 
    joblib.dump(model_if, MODEL_SAVE_PATH) 
    joblib.dump(model_svm, SVM_MODEL_SAVE_PATH)
    joblib.dump(scaler, SCALER_SAVE_PATH)
    print(f"[+] All models and artifacts saved successfully to: {MODEL_DIR}")


# ==========================================
# RUNTIME INFERENCE ENGINE (Used by FastAPI)
# ==========================================
class MLEngine:
    def __init__(self):
        # Load Isolation Forest
        if os.path.exists(MODEL_SAVE_PATH):
            self.model_if = joblib.load(MODEL_SAVE_PATH)
            print(f"[*] Successfully loaded Isolation Forest model.")
        else:
            self.model_if = None
            print(f"[-] WARNING: Isolation Forest not found at {MODEL_SAVE_PATH}.")

        # ==========================================
        # [Extension 4/4] Load second model (SVM) and Scaler upon initialization
        # ==========================================
        if os.path.exists(SVM_MODEL_SAVE_PATH) and os.path.exists(SCALER_SAVE_PATH):
            self.model_svm = joblib.load(SVM_MODEL_SAVE_PATH)
            self.scaler = joblib.load(SCALER_SAVE_PATH)
            print(f"[*] Successfully loaded OneClassSVM model and Scaler.")
        else:
            self.model_svm = None
            self.scaler = None
            print(f"[-] WARNING: OneClassSVM or Scaler not found.")

    def predict_log(self, row_data: dict):
        """Extracts features, runs dual-model inference (Isolation Forest + One-Class SVM), and compares results."""
        if not self.model_if:
            return False, 0.0
         
        # Extract features in the exact order they were trained on
        try:
            features = [float(row_data.get(feat, 0)) for feat in SELECTED_FEATURES]
        except (ValueError, TypeError):
            features = [0.0] * len(SELECTED_FEATURES)

        arr = np.array([features])
        
        # --- Model 1: Isolation Forest Prediction ---
        pred_if = self.model_if.predict(arr)[0]   # -1 = anomaly, 1 = benign
        score_if = self.model_if.decision_function(arr)[0]
        is_attack_if = bool(pred_if == -1)

        # --- Model 2: One-Class SVM Prediction and Comparison ---
        is_attack_svm = False
        score_svm = 0.0
        if self.model_svm and self.scaler:
            arr_scaled = self.scaler.transform(arr)
            pred_svm = self.model_svm.predict(arr_scaled)[0] # -1 = anomaly, 1 = benign
            score_svm = self.model_svm.decision_function(arr_scaled)[0]
            is_attack_svm = bool(pred_svm == -1)

        # ==========================================
        # Dual-Model Ensemble Voting Logic
        # Strategy: Trigger an attack alert if either model detects an anomaly (Logical OR)
        # to ensure higher security coverage and robust threat detection.
        # ==========================================
        final_is_attack = is_attack_if or is_attack_svm
        
        # Average the decision scores from both models as the final anomaly score for the frontend
        final_score = float((score_if + score_svm) / 2.0)

        return final_is_attack, final_score

# Global instance imported by FastAPI
ml_engine = MLEngine()


if __name__ == "__main__": 
    # If you run `python ml_engine.py` directly, it trains and saves both models
    train_isolation_forest()
