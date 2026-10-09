print("=== ML Engine Script Started ===")

import os 
import pandas as pd 
import numpy as np 
from sklearn.ensemble import IsolationForest 
import joblib 

# Define dataset paths (pointing to the root data/ directory)
MONDAY_CSV = os.path.join("data", "Monday-WorkingHours.pcap_ISCX.csv") 
FRIDAY_CSV = os.path.join("data", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv") 

# Define base directory (app/) and model output paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) 
MODEL_DIR = os.path.join(BASE_DIR, "models") 
MODEL_SAVE_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib") 

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

    # Load Monday (Benign) and Friday (DDoS) datasets 
    for file_path in [MONDAY_CSV, FRIDAY_CSV]: 
        if os.path.exists(file_path): 
            print(f"[*] Reading file: {file_path} (loading 20,000 rows)...") 
            # Limit rows to 20,000 per file for fast training
            df_temp = pd.read_csv(file_path, nrows=20000) 
            df_list.append(df_temp) 
            print(f"[+] Loaded {len(df_temp)} rows successfully.")
        else: 
            print(f"[!] Warning: File not found at {file_path}. Please check the data/ directory.") 

    if not df_list: 
        raise FileNotFoundError("No valid CSV files found in the data/ directory.") 

    print("[*] Combining and preprocessing data...")
    # Combine datasets 
    df = pd.concat(df_list, ignore_index=True) 
    
    # Clean column names (strip whitespace)
    df.columns = df.columns.str.strip() 

    # Extract key features
    X = df[SELECTED_FEATURES].copy() 

    # Handle Inf and NaN values
    X.replace([np.inf, -np.inf], np.nan, inplace=True) 
    X.fillna(X.median(), inplace=True) 

    print(f"[+] Data preprocessing complete. Total samples: {len(X)}, Features: {X.shape[1]}") 
    return X 

def train_isolation_forest(): 
    """Train Isolation Forest model and save artifact to disk.""" 
    X_train = load_and_clean_data() 
    
    print("[*] Training Isolation Forest model (this takes ~5-10 seconds)...") 
    # Use n_jobs=1 to avoid Windows multiprocessing deadlock
    model = IsolationForest( 
        n_estimators=100, 
        contamination=0.05, 
        random_state=42, 
        n_jobs=1 
    ) 
    model.fit(X_train) 
    print("[+] Model training successful!") 

    # Ensure app/models directory exists and save the trained model 
    os.makedirs(MODEL_DIR, exist_ok=True) 
    joblib.dump(model, MODEL_SAVE_PATH) 
    print(f"[+] Model saved successfully to: {MODEL_SAVE_PATH}") 

if __name__ == "__main__": 
    train_isolation_forest()