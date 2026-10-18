import time
import os
import pandas as pd
import requests

# ==========================================
# CONFIGURATION
# ==========================================
# Replace with your Server PC's actual local IPv4 address (run `ipconfig` on the server PC)
SERVER_IP = "192.168.1.50" 
PORT = 8000
URL = f"http://{SERVER_IP}:{PORT}/api/logs/ingest"

# Available dataset options mapped to user-friendly menu choices
DATASETS = {
    "1": {
        "name": "DDoS Attack Simulation (Friday)",
        "file": "mixed_monday_benign_friday_ddos_500.csv"
    },
    "2": {
        "name": "PortScan Attack Simulation (Friday)",
        "file": "mixed_monday_benign_friday_portscan_500.csv"
    },
    "3": {
        "name": "Web Attacks Simulation (Thursday)",
        "file": "mixed_monday_benign_thursday_webattacks_500.csv"
    },
    "4": {
        "name": "Infiltration Attack Simulation (Thursday)",
        "file": "mixed_monday_benign_thursday_infiltration_186.csv"
    },
    "5": {
        "name": "Normal Workday Traffic (Monday Benign)",
        "file": "mixed_monday_benign_friday_ddos_500.csv"  # Can use Monday/Benign subset or toggle label filtering if needed
    }
}

BATCH_SIZE = 10     # Number of rows sent per HTTP request for fast inference
STREAM_DELAY = 0.1  # Delay in seconds between batches to simulate real traffic pacing

def show_menu():
    print("\n" + "="*50)
    print("      AI CYBERSECURITY ATTACK SIMULATOR      ")
    print("="*50)
    print(" Select a traffic scenario to stream to the server:\n")
    for key, option in DATASETS.items():
        print(f"  [{key}] {option['name']}")
    print("  [0] Exit")
    print("="*50)

def stream_dataset(file_path, scenario_name):
    if not os.path.exists(file_path):
        print(f"\n[-] Error: Could not find dataset file '{file_path}' in the current folder.")
        print("    Please ensure all CSV files are placed alongside this script.")
        return

    print(f"\n[*] Loading '{scenario_name}' from {file_path}...")
    df = pd.read_csv(file_path)
    print(f"[+] Loaded {len(df)} log records successfully.")
    
    print(f"[*] Targeting Server: {URL}")
    print(f"[*] Streaming live traffic... Press Ctrl+C to stop.\n")

    try:
        for i in range(0, len(df), BATCH_SIZE):
            chunk = df.iloc[i:i + BATCH_SIZE]
            payload = chunk.to_dict(orient="records")
            
            response = requests.post(URL, json=payload)
            
            if response.status_code == 200:
                result = response.json()
                flagged = result.get('anomalies_flagged', 0)
                print(f"[>] Batch sent [{i}/{len(df)}]. ML Flagged Anomalies: {flagged}")
            else:
                print(f"[-] Server error: Status code {response.status_code}")
                
            time.sleep(STREAM_DELAY)
            
        print(f"\n[*] Simulation completed for: {scenario_name}\n")
        
    except requests.exceptions.ConnectionError:
        print(f"\n[-] Connection failed! Could not reach server at {URL}.")
        print("    Verify FastAPI is running and SERVER_IP is correct.")
    except KeyboardInterrupt:
        print("\n[*] Stream manually interrupted by user.\n")

def main():
    while True:
        show_menu()
        choice = input("Enter your choice (0-5): ").strip()
        
        if choice == "0":
            print("\nExiting attack simulator. Stay secure!")
            break
        elif choice in DATASETS:
            selected = DATASETS[choice]
            stream_dataset(selected["file"], selected["name"])
            input("Press Enter to return to the main menu...")
        else:
            print("\n[!] Invalid selection. Please enter a number between 0 and 5.")
            time.sleep(1)

if __name__ == "__main__":
    main()