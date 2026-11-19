"""Attack simulator: streams CIC-IDS-2017 flow records to the FastAPI ingest endpoint.

Run it on a second PC (or a second terminal) next to the CSV files:

    python attack_simulator.py --server 192.168.1.50:8000          # interactive menu
    python attack_simulator.py --server 192.168.1.50:8000 --scenario 1
    python attack_simulator.py --help

The server address can also come from the THREAT_SERVER environment variable.
Needs: pip install pandas requests
"""
import argparse
import os
import sys
import time
from pathlib import Path

import pandas as pd
import requests

HERE = Path(__file__).resolve().parent

SCENARIOS = {
    "1": ("DDoS attack (Friday)", ["mixed_monday_benign_friday_ddos_500.csv"], False),
    "2": ("PortScan attack (Friday)", ["mixed_monday_benign_friday_portscan_500.csv"], False),
    "3": ("Web attacks (Thursday)", ["mixed_monday_benign_thursday_webattacks_500.csv"], False),
    "4": ("Infiltration attack (Thursday)", ["mixed_monday_benign_thursday_infiltration_186.csv"], False),
    "5": ("Normal workday traffic (benign only)", [
        "mixed_monday_benign_friday_ddos_500.csv",
        "mixed_monday_benign_friday_portscan_500.csv",
        "mixed_monday_benign_thursday_webattacks_500.csv",
        "mixed_monday_benign_thursday_infiltration_186.csv",
    ], True),
}


def read_csv(path: Path) -> pd.DataFrame:
    try:
        df = pd.read_csv(path, low_memory=False)
    except UnicodeDecodeError:  # the web-attack file uses Windows-1252
        df = pd.read_csv(path, encoding="cp1252", low_memory=False)
    df.columns = df.columns.str.strip()
    return df


def load_scenario(key: str, shuffle: bool) -> tuple[str, pd.DataFrame]:
    name, files, benign_only = SCENARIOS[key]
    missing = [f for f in files if not (HERE / f).exists()]
    if missing:
        sys.exit(f"[-] Missing dataset file(s) next to this script: {', '.join(missing)}")
    df = pd.concat([read_csv(HERE / f) for f in files], ignore_index=True)
    if benign_only:
        df = df[df["Label"].str.upper() == "BENIGN"].drop_duplicates()
    if shuffle:  # mix attack and benign rows like real traffic
        df = df.sample(frac=1, random_state=None).reset_index(drop=True)
    return name, df


def stream(url: str, name: str, df: pd.DataFrame, batch: int, delay: float) -> None:
    # JSON has no NaN/Infinity; send them as null and let the server clean them.
    df = df.astype(object).where(pd.notna(df), None)
    df = df.replace([float("inf"), float("-inf")], None)
    print(f"\n[*] {name}: {len(df)} flows -> {url}  (Ctrl+C to stop)\n")
    totals = {"benign": 0, "suspicious": 0, "malicious": 0}
    session = requests.Session()
    try:
        for i in range(0, len(df), batch):
            payload = df.iloc[i:i + batch].to_dict(orient="records")
            r = session.post(url, json=payload, timeout=30)
            if r.status_code != 200:
                print(f"[-] Server returned {r.status_code}: {r.text[:200]}")
                return
            v = r.json().get("verdicts", {})
            for k in totals:
                totals[k] += v.get(k, 0)
            print(f"[>] {min(i + batch, len(df)):4d}/{len(df)}  "
                  f"malicious {v.get('malicious', 0):2d}  suspicious {v.get('suspicious', 0):2d}  "
                  f"AI queue +{r.json().get('queued_for_ai', 0)}")
            time.sleep(delay)
    except requests.exceptions.ConnectionError:
        print(f"\n[-] Could not reach {url}. Is uvicorn running with --host 0.0.0.0, and is the "
              "address right? (run `ipconfig` on the server PC)")
        return
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    print(f"\n[*] Done. ML verdicts so far: {totals} (AI reviews keep arriving on the dashboard)\n")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--server", default=os.getenv("THREAT_SERVER", "localhost:8000"),
                    help="host:port of the FastAPI server (default: %(default)s)")
    ap.add_argument("--scenario", choices=SCENARIOS, help="run one scenario without the menu")
    ap.add_argument("--batch", type=int, default=10, help="flows per request (default: 10)")
    ap.add_argument("--delay", type=float, default=0.1, help="seconds between requests (default: 0.1)")
    ap.add_argument("--no-shuffle", action="store_true", help="send rows in file order")
    args = ap.parse_args()

    host = args.server.removeprefix("http://").removeprefix("https://").rstrip("/")
    url = f"http://{host}/api/logs/ingest"

    if args.scenario:
        stream(url, *load_scenario(args.scenario, not args.no_shuffle), args.batch, args.delay)
        return

    while True:
        print("\n" + "=" * 50 + "\n      AI CYBERSECURITY ATTACK SIMULATOR\n" + "=" * 50)
        print(f" Target: {url}\n")
        for k, (name, _, _) in SCENARIOS.items():
            print(f"  [{k}] {name}")
        print("  [0] Exit\n" + "=" * 50)
        choice = input("Choice: ").strip()
        if choice == "0":
            break
        if choice in SCENARIOS:
            stream(url, *load_scenario(choice, not args.no_shuffle), args.batch, args.delay)
            input("Press Enter to return to the menu...")
        else:
            print("[!] Pick a number from the menu.")


if __name__ == "__main__":
    main()
