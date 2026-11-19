"""Train the ML engine.

    python -m app.train

Training data, in order of preference:
  1. data/Monday-WorkingHours.pcap_ISCX.csv (full CIC-IDS-2017 benign day), if present
  2. otherwise the BENIGN rows of the data/mixed_*.csv simulation files
Flows an analyst marked as false positives on the dashboard are always added as extra
benign examples, so the models learn from corrections.

Attack rows are never used for training, only for the accuracy report at the end.
"""
import glob
import logging
import sys
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import KFold
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from app.config import DATA_DIR, MODEL_DIR, MODEL_PATH
from app.detection.features import ID_COLUMNS, vectorise
from app.detection.ml import calibrate

MONDAY_CSV = DATA_DIR / "Monday-WorkingHours.pcap_ISCX.csv"
MAX_TRAIN_ROWS = 20_000  # One-Class SVM training time grows with the square of this
WEIGHTS = {"svm": 0.7, "iforest": 0.3}
SEED = 42


def read_csv(path) -> pd.DataFrame:
    # Some CIC-IDS files are Windows-1252 (the en dash in "Web Attack – XSS").
    try:
        df = pd.read_csv(path, low_memory=False)
    except UnicodeDecodeError:
        df = pd.read_csv(path, encoding="cp1252", low_memory=False)
    df.columns = df.columns.str.strip()
    return df


def make_models() -> dict:
    return {
        "svm": OneClassSVM(kernel="rbf", gamma="scale", nu=0.05),
        "iforest": IsolationForest(n_estimators=200, random_state=SEED, n_jobs=-1),
    }


def load_training_data() -> tuple[pd.DataFrame, str]:
    if MONDAY_CSV.exists():
        print(f"[*] Using {MONDAY_CSV.name}")
        df = read_csv(MONDAY_CSV)
        source = MONDAY_CSV.name
    else:
        files = sorted(glob.glob(str(DATA_DIR / "mixed_*.csv")))
        if not files:
            sys.exit("[-] No training data found in data/.")
        print(f"[*] {MONDAY_CSV.name} not found - using BENIGN rows from {len(files)} simulation CSVs")
        df = pd.concat([read_csv(f) for f in files], ignore_index=True)
        source = "simulation CSVs (benign rows)"
    df = df[df["Label"].astype(str).str.upper() == "BENIGN"]
    df = df.drop_duplicates(subset=[c for c in df.columns if c not in ID_COLUMNS])

    try:
        from app import store
        fps = store.false_positive_features()
        if fps:
            print(f"[*] Adding {len(fps)} analyst-marked false positives as benign examples")
            df = pd.concat([df, pd.DataFrame(fps)], ignore_index=True)
    except Exception as e:  # database missing or unreadable: train without feedback
        print(f"[!] Skipping dashboard feedback: {e}")

    if len(df) > MAX_TRAIN_ROWS:
        df = df.sample(MAX_TRAIN_ROWS, random_state=SEED)
    return df.reset_index(drop=True), source


def pick_features(df: pd.DataFrame) -> list[str]:
    cols = [c for c in df.columns if c not in ID_COLUMNS]
    numeric = [c for c in cols if pd.to_numeric(df[c], errors="coerce").notna().mean() > 0.95]
    # Constant columns carry no information.
    return [c for c in numeric if pd.to_numeric(df[c], errors="coerce").nunique() > 1]


def to_matrix(df: pd.DataFrame, features: list[str]) -> np.ndarray:
    records = df.to_dict(orient="records")
    return np.array([vectorise(r, features) for r in records])


def train_folds(X: np.ndarray, seed: int = SEED) -> tuple[list[dict], dict, list]:
    """Train one model set per fold. Each set scores the benign rows it never saw;
    those held-out scores calibrate the ensemble. Calibrating on training scores
    would make the models look better than they are."""
    oof = {name: np.zeros(len(X)) for name in WEIGHTS}
    folds, splits = [], []
    for train_idx, test_idx in KFold(5, shuffle=True, random_state=seed).split(X):
        scaler = StandardScaler().fit(X[train_idx])
        models = make_models()
        for name, model in models.items():
            model.fit(scaler.transform(X[train_idx]))
            oof[name][test_idx] = -model.score_samples(scaler.transform(X[test_idx]))
        folds.append({"scaler": scaler, "models": models})
        splits.append((train_idx, test_idx))
    return folds, {k: np.sort(v) for k, v in oof.items()}, splits


def report(bundle: dict, X_benign_oof_scores: np.ndarray) -> None:
    """Detection rate per attack type in the simulation CSVs, and false-positive rate on
    held-out benign traffic, at the default thresholds."""
    from app.config import DEFAULT_SETTINGS
    from app.detection.ml import MLEngine, ml_verdict

    s_t = DEFAULT_SETTINGS["ml_suspicious_threshold"]
    m_t = DEFAULT_SETTINGS["ml_malicious_threshold"]
    eng = MLEngine.__new__(MLEngine)
    eng.bundle = bundle

    print(f"\n=== Accuracy report (suspicious >= {s_t}, malicious >= {m_t}) ===")
    fpr_s = float(np.mean(X_benign_oof_scores >= s_t))
    fpr_m = float(np.mean(X_benign_oof_scores >= m_t))
    print(f"Held-out benign flagged: {fpr_s:.1%} (suspicious or worse), {fpr_m:.1%} malicious")

    files = sorted(glob.glob(str(DATA_DIR / "mixed_*.csv")))
    attacks = pd.concat([read_csv(f) for f in files], ignore_index=True) if files else pd.DataFrame()
    if attacks.empty:
        return
    attacks = attacks[attacks["Label"].astype(str).str.upper() != "BENIGN"]
    scores = eng.score_matrix(to_matrix(attacks, bundle["features"]))
    verdicts = np.array([ml_verdict(s, s_t, m_t) for s in scores])
    print(f"{'Attack type':32} {'flows':>6} {'caught':>7} {'malicious':>10}")
    for label, idx in attacks.groupby("Label").groups.items():
        pos = attacks.index.get_indexer(idx)
        v = verdicts[pos]
        print(f"{str(label):32} {len(v):6d} {np.mean(v != 'benign'):7.1%} {np.mean(v == 'malicious'):10.1%}")
    print(f"{'ALL ATTACKS':32} {len(verdicts):6d} {np.mean(verdicts != 'benign'):7.1%} "
          f"{np.mean(verdicts == 'malicious'):10.1%}")


def main() -> None:
    logging.basicConfig(level=logging.WARNING)
    t0 = time.time()
    df, source = load_training_data()
    features = pick_features(df)
    print(f"[*] {len(df)} benign flows, {len(features)} features")
    X = to_matrix(df, features)

    print("[*] Training 5-fold ensemble and calibrating on held-out folds...")
    folds, calibration, _ = train_folds(X)

    bundle = {
        "features": features,
        "folds": folds,
        "calibration": calibration,
        "weights": WEIGHTS,
        "meta": {"source": source, "benign_rows": len(df), "trained_at": time.time()},
    }
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, MODEL_PATH, compress=3)
    print(f"[+] Saved {MODEL_PATH.relative_to(MODEL_DIR.parent.parent)} in {time.time() - t0:.1f}s")

    # False-positive check: a second, differently split ensemble scores benign rows it
    # never trained on, using the saved calibration.
    check_folds, _, splits = train_folds(X, seed=SEED + 1)
    oof_blend = np.zeros(len(X))
    for fold, (_, test_idx) in zip(check_folds, splits):
        Xs = fold["scaler"].transform(X[test_idx])
        for name, w in WEIGHTS.items():
            oof_blend[test_idx] += w * calibrate(calibration[name], -fold["models"][name].score_samples(Xs))
    report(bundle, oof_blend)


if __name__ == "__main__":
    main()
