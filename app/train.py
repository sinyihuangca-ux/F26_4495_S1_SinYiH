"""Train the ML engine.

    python -m app.train

With the CIC-IDS-2017 day files in data/ (*.pcap_ISCX.csv, Monday-Friday) it trains:
  1. Anomaly models (Isolation Forest + One-Class SVM) on normal traffic sampled from
     every day. They need no labels, so they can flag attacks they have never seen.
  2. An attack classifier on the labelled Tue-Fri attacks (DDoS, DoS Hulk, PortScan,
     FTP/SSH brute force, Bot, web attacks, Infiltration, Heartbleed...) plus normal
     traffic. It names known attacks with high accuracy.

Rows the attack simulator sends (data/mixed_*.csv) are excluded, so the dashboard's
accuracy reflects flows the models never trained on. Flows an analyst marked as false
positives are added as extra normal traffic.

Without day files it falls back to the benign rows of the simulation CSVs (anomaly
models only, no classifier).

Takes a few minutes and a few GB of RAM. Files are read one at a time and sampled.
"""
import glob
import sys
import time
from collections import Counter

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.metrics import classification_report
from sklearn.model_selection import KFold, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from app.config import DATA_DIR, MODEL_DIR, MODEL_PATH
from app.detection.features import ID_COLUMNS, normalise_label
from app.detection.ml import calibrate

SEED = 42
WEIGHTS = {"svm": 0.7, "iforest": 0.3}
ANOMALY_ROWS = 20_000         # One-Class SVM training time grows with the square of this
BENIGN_PER_FILE = 25_000      # normal flows sampled from each day file
ATTACK_PER_CLASS = 30_000     # cap per attack type (DoS Hulk alone has 231k rows)
CLASSIFIER_BENIGN = 120_000   # normal flows the classifier sees


def read_csv(path) -> pd.DataFrame:
    # Some CIC-IDS files are Windows-1252 (the dash in "Web Attack – XSS").
    try:
        df = pd.read_csv(path, low_memory=False)
    except UnicodeDecodeError:
        df = pd.read_csv(path, encoding="cp1252", low_memory=False)
    df.columns = df.columns.str.strip()
    df["Label"] = df["Label"].map(normalise_label)
    return df


def numeric_columns(df: pd.DataFrame) -> list[str]:
    return [c for c in df.columns if c not in ID_COLUMNS]


def to_matrix(df: pd.DataFrame, features: list[str]) -> np.ndarray:
    """Same transform as detection.features.vectorise, done column-wise for speed."""
    X = df.reindex(columns=features).apply(pd.to_numeric, errors="coerce").astype("float64")
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0).clip(lower=0.0)
    return np.log1p(X.to_numpy())


def fingerprints(df: pd.DataFrame, cols: list[str]) -> pd.Series:
    """Row identity from the flow's measured values (the day files have no flow IDs)."""
    X = df.reindex(columns=cols).apply(pd.to_numeric, errors="coerce").astype("float64")
    X = X.replace([np.inf, -np.inf], -1.0).fillna(-2.0).round(3)
    return pd.util.hash_pandas_object(X, index=False)


def make_anomaly_models() -> dict:
    return {
        "svm": OneClassSVM(kernel="rbf", gamma="scale", nu=0.05),
        "iforest": IsolationForest(n_estimators=200, random_state=SEED, n_jobs=-1),
    }


# ---------- data loading ----------

CHUNK_ROWS = 100_000  # rows read at a time, so memory stays flat on big files


def _cap(df: pd.DataFrame, n: int, seed: int) -> pd.DataFrame:
    return df if len(df) <= n else df.sample(n, random_state=seed)


def load_day_files(files: list[str]) -> tuple[pd.DataFrame, pd.DataFrame, list[str], dict]:
    """Returns (benign sample, attack sample, feature columns, info).

    Each file is read in chunks; only a running sample is kept (benign rows per file,
    attack rows per type), so even the 692k-row Wednesday file needs little memory."""
    sim_files = sorted(glob.glob(str(DATA_DIR / "mixed_*.csv")))
    sim = pd.concat([read_csv(f) for f in sim_files], ignore_index=True) if sim_files else None
    sim_hashes, sim_cols = set(), None

    benign_parts, attacks_by_type = [], {}
    info = {"excluded_simulator_rows": 0, "files": []}
    features = None
    seed = SEED
    for path in files:
        t0 = time.time()
        benign_kept, rows, n_attacks = None, 0, 0
        # latin-1 never fails to decode; the odd web-attack dash is fixed by normalise_label.
        for chunk in pd.read_csv(path, chunksize=CHUNK_ROWS, encoding="latin-1", low_memory=False):
            seed += 1
            chunk.columns = chunk.columns.str.strip()
            chunk["Label"] = chunk["Label"].map(normalise_label)
            cols = numeric_columns(chunk)
            if features is None:
                features = cols
            if sim is not None:
                if sim_cols != cols:
                    sim_cols, sim_hashes = cols, set(fingerprints(sim, cols).values)
                # Fingerprint before shrinking to float32, so values match the simulator's.
                keep = ~fingerprints(chunk, cols).isin(sim_hashes)
                info["excluded_simulator_rows"] += int((~keep).sum())
                chunk = chunk[keep.values]
            chunk = chunk.drop_duplicates(subset=cols)
            num = chunk[cols].apply(pd.to_numeric, errors="coerce").astype("float32")
            chunk = pd.concat([num, chunk[["Label"]]], axis=1)
            rows += len(chunk)

            benign = chunk[chunk["Label"] == "BENIGN"]
            benign_kept = _cap(benign if benign_kept is None else pd.concat([benign_kept, benign]),
                               BENIGN_PER_FILE, seed)
            for label, g in chunk[chunk["Label"] != "BENIGN"].groupby("Label"):
                n_attacks += len(g)
                prev = attacks_by_type.get(label)
                attacks_by_type[label] = _cap(g if prev is None else pd.concat([prev, g]),
                                              ATTACK_PER_CLASS, seed)
            del chunk, num
        features = [c for c in features if c in benign_kept.columns]
        benign_parts.append(benign_kept)
        name = path.replace("\\", "/").split("/")[-1]
        info["files"].append(name)
        print(f"    {name:62} {rows:>8,} rows  {n_attacks:>7,} attacks  ({time.time() - t0:.0f}s)")

    attacks = pd.concat(attacks_by_type.values(), ignore_index=True)
    benign = pd.concat(benign_parts, ignore_index=True)
    # Constant columns carry no information.
    both = pd.concat([benign[features], attacks[features]])
    features = [c for c in features if both[c].nunique() > 1]
    return benign, attacks, features, info


def load_feedback() -> pd.DataFrame:
    try:
        from app import store
        fps = store.false_positive_features()
    except Exception as e:  # database missing or unreadable: train without feedback
        print(f"[!] Skipping dashboard feedback: {e}")
        return pd.DataFrame()
    if fps:
        print(f"[*] Adding {len(fps)} analyst-marked false positives as normal traffic")
    return pd.DataFrame(fps)


def load_simulation_benign() -> tuple[pd.DataFrame, list[str]]:
    files = sorted(glob.glob(str(DATA_DIR / "mixed_*.csv")))
    if not files:
        sys.exit("[-] No training data found in data/.")
    df = pd.concat([read_csv(f) for f in files], ignore_index=True)
    cols = numeric_columns(df)
    df = df[df["Label"] == "BENIGN"].drop_duplicates(subset=cols)
    features = [c for c in cols if pd.to_numeric(df[c], errors="coerce").nunique() > 1]
    return df, features


# ---------- anomaly models ----------

def train_anomaly(X: np.ndarray, seed: int = SEED):
    """One model set per fold. Each set scores the benign rows it never saw; those
    held-out scores calibrate the ensemble, so 0.9 means 'more unusual than 90% of
    normal traffic' honestly, not on data the models memorised."""
    oof = {name: np.zeros(len(X)) for name in WEIGHTS}
    folds, splits = [], []
    for train_idx, test_idx in KFold(5, shuffle=True, random_state=seed).split(X):
        scaler = StandardScaler().fit(X[train_idx])
        models = make_anomaly_models()
        for name, model in models.items():
            model.fit(scaler.transform(X[train_idx]))
            oof[name][test_idx] = -model.score_samples(scaler.transform(X[test_idx]))
        folds.append({"scaler": scaler, "models": models})
        splits.append((train_idx, test_idx))
    return folds, {k: np.sort(v) for k, v in oof.items()}, splits


def heldout_anomaly_scores(X: np.ndarray, calibration: dict) -> np.ndarray:
    folds, _, splits = train_anomaly(X, seed=SEED + 1)
    out = np.zeros(len(X))
    for fold, (_, test_idx) in zip(folds, splits):
        Xs = fold["scaler"].transform(X[test_idx])
        for name, w in WEIGHTS.items():
            out[test_idx] += w * calibrate(calibration[name], -fold["models"][name].score_samples(Xs))
    return out


# ---------- classifier ----------

def train_classifier(benign: pd.DataFrame, attacks: pd.DataFrame, features: list[str]):
    b = benign.sample(min(len(benign), CLASSIFIER_BENIGN), random_state=SEED)
    data = pd.concat([b, attacks], ignore_index=True)
    X = to_matrix(data, features)
    y = data["Label"].to_numpy()
    counts = Counter(y)
    # Classes with very few rows (Heartbleed: 11) can't be split; train on all of them.
    rare = np.array([counts[label] < 10 for label in y])
    X_tr, X_te, y_tr, y_te = train_test_split(X[~rare], y[~rare], test_size=0.2,
                                              stratify=y[~rare], random_state=SEED)
    X_tr, y_tr = np.vstack([X_tr, X[rare]]), np.concatenate([y_tr, y[rare]])
    clf = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1, class_weight="balanced",
                                         early_stopping=True, random_state=SEED)
    clf.fit(X_tr, y_tr)
    print("\n=== Attack classifier, held-out 20% of the day files ===")
    print(classification_report(y_te, clf.predict(X_te), digits=3, zero_division=0))
    # Refit on everything for the saved model.
    clf_full = HistGradientBoostingClassifier(max_iter=clf.n_iter_, learning_rate=0.1,
                                              class_weight="balanced", early_stopping=False,
                                              random_state=SEED)
    clf_full.fit(X, y)
    classes = list(clf_full.classes_)
    return {"model": clf_full, "classes": classes, "benign_index": classes.index("BENIGN")}


# ---------- report ----------

def simulation_report(bundle: dict, benign_heldout: np.ndarray) -> None:
    from app.config import DEFAULT_SETTINGS
    from app.detection.ml import MLEngine, ml_verdict

    s_t, m_t = DEFAULT_SETTINGS["ml_suspicious_threshold"], DEFAULT_SETTINGS["ml_malicious_threshold"]
    print(f"\n=== Anomaly models: held-out normal traffic flagged (suspicious >= {s_t}) ===")
    print(f"{np.mean(benign_heldout >= s_t):.1%} suspicious or worse, {np.mean(benign_heldout >= m_t):.1%} malicious")

    files = sorted(glob.glob(str(DATA_DIR / "mixed_*.csv")))
    if not files:
        return
    sim = pd.concat([read_csv(f) for f in files], ignore_index=True)
    eng = MLEngine.__new__(MLEngine)
    eng.bundle = bundle
    results = eng.analyse(sim.to_dict(orient="records"))
    verdicts = np.array([ml_verdict(r["score"], s_t, m_t) for r in results])
    named = np.array([r["attack_type"] or "" for r in results])
    print(f"\n=== Combined ML on the simulator's flows (never trained on) ===")
    print(f"{'Dataset label':30} {'flows':>6} {'flagged':>8} {'malicious':>10} {'named right':>12}")
    for label in sorted(sim["Label"].unique()):
        m = (sim["Label"] == label).to_numpy()
        flagged = np.mean(verdicts[m] != "benign")
        right = np.mean(named[m] == label) if label != "BENIGN" else np.nan
        print(f"{label:30} {m.sum():6d} {flagged:8.1%} {np.mean(verdicts[m] == 'malicious'):10.1%} "
              f"{'' if np.isnan(right) else f'{right:.1%}':>12}")


# ---------- main ----------

def main() -> None:
    t0 = time.time()
    day_files = sorted(glob.glob(str(DATA_DIR / "*.pcap_ISCX.csv")))
    feedback = load_feedback()
    classifier = None

    if day_files:
        print(f"[*] Reading {len(day_files)} CIC-IDS-2017 day files (simulator rows are excluded):")
        benign, attacks, features, info = load_day_files(day_files)
        print(f"[*] Excluded {info['excluded_simulator_rows']} rows that the simulator sends")
        print(f"[*] {len(benign):,} normal flows sampled; attacks: "
              + ", ".join(f"{k} {v:,}" for k, v in attacks['Label'].value_counts().items()))
        if not feedback.empty:
            benign = pd.concat([benign, feedback], ignore_index=True)
        source = f"{len(day_files)} CIC-IDS-2017 day files"
    else:
        print("[*] No *.pcap_ISCX.csv day files in data/ - using BENIGN rows of the simulation CSVs.")
        print("    (Anomaly models only. Add the CIC-IDS-2017 day files for the attack classifier.)")
        benign, features = load_simulation_benign()
        if not feedback.empty:
            benign = pd.concat([benign, feedback], ignore_index=True)
        attacks, source = None, "simulation CSVs (benign rows)"

    anomaly_rows = benign.sample(min(len(benign), ANOMALY_ROWS), random_state=SEED)
    print(f"[*] {len(features)} features. Training anomaly models on {len(anomaly_rows):,} normal flows...")
    X = to_matrix(anomaly_rows, features)
    folds, calibration, _ = train_anomaly(X)

    if attacks is not None and len(attacks):
        print(f"[*] Training attack classifier on {min(len(benign), CLASSIFIER_BENIGN) + len(attacks):,} flows...")
        classifier = train_classifier(benign, attacks, features)

    bundle = {
        "features": features,
        "folds": folds,
        "calibration": calibration,
        "weights": WEIGHTS,
        "classifier": classifier,
        "meta": {
            "source": source,
            "benign_rows": len(anomaly_rows),
            "attack_classes": classifier["classes"] if classifier else [],
            "trained_at": time.time(),
        },
    }
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, MODEL_PATH, compress=3)
    size_mb = MODEL_PATH.stat().st_size / 1e6
    print(f"\n[+] Saved app/models/{MODEL_PATH.name} ({size_mb:.1f} MB) in {time.time() - t0:.0f}s")

    simulation_report(bundle, heldout_anomaly_scores(X, calibration))
    print("\n[*] Restart uvicorn to load the new model.")


if __name__ == "__main__":
    main()
