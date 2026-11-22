"""ML engine.

Two parts, both trained by `python -m app.train`:
  * Anomaly models (Isolation Forest + One-Class SVM) trained on normal traffic only.
    Each raw score is calibrated against held-out normal traffic, so 0.95 means "more
    unusual than 95% of normal flows". These can flag attacks never seen in training.
  * An attack classifier (when the CIC-IDS-2017 day files were available) trained on
    labelled attacks. It gives the probability that a flow is an attack and names the
    most likely type (DDoS, DoS Hulk, PortScan, SSH-Patator, ...).

The ML score is the higher of the two, so either one can raise a flow. Thresholds
(adjustable in Settings) turn it into benign / suspicious / malicious.
"""
import logging
from typing import Optional

import joblib
import numpy as np

from app.config import MODEL_PATH
from app.detection.features import vectorise

log = logging.getLogger("ml")


def calibrate(sorted_benign_scores: np.ndarray, raw: np.ndarray) -> np.ndarray:
    """Share of benign calibration flows with a lower anomaly score (0-1)."""
    idx = np.searchsorted(sorted_benign_scores, raw, side="right")
    return idx / len(sorted_benign_scores)


class MLEngine:
    def __init__(self, path=MODEL_PATH):
        self.path = path
        self.bundle: Optional[dict] = None
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            log.warning("No model at %s - run `python -m app.train`. ML engine is off.", self.path)
            self.bundle = None
            return
        self.bundle = joblib.load(self.path)
        log.info("Loaded ML bundle trained on %s benign flows (%s)",
                 self.bundle["meta"]["benign_rows"], self.bundle["meta"]["source"])

    @property
    def ready(self) -> bool:
        return self.bundle is not None

    @property
    def feature_names(self) -> list[str]:
        return self.bundle["features"] if self.bundle else []

    def score_matrix(self, X: np.ndarray) -> np.ndarray:
        """Blended 0-1 anomaly score per row of an already-vectorised matrix."""
        b = self.bundle
        total = np.zeros(len(X))
        # The bundle holds one model set per cross-validation fold; their calibrated
        # scores are averaged. Each set is on the same scale as the calibration data.
        for fold in b["folds"]:
            Xs = fold["scaler"].transform(X)
            for name, weight in b["weights"].items():
                raw = -fold["models"][name].score_samples(Xs)  # higher = more anomalous
                total += weight * calibrate(b["calibration"][name], raw)
        return np.clip(total / len(b["folds"]), 0.0, 1.0)

    def analyse(self, rows: list[dict]) -> list[dict]:
        """Per row: combined score, anomaly score, and the classifier's attack name and
        probability (None when no classifier was trained)."""
        if not self.ready or not rows:
            return [{"score": 0.0, "anomaly": 0.0, "attack_type": None, "attack_prob": None} for _ in rows]
        X = np.array([vectorise(r, self.feature_names) for r in rows])
        anomaly = self.score_matrix(X)
        clf = self.bundle.get("classifier")
        if not clf:
            return [{"score": round(float(a), 4), "anomaly": round(float(a), 4),
                     "attack_type": None, "attack_prob": None} for a in anomaly]
        proba = clf["model"].predict_proba(X)
        b = clf["benign_index"]
        attack_prob = 1.0 - proba[:, b]
        masked = proba.copy()
        masked[:, b] = -1.0
        best = masked.argmax(axis=1)
        out = []
        for a, p, k in zip(anomaly, attack_prob, best):
            out.append({
                "score": round(float(max(a, p)), 4),
                "anomaly": round(float(a), 4),
                # Only name a type when the classifier leans towards "attack" at all.
                "attack_type": clf["classes"][k] if p >= 0.5 else None,
                "attack_prob": round(float(p), 4),
            })
        return out

    def score(self, rows: list[dict]) -> list[float]:
        return [r["score"] for r in self.analyse(rows)]


def ml_verdict(score: float, suspicious_t: float, malicious_t: float) -> str:
    if score >= malicious_t:
        return "malicious"
    if score >= suspicious_t:
        return "suspicious"
    return "benign"


ml_engine = MLEngine()
