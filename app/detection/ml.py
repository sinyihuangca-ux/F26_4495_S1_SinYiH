"""ML engine: Isolation Forest + One-Class SVM, trained on benign traffic only.

Each model's raw anomaly score is calibrated against held-out benign traffic, so a
score of 0.95 means "more unusual than 95% of normal flows seen in training".
The two calibrated scores are blended into one 0-1 ML score, and thresholds
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

    def score(self, rows: list[dict]) -> list[float]:
        if not self.ready or not rows:
            return [0.0] * len(rows)
        X = np.array([vectorise(r, self.feature_names) for r in rows])
        return self.score_matrix(X).round(4).tolist()


def ml_verdict(score: float, suspicious_t: float, malicious_t: float) -> str:
    if score >= malicious_t:
        return "malicious"
    if score >= suspicious_t:
        return "suspicious"
    return "benign"


ml_engine = MLEngine()
