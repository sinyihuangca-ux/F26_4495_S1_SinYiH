"""How the ML and AI verdicts combine into one final verdict.

The goal is to cut false positives without letting a single engine hide an attack:
  * a confident AI "benign" can clear an ML "suspicious" (the usual false positive),
  * but when one engine says malicious and the other says benign, the flow is marked
    "suspicious" for an analyst instead of either engine winning outright,
  * low-confidence AI calls are never trusted to clear or escalate anything.
"""
from typing import Optional

RANK = {"benign": 0, "suspicious": 1, "malicious": 2}


def combine(
    ml: Optional[str],
    ai: Optional[str],
    ai_confidence: Optional[float],
    ai_min_confidence: float,
    allowlisted: bool = False,
) -> tuple[str, Optional[str]]:
    """Return (final_verdict, agreement). agreement is None unless both engines gave a verdict."""
    agreement = None
    if ml is not None and ai is not None:
        agreement = "agree" if (ml == "benign") == (ai == "benign") else "disagree"

    if allowlisted:
        return "benign", agreement

    if ai is None:
        return (ml or "benign"), agreement

    confident = (ai_confidence or 0.0) >= ai_min_confidence
    if not confident and ai == "malicious":
        ai_eff = "suspicious"
    else:
        ai_eff = ai

    if ml is None:  # ML switched off: AI alone
        return ai_eff, agreement

    if ml == "benign":
        # AI flagged something ML missed: worth a look, but not proof on its own.
        return ("benign" if ai_eff == "benign" else "suspicious"), agreement

    if ml == "suspicious":
        if ai_eff == "benign":
            return ("benign" if confident else "suspicious"), agreement
        return ai_eff, agreement  # suspicious or (confident) malicious

    # ml == "malicious"
    if ai_eff == "benign" and confident:
        return "suspicious", agreement
    return "malicious", agreement
