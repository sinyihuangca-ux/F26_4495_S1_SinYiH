"""Paths, environment loading and default settings.

Secrets (AI provider keys) live in the project-root .env file.
Everything else the dashboard can change is stored in SQLite (see store.py).
"""
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent
APP_DIR = ROOT_DIR / "app"
DATA_DIR = ROOT_DIR / "data"
MODEL_DIR = APP_DIR / "models"
MODEL_PATH = MODEL_DIR / "ml_bundle.joblib"
ENV_PATH = Path(os.getenv("THREAT_ENV_FILE", ROOT_DIR / ".env"))
DB_PATH = Path(os.getenv("THREAT_DB_PATH", ROOT_DIR / "threats.db"))

load_dotenv(ENV_PATH)

# Secrets the dashboard is allowed to write. Values are never sent back unmasked.
SECRET_KEYS = {
    "gemini": "GEMINI_API_KEY",
    "groq": "GROQ_API_KEY",
    "openai": "OPENAI_API_KEY",
    "claude": "ANTHROPIC_API_KEY",
}

PROVIDERS = ["gemini", "groq", "openai", "claude"]

# Allowed values for settings that are a fixed choice.
CHOICE_SETTINGS = {"notify_min_verdict": ("malicious", "suspicious")}

# Non-secret settings and their defaults. Types here are used to validate updates.
DEFAULT_SETTINGS: dict = {
    "ml_enabled": True,
    "ai_enabled": True,
    # ML score (0-1) at or above which a flow is "suspicious" / "malicious".
    "ml_suspicious_threshold": 0.85,
    "ml_malicious_threshold": 0.95,
    # Share of ML-benign flows the AI also checks, so it can catch what ML misses.
    "ai_sample_rate": 0.10,
    # AI verdicts below this confidence are treated as "suspicious" rather than trusted.
    "ai_min_confidence": 0.60,
    # Seconds to wait between AI calls (keeps free tiers from rate-limiting).
    "ai_min_interval": 2.0,
    "ai_batch_size": 10,
    "provider_order": list(PROVIDERS),
    "models": {
        "gemini": "gemini-2.5-flash",
        "groq": "openai/gpt-oss-120b",
        "openai": "gpt-4o-mini",
        "claude": "claude-haiku-4-5",
    },
    # Browser notifications raised by the dashboard (see web-frontend lib/notify.tsx).
    "notify_enabled": True,
    # Lowest final verdict that notifies: "malicious" or "suspicious".
    "notify_min_verdict": "malicious",
    # Per incident (target IP+port): at most one popup per this many seconds;
    # flows in between are rolled into the next update.
    "notify_cooldown": 30,
}

# Model names providers have shut down -> what to use instead.
# Groq retired the Llama 3.x models for free/developer accounts on 2026-08-16.
RETIRED_MODELS = {
    "llama-3.3-70b-versatile": "openai/gpt-oss-120b",
    "llama-3.1-8b-instant": "openai/gpt-oss-20b",
}

# Clerk: set one of these so the backend can verify dashboard users.
CLERK_JWKS_URL = os.getenv("CLERK_JWKS_URL", "")
CLERK_PUBLISHABLE_KEY = os.getenv("CLERK_PUBLISHABLE_KEY", "") or os.getenv(
    "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY", ""
)

CORS_ORIGINS = [
    o.strip()
    for o in os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
    if o.strip()
]
