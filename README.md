# AI-Powered Threat Detection & Mitigation Platform

A cross-PC network threat monitor. An attack simulator streams CIC-IDS-2017 flow
records to a FastAPI backend. Two engines judge every flow on their own:

- **ML engine**: an Isolation Forest and a One-Class SVM trained only on normal traffic.
- **AI engine**: an LLM (Gemini, Groq, OpenAI or Claude, with automatic failover)
  that reviews the flows the ML engine is unsure about, plus a random sample of the rest.

The Next.js dashboard shows both verdicts side by side, the combined verdict, live
accuracy against the dataset labels, and lets an analyst mark false positives.

Mid-course video:
https://collegedouglas-my.sharepoint.com/:f:/r/personal/huangs36_student_douglascollege_ca/_layouts/15/onedrive.aspx?id=%2Fpersonal%2Fhuangs36%5Fstudent%5Fdouglascollege%5Fca%2FDocuments%2FCSIS%204495%20Applied%20Research%20Project%2FMidCourseProgress%20Video&share=cgqlpxrQD40%2DR4JV%2D3YSZd4mEgUCPofkm4yp868NyOVVEzpGVw

## Quick start

### One command (Windows)

From the project root (`F26_4495_S1_SinYiH`):

```powershell
.\start.ps1              # backend + dashboard, opens the browser
.\start.ps1 -Simulate    # also starts the attack simulator against this PC
```

The first run creates `.venv`, installs the Python and npm packages, trains the model
if it's missing, and creates `.env` / `.env.local` from the examples. Later runs skip
whatever is already in place. The backend and dashboard each open in their own
window; close them to stop. If Windows blocks the script, run
`powershell -ExecutionPolicy Bypass -File .\start.ps1`.

You still need to put your Clerk keys in `Implementation/apps/web-frontend/.env.local`
(and `CLERK_PUBLISHABLE_KEY` in the root `.env`) once.

### Step by step

All commands start from the project root.

### 1. Backend (FastAPI + ML engine)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
copy .env.example .env          # then set CLERK_PUBLISHABLE_KEY (see below)
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Check http://localhost:8000/api/health. `model_loaded` should be `true`.

### 2. Dashboard (Next.js)

```powershell
cd Implementation/apps/web-frontend
copy .env.example .env.local    # fill in your Clerk keys
npm install
npm run dev
```

Open http://localhost:3000/dashboard and sign in. Under **Settings**:

- paste at least one AI key (Groq's free tier works). It is sent to the backend and
  saved in the root `.env`; the dashboard only ever shows it masked.
- switch the ML or AI engine on or off, and tune the thresholds.
- set an ntfy topic if you want phone notifications for malicious flows.

### 3. Attack simulator (second PC or terminal)

Copy the `data/` folder to the other machine (it needs `pip install pandas requests`), then:

```powershell
cd data
python attack_simulator.py --server 192.168.1.50:8000      # your server's IPv4 from ipconfig
```

Pick a scenario (DDoS, PortScan, web attacks, infiltration, or benign-only traffic).
`--scenario 1` skips the menu, and `--help` lists the other options.

## How a flow is judged

1. **ML score (0-1).** Each model's anomaly score is compared with held-out normal
   traffic, so 0.90 means "more unusual than 90% of normal flows". At or above the
   *suspicious* threshold (default 0.85) the flow is suspicious; at or above the
   *malicious* threshold (default 0.95) it is malicious.
2. **AI review.** Every ML-suspicious or ML-malicious flow, plus 10% of ML-benign
   flows, goes to the AI in batches through a rate-limited queue. The AI returns its
   own verdict, a guessed attack type, a confidence and a one-line reason. If the ML
   engine is off, the AI reviews everything.
3. **Combined verdict** (`app/detection/verdict.py`):
   - a confident AI "benign" clears an ML "suspicious", which is the usual false positive.
   - if one engine says malicious and the other says benign, the flow becomes "suspicious" for a human to decide.
   - AI calls below the confidence threshold (default 60%) can't clear or escalate anything.
   - flows matching an allowlist rule are never alerted on.
4. **Analyst feedback.** On the Logs and Threats pages you can mark a flow as a real
   threat or a false positive (optionally allowlisting its source IP and port).
   False positives become extra normal-traffic examples the next time you train.

The dataset's `Label` column is stored only to score accuracy on the dashboard. It
never decides a verdict.

## Training the ML engine

```powershell
python -m app.train
```

This writes `app/models/ml_bundle.joblib` and prints detection and false-positive
rates. Restart uvicorn afterwards to load the new model.

By default it trains on the benign rows of the four `data/mixed_*.csv` files (165
unique flows). That's enough to work, but the false-positive rate is high. For a much
better model, download `Monday-WorkingHours.pcap_ISCX.csv` from the
[CIC-IDS-2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html), put it in
`data/`, and run the same command: it uses the Monday file automatically (capped at
20,000 rows). The file is git-ignored because of its size.

## Project layout

```
app/                      FastAPI backend
  main.py                 routes: /api/logs/ingest, /api/flows, /api/stats, /api/settings,
                          /api/analyze-threats, /api/rss, /ws/alerts
  detection/ml.py         ML engine (5-fold Isolation Forest + One-Class SVM ensemble)
  detection/ai.py         AI engine: prompt, provider failover, background review queue
  detection/verdict.py    rules for combining the two verdicts
  detection/features.py   CIC-IDS record -> feature vector
  store.py                SQLite (threats.db): flows, feedback, allowlist, settings
  auth.py                 Clerk token check for endpoints that change things
  notify.py               ntfy.sh push notifications (rate-limited, non-blocking)
  train.py                training script
  models/ml_bundle.joblib trained models
data/                     attack_simulator.py and the four simulation CSVs
tests/                    backend tests (python -m pytest -q)
Implementation/apps/web-frontend/   Next.js 16 dashboard with Clerk sign-in
DocumentsAndReports/      proposal and progress reports
```

## API at a glance

| Method | Path | What it does |
| --- | --- | --- |
| POST | `/api/logs/ingest` | Body: JSON list of CIC-IDS flow records. Used by the simulator. |
| GET | `/api/flows` | Stored flows. Filters: `alerts_only`, `verdict`, `q`, `limit`. |
| GET | `/api/flows/export.csv` | CSV export. |
| POST | `/api/flows/{id}/feedback` | `{"feedback": "false_positive" or "confirmed" or null, "allowlist": bool}` |
| GET | `/api/stats` | Counts and per-engine accuracy. |
| GET/PUT | `/api/settings` | Engine switches, thresholds, providers and keys (keys always masked). |
| POST | `/api/analyze-threats` | AI briefing that ranks the current threats by severity. |
| GET | `/api/health` | Model status, AI provider status, queue size. |
| WS | `/ws/alerts` | Live `FLOW`, `FLOW_UPDATED` and `STATS` messages. |

Interactive docs: http://localhost:8000/docs

## Security notes

- Endpoints that change settings, feedback or data need a signed-in Clerk user. The
  backend checks the token when `CLERK_PUBLISHABLE_KEY` is set in the root `.env`.
  Without it, they only accept requests from the machine running the backend.
- `/api/logs/ingest` is open on purpose so the simulator on another PC can post to it.
  Run the backend on a trusted network.
- `.env`, `.env.local` and `threats.db` are git-ignored. Never commit them.

## Troubleshooting

- **`ModuleNotFoundError: No module named 'app'`.** Run uvicorn from the project root, not from inside `app/`.
- **WebSocket 404, or "No supported WebSocket library detected".** Run `python -m pip install "uvicorn[standard]"`.
- **The dashboard says "Disconnected".** Check uvicorn is running, then check the address under Settings → Backend server. From another PC, the backend must be started with `--host 0.0.0.0` and that PC's origin added to `CORS_ORIGINS` in `.env`.
- **Settings says "Clerk is not configured on the backend".** Add `CLERK_PUBLISHABLE_KEY` to the root `.env` and restart uvicorn, or open the dashboard on the backend machine.
- **AI column says "unavailable".** Hover it to see why. Usually the key is wrong or the provider is rate-limiting; `/api/health` shows each provider's status.
- **`InconsistentVersionWarning` when loading the model.** Your scikit-learn version differs from the one used for training. Run `python -m app.train` to retrain.
