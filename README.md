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

Run it from the project root (`F26_4495_S1_SinYiH`), not from inside
`Implementation\apps\web-frontend`. Pick **one** of these setups; don't run both
commands, or a second backend and dashboard will fight over the same ports.

**One PC (testing on your own machine):**

```powershell
.\start.ps1 -Simulate
```

This opens three windows: backend, dashboard and attack simulator (aimed at
`localhost`). `-Simulate` does everything plain `.\start.ps1` does, plus the simulator.

**Two PCs (a second machine plays the attacker):**

On the main PC:

```powershell
.\start.ps1
ipconfig                 # note this PC's IPv4 address, e.g. 192.168.1.50
```

On the attacker PC (copy the `data` folder over first):

```powershell
pip install pandas requests
cd data
python attack_simulator.py --server 192.168.1.50:8000
```

If the attacker PC can't connect, allow port 8000 through Windows Firewall on the
main PC (admin PowerShell, once):

```powershell
New-NetFirewallRule -DisplayName "Threat platform 8000" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow
```

The first run creates `.venv`, installs the Python and npm packages, trains the model
if it's missing, and creates the root `.env` (all keys live there). Later runs skip
whatever is already in place. The backend and dashboard each open in their own
window; close them to stop. If Windows blocks the script, run
`powershell -ExecutionPolicy Bypass -File .\start.ps1`.

You still need to put your Clerk keys in the root `.env` once (see **Keys** below).

### Step by step

All commands start from the project root.

### 1. Backend (FastAPI + ML engine)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
# create .env in the project root with your Clerk keys (see Keys below; start.ps1 makes a blank one)
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Check http://localhost:8000/api/health. `model_loaded` should be `true`.

### 2. Dashboard (Next.js)

```powershell
cd Implementation/apps/web-frontend
# (no .env.local needed: the dashboard reads the root .env)
npm install
npm run dev
```

Open http://localhost:3000/dashboard and sign in. Under **Settings**:

- paste at least one AI key (Groq's free tier works). It is sent to the backend and
  saved in the root `.env`; the dashboard only ever shows it masked.
- switch the ML or AI engine on or off, and tune the thresholds.
- choose which attacks raise notifications, and click **Send test notification** to check
  Windows notifications work.

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
4. **AI advisor ("Analyse priority").** Flagged flows are grouped into incidents
   (per target service, a separate "scan" incident when one source touches many ports,
   and a new incident after a 5-minute quiet gap). For each incident the advisor gives
   its best assessment of the attack, a confidence level, the evidence behind it,
   specific steps, and what to check to confirm it. Briefings are saved; clicking again
   only re-analyses incidents that are new or have grown, and the refresh icon on a card
   forces a re-read.
5. **Analyst feedback.** On the Threats & Logs page you can mark a flow as a real
   threat or a false positive (optionally allowlisting its source IP and port).
   False positives become extra normal-traffic examples the next time you train.

The dataset's `Label` column is stored only to score accuracy on the dashboard. It
never decides a verdict.

## Keys

Every key lives in **one file: `.env` in the project root** (next to `app/` and
`start.ps1`). The backend reads it directly; the dashboard reads it through
`next.config.ts`. It's git-ignored, so never commit it.

```dotenv
# Clerk sign-in: https://dashboard.clerk.com -> API keys
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_...
CLERK_SECRET_KEY=sk_test_...
NEXT_PUBLIC_CLERK_SIGN_IN_FALLBACK_REDIRECT_URL=/dashboard
NEXT_PUBLIC_CLERK_SIGN_UP_FALLBACK_REDIRECT_URL=/dashboard
NEXT_PUBLIC_API_URL=localhost:8000
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
# AI keys: entered on the dashboard's Settings page, which writes them here
GEMINI_API_KEY=
GROQ_API_KEY=
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
```

`start.ps1` creates this file with blank values on the first run. If you still have the
old `Implementation/apps/web-frontend/.env.local`, it moves the Clerk keys from there
into the root `.env` once; after that `.env.local` is ignored and can be deleted. After
changing the Clerk keys, restart the dashboard.

## Attack notifications

When an attack comes in, the backend shows a **Windows notification** on the PC running
uvicorn. It works with the browser closed, and clicking it opens Threats & Logs. While the
dashboard is open, the same alerts also appear as banners on the page.

- One notification per attacked target (IP + port). Further flows are rolled into a
  "+N more" update at most once per cooldown (default 30 s). A source that probes 3+
  targets within a minute counts as one port-scan incident.
- Settings → Attack notifications: switch them off, choose malicious only (default) or
  malicious + suspicious, set the cooldown, and send a test notification.
- Needs the backend on Windows 10/11 with `windows-toasts` installed (included in
  `requirements.txt`, so `start.ps1` installs it). On other systems notifications are
  silently skipped.
- Nothing showing? Check Windows Settings → System → Notifications, and that Do Not
  Disturb / Focus is off. The notifications show under Command Prompt's name, because
  that's the identity Windows lets an unpackaged Python app use, with "AI Threat
  Mitigation" as the source line.

## Training the ML engine

```powershell
python -m app.train
```

Put the CIC-IDS-2017 day files (`*.pcap_ISCX.csv`, Monday-Friday, ~885 MB) in `data/`
first. They're git-ignored. Training reads them in 100k-row chunks, takes a few minutes and
about 1 GB of RAM, and writes `app/models/ml_bundle.joblib` (about 6 MB). Restart
uvicorn afterwards to load it.

It trains two things:

- **Anomaly models** (Isolation Forest + One-Class SVM) on normal traffic sampled from
  all five days. No labels, so they can flag attacks they've never seen.
- **An attack classifier** on the labelled Tue-Fri attacks (DDoS, DoS Hulk/GoldenEye/
  slowloris/Slowhttptest, PortScan, FTP/SSH-Patator, Bot, web attacks, Heartbleed).
  It names known attacks.

A flow's ML score is the higher of the two. The classifier's attack name appears in the
ML column, the incident cards and the notifications.

The rows the simulator sends (`data/mixed_*.csv`) are excluded from training, so the
accuracy panel shows performance on flows the models never saw. The dataset's only
Infiltration and SQL-injection examples are all in those files, so the classifier can't
learn those two, and the anomaly models catch them instead. Flows you mark as false
positives are added as extra normal traffic the next time you train.

The script prints a held-out accuracy report per attack type. On the full dataset it
catches 100% of the simulator's DDoS, PortScan, brute-force and XSS flows, about 89% of
Infiltration and most SQL injection, and wrongly flags roughly 10-13% of normal flows,
mostly as "suspicious" (the AI review is there to clear those).

Without the day files it falls back to the benign rows of the four simulation CSVs:
anomaly models only, with a high false-positive rate.

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
  winnotify.py            Windows notifications for incoming attacks
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
| GET | `/api/incidents` | Current incidents with their saved AI briefing (no AI call). |
| POST | `/api/analyze-threats` | AI advisor: briefs new or grown incidents; `{"force_keys": [...]}` re-briefs specific ones. |
| GET | `/api/health` | Model status, AI provider status, queue size. |
| WS | `/ws/alerts` | Live `FLOW`, `FLOW_UPDATED` and `STATS` messages. |

Interactive docs: http://localhost:8000/docs

## Security notes

- Endpoints that change settings, feedback or data need a signed-in Clerk user. The
  backend checks the token when `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` is set in the root `.env`.
  Without it, they only accept requests from the machine running the backend.
- `/api/logs/ingest` is open on purpose so the simulator on another PC can post to it.
  Run the backend on a trusted network.
- `.env` and `threats.db` are git-ignored. Never commit them.

## Troubleshooting

- **`ModuleNotFoundError: No module named 'app'`.** Run uvicorn from the project root, not from inside `app/`.
- **WebSocket 404, or "No supported WebSocket library detected".** Run `python -m pip install "uvicorn[standard]"`.
- **The dashboard says "Disconnected".** Check uvicorn is running, then check the address under Settings → Backend server. From another PC, the backend must be started with `--host 0.0.0.0` and that PC's origin added to `CORS_ORIGINS` in `.env`.
- **Settings says "Clerk is not configured on the backend".** Add `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` to the root `.env` and restart uvicorn, or open the dashboard on the backend machine.
- **AI column says "unavailable".** Hover it to see why. Usually the key is wrong or the provider is rate-limiting; `/api/health` shows each provider's status.
- **`InconsistentVersionWarning` when loading the model.** Your scikit-learn version differs from the one used for training. Run `python -m app.train` to retrain.
