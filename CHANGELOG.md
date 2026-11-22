# Changelog

## 2.7.0 - 2026-11-22

### All keys in one root `.env`
- The dashboard now reads the project-root `.env` (`next.config.ts` loads it at startup),
  so the Clerk keys sit next to the AI keys in one file. Values there take priority over
  any old `web-frontend/.env.local`, which is no longer needed. Tested in production
  and dev mode: the server and the sign-in check get `CLERK_SECRET_KEY`, and the
  publishable key is built into the pages.
- One name for the publishable key, `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY`, used by both
  the dashboard and the backend's sign-in check. The older `CLERK_PUBLISHABLE_KEY` still
  works.
- `start.ps1`: creates a single root `.env` template (Clerk, backend address, CORS, AI
  keys) and no `.env.local`. On first run it moves real Clerk keys from an old
  `web-frontend/.env.local` into the root `.env` (placeholders are skipped, existing
  values are never overwritten), then stops with a clear message if the publishable key
  is still missing. Files are written without a BOM so both Python and Node parse line 1.
- README: a new **Keys** section with the full `.env` layout.

## 2.6.0 - 2026-11-21 (branch `feature/windows-notifications`)

- **Real Windows notifications from the backend** (`app/winnotify.py`, using the
  `windows-toasts` package). The browser's notifications only worked while a dashboard
  tab was open; these appear on the PC running uvicorn even with the browser closed.
  Clicking one opens Threats & Logs in the default browser.
- They use the same rules as before: one per incident (target IP + port, or one port-scan
  incident per source), "+N more" roll-ups after the cooldown, the malicious /
  malicious + suspicious setting, and an AI review that escalates a flow can notify.
  Notifications for the same incident replace each other in the Action Center.
  Showing one runs off the event loop and can never break ingestion.
- The dashboard keeps its in-page banners. Its browser notifications and the "Enable
  browser notifications" button are removed to avoid duplicates.
- Settings → Attack notifications shows whether Windows notifications are available and
  has a **Send test notification** button (`POST /api/notifications/test`, sign-in required).
  `/api/health` reports `notifications.windows`.
- `requirements.txt`: `windows-toasts>=1.3` (installed only on Windows).
- Tests: 32.

## 2.5.0 - 2026-11-20 (branch `feature/notifications`)

### ML engine trained on the full CIC-IDS-2017 week
- `python -m app.train` now uses every `data/*.pcap_ISCX.csv` day file (Monday-Friday)
  instead of only Monday:
  - anomaly models train on normal traffic sampled from all five days;
  - **new attack classifier** (HistGradientBoosting) trained on the labelled Tue-Fri
    attacks: 12 attack types plus normal. It reaches 98.6% accuracy on a held-out 20%.
  - The ML score is the higher of the anomaly score and the classifier's attack
    probability, and the classifier's attack name is stored with each flow
    (`ml_attack_type`, `ml_attack_prob`, `ml_anomaly`; existing databases are migrated).
- **The simulator's rows are excluded from training** (matched on their measured values),
  so the accuracy panel shows performance on unseen flows. On those: DDoS, PortScan,
  web brute force and XSS 100% flagged; Infiltration 89% and SQL injection 76% (no
  training examples remain for either, so only the anomaly models catch them); about
  10-13% of normal flows flagged, mostly as suspicious.
- Labels are normalised ("Web Attack \ufffd XSS" and similar become "Web Attack - XSS").
- Files are read in 100k-row chunks, keeping only a running sample (25k normal flows per
  day, at most 30k per attack type, stored as float32). Peak memory is about 1 GB; the
  first version loaded whole files and ran out of memory on the 692k-row Wednesday file.
  The run takes a few minutes, and the saved model is about 6 MB.
- The classifier's attack names appear in the ML column, the incident cards ("Classifier
  says"), notifications and the AI advisor's evidence. Settings shows whether a classifier
  is loaded.
- `.gitignore` now excludes every `data/*.pcap_ISCX.csv`; previously six of the eight day
  files would have been committed.
- Tests: 29.

## 2.4.0 - 2026-11-20 (branch `feature/notification`)

### Attack notifications from the dashboard
- **Removed ntfy.sh.** It only worked with the ntfy app open. `app/notify.py`, the ntfy
  topic setting and `NTFY_TOPIC` are gone.
- **The dashboard now raises the notifications itself** (`lib/notify.tsx`):
  - an alert banner on the page when the dashboard is in view;
  - a Windows/browser notification when the tab is in the background or minimised
    (needs one-time permission: Settings -> Attack notifications -> Enable browser
    notifications);
  - clicking either one opens Threats & Logs.
- **One popup per incident.** The first qualifying flow to a target (IP + port) notifies
  at once. Further flows are rolled into a "+N more" update, at most once per cooldown
  (default 30 s). A source that hits 3+ different ports within a minute is treated as
  one port-scan incident, so a 92-port scan gives about 5 notifications instead of 92.
  Repeat notifications for the same incident replace each other instead of stacking.
- **New setting `notify_min_verdict`**: notify on malicious flows only (default) or on
  malicious + suspicious. Notifications can also be switched off. These settings are
  included in `/api/health`, so every open dashboard tab reads them without signing in.
- Works while at least one dashboard tab is open. It doesn't need the ntfy app or any
  other service.

### start.ps1
- If an `.env.example` file is missing (both were removed from the repo), it now writes a
  blank `.env` / `.env.local` template itself instead of failing.
- It now stops with a clear message when `web-frontend\.env.local` has no real Clerk
  publishable key, instead of the dashboard crashing with "Publishable key not valid".

- Tests: 27 (added notification settings).

## 2.3.0 - 2026-11-20

- **Merged the Logs and Threats pages** into one "Threats & Logs" page at `/logs`. They
  showed largely the same flows. From top to bottom it has the active threat types next
  to detection accuracy, the AI advisor, then the audit log. The audit log has a new
  "Needs review" filter, now the default, which replaces the Threats page's separate table.
  The sidebar has one entry instead of two, and `/threats` redirects to `/logs`.

## 2.2.0 - 2026-11-19

### AI advisor (the "Analyse priority" briefing)
- **Rebuilt around incidents instead of category counts.** The old briefing only saw
  totals like `{"Suspicious traffic": 732}`, so its advice was generic. Flagged flows
  are now grouped into incidents (`app/detection/incidents.py`):
  - by target service (dst IP + port);
  - a source that touches 10+ ports only lightly becomes one "scan" incident (its heavy
    traffic to a single port stays a separate target incident, so a DDoS and a port scan
    from the same attacker IP aren't merged);
  - a quiet gap of 5+ minutes starts a new incident, so separate attack runs stay apart.
- Each incident carries measured evidence: rate, sources and targets, median packet,
  byte and duration values, TCP flag shares, ML score range, and per-flow AI verdicts.
  The dataset label is still never included.
- The advisor commits to an assessment for each incident (e.g. "HTTP flood (DDoS)") with
  a confidence level, the specific evidence behind it, alternative explanations, concrete
  steps for that host and port (no commands), and what to check to confirm it.
- **Briefings are saved** (`incident_briefs` table). "Analyse priority" only sends incidents
  that are new, or have grown by at least 10% (and at least 5 flows) since their last
  briefing, so incidents it has already read don't cost tokens. Each card has a refresh
  button to force a re-read. New endpoint `GET /api/incidents` shows saved briefings
  without calling the AI.

- **ML and AI side by side in each incident card** (ported from Sin-Yi's split
  "ML Detected Results / AI Detection Results" briefing in her `app/page.tsx`, commit
  8345a36/90c8ace). Left column: what the ML engine flagged (verdict counts, score
  median and range, rate, sources or ports). Right column: the AI assessment. The
  advisor now spans the full page width on Dashboard and Threats so both columns fit;
  they stack on narrow screens.
- Merged with Sin-Yi's 2026-11-19 commits: her `app/page.tsx` (settings drawer + split
  briefing) and the `/api/analyze-threats` endpoint she added to `initial-app/` are
  superseded by the Settings page, the incident advisor above and the main backend.
  Her NotificationBell fix (stray `>`) was already in the rebuilt component.

### Per-flow AI review
- Each flow is now sent with its context from the last 10 minutes: flows to the same
  IP+port, distinct sources, time span, and ports/hosts touched by the same source. A
  DDoS or brute force looks ordinary one flow at a time, so this lets the AI name volume
  attacks. The prompt also asks it to name an attack type whenever it flags a flow.

### Fixes
- Groq retired `llama-3.3-70b-versatile` on 2026-08-16 (every Groq call was returning
  404). The default is now `openai/gpt-oss-120b`, and saved settings that still use a
  retired name are switched automatically.
- The source port is stored with each flow, for incident evidence.
- Tests: 26 (added grouping, briefing cache, per-flow context, model migration).

## 2.1.0 - 2026-11-19

- Added `start.ps1`, which starts the backend and dashboard with one command, each in its own
  window. It handles first-run setup (venv, pip and npm installs, model training, `.env`
  files) and skips any step that's already done. `-Simulate` also starts the attack
  simulator against this PC, and `-NoBrowser` skips opening the dashboard.
- `next.config.ts`: `turbopack.root` is now an absolute path, which removes the
  "turbopack.root should be absolute" warning.
- README: explains the one-PC (`.\start.ps1 -Simulate`) and two-PC (`.\start.ps1` +
  simulator on the other machine) setups, and the firewall rule for port 8000.

## 2.0.0 - 2026-11-19 (branch `rebuild`)

A rebuild of the backend, simulator and dashboard. The core flow is unchanged: the
simulator posts CIC-IDS-2017 records to `/api/logs/ingest`, the backend scores them,
and the dashboard shows alerts live over `/ws/alerts`. Folder names are unchanged.

### Detection
- **Removed the label shortcut.** `/api/logs/ingest` used to raise an alert whenever
  the CSV's `Label` column wasn't BENIGN, so the dashboard showed the dataset's answers
  rather than the model's. The label is now stored only to score accuracy.
- **Retrained the ML engine.** The old Isolation Forest used 8 features and, judged
  without the label shortcut, caught about 6% of attacks. The One-Class SVM was in the
  code, but its model file was never saved, so it never ran. The new engine is a 5-fold
  ensemble of both models over 66 log-scaled features, calibrated on held-out normal
  traffic. On the repo's data it catches 66% of attack flows; 11.5% of held-out normal
  flows land in "suspicious", which is what the AI review is for. See `python -m app.train`.
- **Added three verdict levels** (benign / suspicious / malicious) with thresholds
  you can adjust, instead of a yes/no flag.
- **Added the AI engine as a second, independent judge.** It reviews ML-flagged flows
  plus a configurable sample of ML-benign ones, through a rate-limited background
  queue with Gemini → Groq → OpenAI → Claude failover. Providers that return 429 or
  reject their key are skipped for a while.
- **Added combination rules** (`app/detection/verdict.py`), an ML-vs-AI agreement flag,
  analyst feedback (confirmed / false positive), and an allowlist. False positives
  feed back into training.
- Either engine can be switched off from Settings.

### Backend
- Split `app/main.py` into `detection/`, `store.py`, `auth.py`, `notify.py`, `train.py`.
- Flows, feedback, allowlist and settings are stored in SQLite (`threats.db`) instead of
  each browser's localStorage, so history survives a browser change and all pages agree.
- AI keys are entered on the Settings page, written to the backend `.env`, and only
  ever returned masked. The dashboard no longer calls Gemini directly from the browser.
- Endpoints that change settings or data check the Clerk session token. Without Clerk
  configured they only accept requests from the local machine.
- ntfy alerts are now async and rate-limited, and the topic comes from Settings or `.env`. Previously
  every flagged row made a blocking `requests.post`, and the topic was hard-coded.
- New endpoints: `/api/flows`, `/api/flows/export.csv`, `/api/flows/{id}/feedback`,
  `/api/stats`, `/api/settings`, `/api/allowlist`, `/api/health`, `/api/rss`.
  `/api/analyze-threats` now uses the stored threat counts and server-side keys.
- Fixed: the Gemini model name `gemini-3.8-flash` (doesn't exist) is now `gemini-2.5-flash`
  and configurable per provider. The WebSocket manager no longer crashes on
  disconnect. The Dockerfile had a syntax error (`"--port". "8000"`).
  `requirements.txt` was missing pandas, httpx, requests and joblib.
- Added backend tests (`python -m pytest -q`, 22 tests).

### Simulator (`data/attack_simulator.py`)
- The server address is now `--server host:port` or `THREAT_SERVER`, instead of being edited into the file.
- Added `--scenario`, `--batch`, `--delay` and `--no-shuffle`. Rows are shuffled by default so
  attack and normal traffic arrive mixed.
- The "normal traffic" scenario now actually sends only benign rows. It used to resend the DDoS file.
- Reads the Windows-1252 web-attack CSV correctly, and prints per-batch verdicts.

### Dashboard (`Implementation/apps/web-frontend`)
- One shared WebSocket connection (`lib/live.tsx`) with auto-reconnect, instead of three
  separate ones. The notification bell's connection was hard-coded to localhost.
- Dashboard, Logs, Threats and Settings all show real backend data. Removed the
  hard-coded demo data in the log feed, KPI cards, charts and RSS route.
- New pages: **Threats** (what needs review, accuracy, AI briefing) and **Settings**
  (backend address, engine switches, thresholds, AI keys and provider order, ntfy, allowlist).
  The sidebar links to both already existed but went nowhere. Removed the "Containers" link.
- Fixed the route conflict: `app/page.tsx` and `app/(marketing)/page.tsx` both served `/`.
- Fixed nested `<html>` layouts: `ClerkProvider` now lives in the root layout only.
- Fixed a syntax error in `NotificationBell.tsx` (a stray `>`).
- Fixed the font: `--font-sans` referenced itself, so pages rendered in a serif fallback.
- Logs, Threats and Settings are now login-protected, as well as Dashboard.
- Upgraded `next` and `eslint-config-next` from 16.4.3 to 16.4.6. `next build` refused to
  build 16.4.3 because of a known security vulnerability.
- `next build` passes with no type or lint errors.

### Removed
- `clerk-nextjs/`: an unused starter app.
- `backend/main.py`: a second FastAPI app that sent random fake alerts.
- `Implementation/apps/initial-app/`: an outdated copy of the backend.
- `app/attacking setup/attack_simulator.py`: a duplicate of `data/attack_simulator.py`.
- `app/parser.py` and `data/sample_syslog.log`: a syslog parser nothing called.
- `app/ml_engine.py`, `app/models/isolation_forest*.joblib`: replaced by `app/detection/` and `ml_bundle.joblib`.
- Root `package.json`, `package-lock.json` and `node_modules`, which nothing used, and `tree.txt` (a 650 KB directory dump).
- `Implementation/apps/web-frontend/utils/aiClient.ts`, `components/log-feed.tsx`,
  `components/action-banner.tsx` and `app/api/notifications/rss/`: unused or demo-only.

### Size
The folder was about 900 MB, almost all of it generated files: `.next` (316 MB),
three `node_modules` folders, `.venv`, and about 105 MB of git history. The source
itself is about 9 MB, including the reports. Generated folders are git-ignored and
rebuilt by `npm install` and `pip install`. Git history was left as is, because shrinking it would
mean rewriting shared history; about 70 MB of it is old CICFlowMeter and jnetpcap zips.
