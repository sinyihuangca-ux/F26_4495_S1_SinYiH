<#
.SYNOPSIS
  Starts the whole platform: FastAPI backend + Next.js dashboard (and optionally the simulator).

.EXAMPLE
  .\start.ps1              # backend + dashboard, opens the browser
  .\start.ps1 -Simulate    # also opens the attack simulator, pointed at this PC
  .\start.ps1 -NoBrowser   # don't open the browser

  The first run creates .venv, installs Python and npm packages and trains the model if
  it's missing. Later runs skip whatever is already in place, so they start quickly.
  Each part runs in its own window; close the window or press Ctrl+C there to stop it.

  If Windows blocks the script:  powershell -ExecutionPolicy Bypass -File .\start.ps1
#>
param(
    [switch]$Simulate,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$Venv = Join-Path $Root ".venv"
$Py = Join-Path $Venv "Scripts\python.exe"
$Web = Join-Path $Root "Implementation\apps\web-frontend"

function Step($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }

# Newer-than check: true if $source changed after $marker was written (or $marker is missing).
function Outdated($source, $marker) {
    if (-not (Test-Path $marker)) { return $true }
    return (Get-Item $source).LastWriteTime -gt (Get-Item $marker).LastWriteTime
}

# Prefer PowerShell 7 for the child windows when it's installed.
$Shell = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh" } else { "powershell" }

# ---------- Python backend ----------
if (-not (Test-Path $Py)) {
    Step "Creating virtual environment (.venv)..."
    python -m venv $Venv
    if ($LASTEXITCODE) { throw "Couldn't create .venv. Is Python 3.13 installed and on PATH?" }
}

$PipMarker = Join-Path $Venv ".requirements-installed"
if (Outdated (Join-Path $Root "requirements.txt") $PipMarker) {
    Step "Installing Python packages..."
    & $Py -m pip install --quiet --disable-pip-version-check -r (Join-Path $Root "requirements.txt")
    if ($LASTEXITCODE) { throw "pip install failed." }
    New-Item $PipMarker -ItemType File -Force | Out-Null
}

if (-not (Test-Path (Join-Path $Root "app\models\ml_bundle.joblib"))) {
    Step "No trained model found - training one (takes a few seconds)..."
    Push-Location $Root
    try { & $Py -m app.train; if ($LASTEXITCODE) { throw "Training failed." } }
    finally { Pop-Location }
}

if (-not (Test-Path (Join-Path $Root ".env"))) {
    Copy-Item (Join-Path $Root ".env.example") (Join-Path $Root ".env")
    Warn "Created .env from .env.example. Add CLERK_PUBLISHABLE_KEY to it so settings can be changed from other PCs."
}

# ---------- Next.js dashboard ----------
$NpmMarker = Join-Path $Web "node_modules\.package-lock.json"
if (Outdated (Join-Path $Web "package-lock.json") $NpmMarker) {
    Step "Installing dashboard packages (npm install)..."
    Push-Location $Web
    try { npm install --no-audit --no-fund; if ($LASTEXITCODE) { throw "npm install failed. Is Node.js installed?" } }
    finally { Pop-Location }
}

if (-not (Test-Path (Join-Path $Web ".env.local"))) {
    Copy-Item (Join-Path $Web ".env.example") (Join-Path $Web ".env.local")
    Warn "Created web-frontend\.env.local - fill in your Clerk keys, or sign-in won't work."
}

# ---------- Launch ----------
function Launch($title, $dir, $command) {
    $full = "`$Host.UI.RawUI.WindowTitle = '$title'; $command"
    Start-Process $Shell -WorkingDirectory $dir -ArgumentList "-NoExit", "-Command", $full | Out-Null
}

Step "Starting backend   -> http://localhost:8000  (window: Backend)"
Launch "Backend (FastAPI)" $Root "& '$Py' -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

Step "Starting dashboard -> http://localhost:3000  (window: Dashboard)"
Launch "Dashboard (Next.js)" $Web "npm run dev"

# Wait for the backend before opening anything that talks to it.
$ready = $false
for ($i = 0; $i -lt 30 -and -not $ready; $i++) {
    Start-Sleep -Seconds 1
    try { Invoke-RestMethod "http://localhost:8000/api/health" -TimeoutSec 2 | Out-Null; $ready = $true } catch { }
}
if (-not $ready) { Warn "Backend hasn't answered yet - check the Backend window for errors." }

if ($Simulate) {
    Step "Starting attack simulator (window: Simulator)"
    Launch "Attack simulator" (Join-Path $Root "data") "& '$Py' attack_simulator.py --server localhost:8000"
}

if (-not $NoBrowser) {
    Start-Sleep -Seconds 4   # give Next.js a moment to compile the first page
    Start-Process "http://localhost:3000/dashboard"
}

Write-Host ""
Write-Host "Running. Close the Backend and Dashboard windows to stop." -ForegroundColor Green
Write-Host "Simulator on another PC:  python attack_simulator.py --server <this PC's IP>:8000"
