<#
.SYNOPSIS
  Starts the whole platform: FastAPI backend + Next.js dashboard (and optionally the simulator).

.EXAMPLE
  .\start.ps1              # backend + dashboard, opens the browser
  .\start.ps1 -Simulate    # also opens the attack simulator, pointed at this PC
  .\start.ps1 -NoBrowser   # don't open the browser

  The first run creates .venv, installs Python and npm packages, trains the model if
  it's missing, and creates the root .env (all keys live there). Later runs skip whatever is already in place, so they start quickly.
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

# ---------- Keys: one .env in the project root ----------
# The backend and the dashboard both read the root .env (the dashboard via
# next.config.ts). It holds the Clerk keys and the AI keys; git ignores it.
$RootEnv = Join-Path $Root ".env"
$OldEnv = Join-Path $Web ".env.local"   # where the Clerk keys used to live
$Utf8 = New-Object System.Text.UTF8Encoding $false   # no BOM, so every reader parses line 1

function Get-EnvValue($file, $key) {
    if (-not (Test-Path $file)) { return "" }
    $m = Select-String -Path $file -Pattern "^$key=(.*)$" | Select-Object -First 1
    if ($m) { return $m.Matches[0].Groups[1].Value.Trim().Trim('"') } else { return "" }
}

function Set-EnvValue($file, $key, $value) {
    $found = $false
    $lines = @(Get-Content $file | ForEach-Object {
        if ($_ -match "^$key=") { $found = $true; "$key=$value" } else { $_ }
    })
    if (-not $found) { $lines += "$key=$value" }
    [System.IO.File]::WriteAllLines($file, [string[]]$lines, $Utf8)
}

if (-not (Test-Path $RootEnv)) {
    $template = @"
# All keys for the platform (backend + dashboard). Git-ignored: never commit this file.
# Clerk sign-in keys: https://dashboard.clerk.com -> API keys
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=
CLERK_SECRET_KEY=
NEXT_PUBLIC_CLERK_SIGN_IN_FALLBACK_REDIRECT_URL=/dashboard
NEXT_PUBLIC_CLERK_SIGN_UP_FALLBACK_REDIRECT_URL=/dashboard
# Backend address the dashboard uses by default (can be changed per browser in Settings)
NEXT_PUBLIC_API_URL=localhost:8000
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
# AI providers: managed from the dashboard's Settings page
GEMINI_API_KEY=
GROQ_API_KEY=
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
"@
    [System.IO.File]::WriteAllText($RootEnv, $template, $Utf8)
    Step "Created .env in the project root."
}

# One-time move: copy real keys from the old web-frontend\.env.local into the root .env.
if (Test-Path $OldEnv) {
    $moved = @()
    foreach ($key in "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY", "CLERK_SECRET_KEY",
                     "NEXT_PUBLIC_CLERK_SIGN_IN_FALLBACK_REDIRECT_URL",
                     "NEXT_PUBLIC_CLERK_SIGN_UP_FALLBACK_REDIRECT_URL", "NEXT_PUBLIC_API_URL") {
        $old = Get-EnvValue $OldEnv $key
        if ($old -and $old -notmatch '\.\.\.' -and -not (Get-EnvValue $RootEnv $key)) {
            Set-EnvValue $RootEnv $key $old
            $moved += $key
        }
    }
    if ($moved.Count) { Step "Moved $($moved -join ', ') from web-frontend\.env.local into the root .env." }
    Warn "web-frontend\.env.local is no longer used (keys now live in the root .env). You can delete it."
}

$pk = Get-EnvValue $RootEnv "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY"
if (-not $pk) { $pk = Get-EnvValue $RootEnv "CLERK_PUBLISHABLE_KEY" }   # older name
if (-not $pk -or $pk -notmatch '^pk_(test|live)_\S{20,}') {
    Warn "No real Clerk publishable key in the root .env (found '$pk')."
    Warn "Open $RootEnv and fill in NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY (pk_test_...) and CLERK_SECRET_KEY (sk_test_...), then run this again."
    exit 1
}
if (-not (Get-EnvValue $RootEnv "CLERK_SECRET_KEY")) {
    Warn "CLERK_SECRET_KEY is empty in the root .env - sign-in will fail until you add it."
}

# ---------- Next.js dashboard ----------
$NpmMarker = Join-Path $Web "node_modules\.package-lock.json"
if (Outdated (Join-Path $Web "package-lock.json") $NpmMarker) {
    Step "Installing dashboard packages (npm install)..."
    Push-Location $Web
    try { npm install --no-audit --no-fund; if ($LASTEXITCODE) { throw "npm install failed. Is Node.js installed?" } }
    finally { Pop-Location }
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
