AI-Powered Threat Detection & Mitigation Platform
An end-to-end, cross-PC cybersecurity monitoring and threat response platform that ingests live network logs, performs unsupervised machine learning anomaly detection via an Isolation Forest model, and streams real-time alerts to a secure Next.js & React Dashboard.

🚀 Quick Start & Activation Guide
Follow these steps in order to fire up the complete system (Backend ML/API + Frontend Dashboard).

Step 1: Start the FastAPI Backend & ML Engine
Open your terminal in the project root directory, activate your virtual environment, and launch Uvicorn:

PowerShell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --host 0.0.0.0 --reload --port 8000
Verify: Open http://localhost:8000/docs to see the interactive Swagger UI and verify the Isolation Forest model loaded successfully.

Step 2: Start the Next.js Frontend Dashboard
Open a second separate terminal window, navigate to your frontend directory, install dependencies (if not already done), and start the development server:

Bash
cd web-frontend
npm install
npm run dev
Access: Open http://localhost:3000 in your browser.

Dashboard Route: Navigate to http://localhost:3000/dashboard to view the live threat feed, KPI counters, and active WebSocket connection status ("Connected (Live)").

Step 3: Run the Attack Simulator (Second PC / Terminal)
On your simulator node or a separate machine on the network:

PowerShell
python attack_simulator.py
Select an attack scenario (e.g., DDoS, PortScan, or Web Attacks) from the interactive menu to stream logs to FastAPI and watch alerts instantly light up your dashboard!

🧠 Architecture & Component Breakdown
1. Layer 3 Threat Detection Engine (Backend)
This subsystem handles high-throughput log ingestion and unsupervised anomaly detection.

Technology Stack: FastAPI, Python, Scikit-Learn, Pandas, NumPy, Uvicorn (with WebSockets support).

Model: An Isolation Forest model (isolation_forest.joblib) trained on the CIC-IDS-2017 dataset.

Directory Structure:

Plaintext
app/
├── main.py                   # FastAPI application, CORS middleware, & WebSocket manager
├── ml_engine.py              # Data preprocessing & Isolation Forest inference engine
└── models/
    └── isolation_forest.joblib # Serialized ML model artifact
2. Web Frontend & Authentication (Clerk Core 3)
The command-center interface built with Next.js, Tailwind CSS, Lucide icons, and real-time WebSocket listeners.

🔑 Environment Variables Setup (web-frontend/.env.local)
Ensure a .env.local file exists directly in your web-frontend/ root folder:

Code snippet
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_...
CLERK_SECRET_KEY=sk_test_...
NEXT_PUBLIC_CLERK_SIGN_IN_FALLBACK_REDIRECT_URL=/dashboard
NEXT_PUBLIC_CLERK_SIGN_UP_FALLBACK_REDIRECT_URL=/dashboard
🛠️ Troubleshooting & Common Fixes
1. Clerk Core 3 Component Error (<SignedOut> is not available)
Cause: Using legacy Clerk control components in @clerk/nextjs Core 3.

Fix: Replace them with the unified <Show> component syntax:

TypeScript
<Show when="signed-out">
  {/* Signed out content / login buttons */}
</Show>

<Show when="signed-in">
  {/* Signed in content / user buttons */}
</Show>
2. Middleware Missing Error (auth() was called but Clerk can't detect usage)
Fix: Ensure a middleware.ts file is present in the root of web-frontend/:

TypeScript
import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";

const isProtectedRoute = createRouteMatcher(["/dashboard(.*)"]);

export default clerkMiddleware(async (auth, req) => {
  if (isProtectedRoute(req)) {
    await auth.protect();
  }
});

export const config = {
  matcher: [
    '/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|kit)).*)',
    '/(api|trpc)(.*)',
  ],
};
3. Uvicorn Import Error (ModuleNotFoundError: No module named 'app')
Fix: Always execute Uvicorn from the project root directory (where the app/ folder lives), with your virtual environment activated, using:

PowerShell
python -m uvicorn app.main:app --host 0.0.0.0 --reload --port 8000