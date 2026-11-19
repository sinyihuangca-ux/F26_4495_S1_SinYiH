# Web frontend

The Next.js 16 dashboard for the threat platform. Setup and usage are in the
[project README](../../../README.md).

```powershell
copy .env.example .env.local   # Clerk keys
npm install
npm run dev                    # http://localhost:3000/dashboard
```

- `lib/api.ts`: backend address and typed API calls
- `lib/live.tsx`: the single shared WebSocket connection and live state
- `app/(dashboard)/`: Dashboard, Logs, Threats and Settings pages (sign-in required)
- `app/(marketing)/`: the public landing page
