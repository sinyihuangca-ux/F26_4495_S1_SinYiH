## Getting Started
First go to the web-frontend folder


Then  install the packages
```bash
npm install
# or
yarn install
# or
pnpm install
# or
bun install
```


Then, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can view the dashboard page by going to  [http://localhost:3000/dashboard](http://localhost:3000/dashboard)

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.
# Web Frontend - Clerk Setup & Troubleshooting Guide

This guide documents the setup, architecture, and common troubleshooting steps encountered while integrating **Clerk Authentication (Core 3)** into this Next.js application.

---

## What We've Built & Configured So Far

1. **Clerk Core 3 Integration:**
   - Wrapped the root layout with `<ClerkProvider>`.
   - Replaced deprecated legacy control components (`<SignedOut>`, `<SignedIn>`) with the new unified `<Show>` component (`<Show when="signed-out">`, `<Show when="signed-in">`).
   - Integrated Clerk's `<SignInButton>`, `<SignUpButton>`, and `<UserButton>` into the global header.

2. **Dashboard & Protected Routes:**
   - Created a feature-rich dashboard layout (`/dashboard`) containing KPI cards, a log feed, analytics charts, and action banners.
   - Configured route matching and protection via Next.js Middleware.

---

## 🛠️ Environment Variables Setup

Ensure a `.env.local` file exists directly in the `web-frontend/` root folder with your Clerk API credentials:

```env
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_...
CLERK_SECRET_KEY=sk_test_...
NEXT_PUBLIC_CLERK_SIGN_IN_FALLBACK_REDIRECT_URL=/dashboard
NEXT_PUBLIC_CLERK_SIGN_UP_FALLBACK_REDIRECT_URL=/dashboard
```

---

## ⚠️ Probable Errors & Their Fixes

### 1. Clerk Core 3 Component Error (`<SignedOut> is not available`)
* **Cause:** Using older versions or legacy Clerk control components like `<SignedOut>` or `<SignedIn>` in `@clerk/nextjs` Core 3.
* **Fix:** Replace them with the unified `<Show>` syntax:
  ```tsx
  <Show when="signed-out">
    {/* Signed out content / buttons */}
  </Show>

  <Show when="signed-in">
    {/* Signed in content / user buttons */}
  </Show>
  ```

### 2. Missing Environment Variables Error
* **Cause:** The `.env.local` file is named incorrectly, missing `NEXT_PUBLIC_` prefixes, or the dev server wasn't restarted after creation.
* **Fix:** 
  1. Verify the file is strictly named **`.env.local`** (not `.env` or `.env.development`).
  2. Kill your development process (`Ctrl + C`) and run `npm run dev` again to reload env variables.

### 3. Middleware Missing Error (`auth() was called but Clerk can't detect usage of clerkMiddleware()`)
* **Cause:** The `middleware.ts` file is missing from the project root or lacks proper matchers.
* **Fix:** Create a `middleware.ts` file in the root of `web-frontend/` (alongside `package.json` and `app/`):
  ```typescript
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
  ```

### 4. Layout Reverting or Header Disappearing
* **Cause:** Accidental overwrite of `app/layout.tsx` back to the default Next.js template (removing `<ClerkProvider>` and the `<header>` block).
* **Fix:** Ensure your `app/layout.tsx` wraps children in `<ClerkProvider>` and includes your navigation header components.
```

eof