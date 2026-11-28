import fs from "node:fs";
import path from "node:path";
import type { NextConfig } from "next";

// All keys live in ONE file: the .env in the project root (next to app/ and start.ps1),
// shared with the FastAPI backend. Next.js normally only reads env files in this folder,
// so load the root .env here. Its values win over any old web-frontend/.env.local.
function loadRootEnv() {
  const file = path.resolve(process.cwd(), "../../../.env");
  if (!fs.existsSync(file)) return;
  for (const raw of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq < 1) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (value) process.env[key] = value;
  }
  // Older setups named the publishable key CLERK_PUBLISHABLE_KEY; the dashboard needs
  // the NEXT_PUBLIC_ name.
  if (!process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY && process.env.CLERK_PUBLISHABLE_KEY) {
    process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY = process.env.CLERK_PUBLISHABLE_KEY;
  }
}
loadRootEnv();

const nextConfig: NextConfig = {
  /* config options here */
  experimental: {
    agentFeedback: true,
  },
  cacheComponents: true,
  partialPrefetching: true,
  turbopack: {
    root: path.resolve("."), // must be absolute
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
