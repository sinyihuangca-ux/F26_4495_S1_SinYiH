import type { Metadata } from "next";
import { cn } from "@/lib/utils";
import "@/app/globals.css";
import { Sidebar } from "@/components/sidebar";
import NotificationBell from "./components/NotificationBell";
import {
  ClerkProvider,
  SignInButton,
  SignUpButton,
  UserButton,
  Show,
} from "@clerk/nextjs";

export const metadata: Metadata = {
  title: "AI Cyber Threat Mitigation Dashboard",
  description: "Real-time ML Anomaly Detection & WebSocket Dashboard",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <ClerkProvider>
      <html lang="en" className="dark">
        <body className="flex min-h-screen bg-[#0B0F19] text-white antialiased">
          {/* Existing Sidebar */}
          <Sidebar />

          {/* Main Content Area */}
          <div className="flex-1 flex flex-col overflow-y-auto">
            {/* Header with Notification Bell and Clerk Auth Controls */}
            <header className="flex justify-between items-center px-6 py-4 border-b border-gray-800 bg-[#0B0F19]/50 backdrop-blur-md h-16">
              <div className="font-semibold text-sm text-gray-300">
                AI Threat Mitigation Dashboard
              </div>

              <div className="flex items-center gap-4">
                {/* 🔔 Live WebSocket Notification Bell */}
                <NotificationBell />

                {/* Clerk Auth Controls */}
                <Show when="signed-out">
                  <SignInButton mode="modal">
                    <button className="px-4 py-2 text-sm font-medium bg-gray-800 text-gray-200 hover:bg-gray-700 rounded-md transition-colors border border-gray-700">
                      Sign In
                    </button>
                  </SignInButton>
                  <SignUpButton mode="modal">
                    <button className="px-4 py-2 text-sm font-medium bg-purple-600 text-white hover:bg-purple-500 rounded-md transition-colors shadow-sm">
                      Sign Up
                    </button>
                  </SignUpButton>
                </Show>

                <Show when="signed-in">
                  <UserButton
                    appearance={{
                      elements: {
                        avatarBox: "w-9 h-9 border border-gray-700",
                      },
                    }}
                  />
                </Show>
              </div>
            </header>

            {/* Page Content */}
            <main className="flex-1 p-6">{children}</main>
          </div>
        </body>
      </html>
    </ClerkProvider>
  );
}