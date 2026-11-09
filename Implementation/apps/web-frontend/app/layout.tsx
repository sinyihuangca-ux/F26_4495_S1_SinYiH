import "./globals.css"; // or styles if you have them

export const metadata = {
  title: "AI Fortress Security Command Center",
  description: "Real-time AI security command center with multi-model failover and audit logs",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-slate-950 text-slate-100 min-h-screen antialiased">
        {children}
      </body>
    </html>
  );
}