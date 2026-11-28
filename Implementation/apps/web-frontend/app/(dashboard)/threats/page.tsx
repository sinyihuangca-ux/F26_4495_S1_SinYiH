import { redirect } from "next/navigation";

// Threats and logs now share one page; keep old links working.
export default function ThreatsPage() {
  redirect("/logs");
}
