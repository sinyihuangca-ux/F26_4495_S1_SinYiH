import { Zap, ShieldAlert, ChevronRight } from "lucide-react"
import { Button } from "@/components/ui/button"

export function ActionBanner() {
  return (
    <div className="flex flex-col gap-4 rounded-xl border border-slate-800 bg-slate-900/60 p-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-sky-500/20 bg-sky-500/10 text-sky-400">
          <Zap className="h-5 w-5" />
        </div>
        <div>
          <h4 className="font-semibold text-white">Response Actions</h4>
          <p className="text-xs text-slate-400">Isolate suspicious containers or trigger snapshot recovery to quickly mitigate threats.</p>
        </div>
      </div>

      <Button className="group h-11 bg-gradient-to-r from-red-600 to-rose-600 font-medium text-white shadow-lg shadow-red-950/50 hover:from-red-500 hover:to-rose-500">
        <ShieldAlert className="mr-2 h-5 w-5" />
        Isolate Container / Trigger Snapshot Recovery
        <ChevronRight className="ml-2 h-4 w-4 transition-transform group-hover:translate-x-1" />
      </Button>
    </div>
  )
}