import { StatusDot } from "./StatusDot";
import { DebugSessionButton } from "./DebugSessionButton";

interface TopBarProps {
  title: string;
}

export function TopBar({ title }: TopBarProps) {
  return (
    <header className="h-14 shrink-0 flex items-center justify-between px-6 border-b border-slate-800 bg-slate-900/60">
      <DebugSessionButton mode="export" />
      <div id="page-title" className="text-sm font-semibold text-slate-100">
        {title}
      </div>
      <div className="flex items-center gap-3">
        <span className="flex items-center gap-1.5 text-xs text-emerald-400">
          <StatusDot status="ok" />
          Operational
        </span>
        <span className="font-mono text-xs text-slate-500">v0.1.0</span>
      </div>
    </header>
  );
}
