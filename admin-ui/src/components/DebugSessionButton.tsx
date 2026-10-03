import { useRef, useState } from "react";
import { getToken, isTokenValid, setToken } from "../lib/auth";

// Snapshots only transport an existing credential. The API remains the authority
// for its signature, audience and expiry; importing never creates a session.
export function DebugSessionButton({ mode }: { mode: "export" | "import" }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const attempt = useRef(0);
  const [snapshot, setSnapshot] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  function clear() {
    attempt.current++;
    setSnapshot("");
    setError("");
    setCopied(false);
    setBusy(false);
  }

  function open() {
    clear();
    if (mode === "export") {
      const token = getToken();
      if (token) setSnapshot(JSON.stringify({ version: 1, product: "selkie", token }, null, 2));
      else setError("No active session. Sign in again.");
    }
    dialog.current?.showModal();
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(snapshot);
      setCopied(true);
    } catch {
      setError("Could not copy. Select the snapshot and copy it manually.");
    }
  }

  async function importSession(event: React.FormEvent) {
    event.preventDefault();
    const currentAttempt = ++attempt.current;
    setBusy(true);
    setError("");
    try {
      const data: unknown = JSON.parse(snapshot);
      if (!data || typeof data !== "object" || !("product" in data) || data.product !== "selkie" ||
        !("version" in data) || data.version !== 1 || !("token" in data) ||
        typeof data.token !== "string" || !isTokenValid(data.token)) {
        throw new Error("Paste a valid, unexpired Selkie session snapshot.");
      }
      const response = await fetch("/api/v1/system/info", {
        headers: { Authorization: `Bearer ${data.token}` },
        cache: "no-store",
        redirect: "error",
      });
      if (!response.ok) {
        throw new Error(response.status === 401 || response.status === 403
          ? "This session is expired or cannot access Selkie admin. Sign in again."
          : "Could not validate the session. Try again.");
      }
      if (attempt.current !== currentAttempt || !dialog.current?.open) return;
      setToken(data.token);
      clear();
      dialog.current.close();
      window.location.replace("/admin");
    } catch (cause) {
      if (attempt.current !== currentAttempt) return;
      setSnapshot("");
      setError(cause instanceof SyntaxError
        ? "Paste the session snapshot JSON copied from Selkie admin."
        : cause instanceof Error ? cause.message : "Could not import the session.");
    } finally {
      if (attempt.current === currentAttempt) setBusy(false);
    }
  }

  return <>
    <button onClick={open} aria-label="Debug session snapshot" title="Debug session snapshot"
      className="fixed bottom-5 right-5 z-40 flex h-11 w-11 items-center justify-center rounded-full border border-slate-600 bg-slate-800 text-slate-300 shadow-lg hover:bg-slate-700">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="m8 2 2 3m6-3-2 3M9 9h6m-3 0v11M4 13H2m20 0h-2M5 7 3 5m16 2 2-2M5 19l-2 2m16-2 2 2" />
        <rect x="5" y="5" width="14" height="15" rx="7" />
      </svg>
    </button>
    <dialog ref={dialog} onClose={clear} aria-labelledby="debug-session-title"
      className="w-[calc(100%_-_2rem)] max-w-lg rounded-xl border border-slate-700 bg-slate-900 p-6 text-slate-100 shadow-2xl backdrop:bg-black/70">
      <form onSubmit={importSession} className="space-y-4">
        <div className="flex items-center justify-between gap-3">
          <h2 id="debug-session-title" className="text-lg font-semibold">{mode === "export" ? "Session debug snapshot" : "Log in with session"}</h2>
          <button type="button" aria-label="Close session dialog" onClick={() => dialog.current?.close()} className="px-2 text-slate-400 hover:text-white">✕</button>
        </div>
        <p className="text-sm text-slate-400">{mode === "export"
          ? "Copy this session snapshot to continue the same session on another machine. Treat it as a secret."
          : "Paste a session snapshot copied from Selkie admin to continue that session here."}</p>
        <label htmlFor="session-snapshot" className="block text-sm">Session snapshot</label>
        <textarea id="session-snapshot" autoFocus value={snapshot} readOnly={mode === "export"} onChange={(event) => setSnapshot(event.target.value)}
          spellCheck={false} autoComplete="off" placeholder="Paste session snapshot JSON" rows={8}
          className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-indigo-500" />
        {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
        <div className="flex justify-end gap-3">
          <button type="button" onClick={() => dialog.current?.close()} className="rounded-lg px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">Cancel</button>
          {mode === "export"
            ? <button type="button" onClick={() => void copy()} disabled={!snapshot} className="rounded-lg bg-indigo-600 px-4 py-2 text-sm disabled:opacity-50">{copied ? "Copied" : "Copy JSON"}</button>
            : <button type="submit" disabled={busy || !snapshot.trim()} className="rounded-lg bg-indigo-600 px-4 py-2 text-sm disabled:opacity-50">{busy ? "Checking session…" : "Log in with session"}</button>}
        </div>
      </form>
    </dialog>
  </>;
}
