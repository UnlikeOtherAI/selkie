import { useEffect, useState } from "react";
import { DebugSessionButton } from "../components/DebugSessionButton";

export function LoginPage() {
  const [devEnabled, setDevEnabled] = useState(false);

  useEffect(() => {
    fetch("/auth/dev-status")
      .then((r) => r.json())
      .then((d: { enabled: boolean }) => {
        if (d.enabled) setDevEnabled(true);
      })
      .catch(() => {});
  }, []);

  return (
    <div className="h-full flex flex-col items-center justify-center">
      <DebugSessionButton mode="import" />
      <div className="flex flex-col items-center gap-6">
        {/* Icon */}
        <img
          src="/assets/icon-1024.png"
          alt="Selkie"
          className="w-[130px] h-[130px] rounded-2xl shadow-xl"
        />

        {/* Card */}
        <div className="w-80 bg-slate-900 border border-slate-800 rounded-xl p-8 flex flex-col items-center gap-6 shadow-2xl">
          <div className="text-center space-y-1">
            <h1 className="text-lg font-semibold text-slate-100">
              Sign in to Selkie
            </h1>
            <p className="text-sm text-slate-500">
              Secure access to your devices
            </p>
          </div>

          {/* UOA sign-in */}
          <a
            href="/auth/login"
            className="w-full flex items-center justify-center gap-3 bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700 text-white text-sm font-medium px-4 py-2.5 rounded-lg transition-colors"
          >
            Login / Sign up
          </a>

          {/* Dev login */}
          {devEnabled && (
            <a
              id="dev-login-btn"
              href="/auth/dev-login"
              className="w-full flex items-center justify-center gap-3 bg-slate-800 hover:bg-slate-700 active:bg-slate-900 text-slate-200 text-sm font-medium px-4 py-2.5 rounded-lg transition-colors border border-slate-700"
            >
              <svg
                className="h-4 w-4"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M16 18l6-6-6-6" />
                <path d="M8 6l-6 6 6 6" />
              </svg>
              Dev Login
            </a>
          )}
        </div>

        <p className="text-xs text-slate-600">
          Made with love in Scotland &copy; 2026{" "}
          <a
            href="https://unlikeotherai.com"
            className="text-slate-200 font-medium hover:text-white transition-colors"
          >
            UnlikeOtherAI
          </a>
        </p>
      </div>
    </div>
  );
}
