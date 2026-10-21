import { useEffect, useState } from "react";
import { Routes, Route, Navigate, useNavigate, useLocation } from "react-router-dom";
import {
  getToken,
  setToken,
  removeToken,
  parseJWT,
  isTokenValid,
  extractTokenFromHash,
  type JWTClaims,
} from "./lib/auth";
import { Layout } from "./components/Layout";
import { LoginPage } from "./pages/LoginPage";
import { OverviewPage } from "./pages/OverviewPage";
import { DevicesPage } from "./pages/DevicesPage";
import { SessionsPage } from "./pages/SessionsPage";
import { ServicesPage } from "./pages/ServicesPage";
import { RelayPage } from "./pages/RelayPage";
import { SystemPage } from "./pages/SystemPage";
import { PairPage } from "./pages/PairPage";

function RequireAuth({ children, claims }: { children: React.ReactNode; claims: JWTClaims | null }) {
  if (!claims) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

export function App() {
  const [claims, setClaims] = useState<JWTClaims | null>(null);
  const [tokenForExchange] = useState(() => extractTokenFromHash() ?? getToken());
  const [checked, setChecked] = useState(false);
  const [sessionAttempt, setSessionAttempt] = useState(0);
 const [unavailable,setUnavailable]=useState(false);
 const [logoutPending,setLogoutPending]=useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const stored = tokenForExchange;
    if (stored) {
      const previous = parseJWT(stored) as Record<string, unknown> | null;
      if (previous && ["email", "display_name", "picture"].some(key => key in previous)) removeToken();
      else setToken(stored);
    }
    if (!stored || !isTokenValid(stored)) { setChecked(true); return; }
    const previous = parseJWT(stored) as Record<string, unknown> | null;
    const needsCleanup = previous && ["email", "display_name", "picture"].some(key => key in previous);
    const reference = needsCleanup
      ? fetch("/api/v1/auth/session", { headers: { Authorization: `Bearer ${stored}` }, cache: "no-store", redirect: "error" })
        .then(async response => {
          if (response.status === 401) return "";
          if (!response.ok) throw new Error("Session cleanup unavailable");
          const result: { token: string } = await response.json();
          setToken(result.token);
          return result.token;
        })
      : Promise.resolve(stored);
    reference.then(token => token
      ? fetch("/auth/session", { headers: { Authorization: `Bearer ${token}` }, cache: "no-store", redirect: "error" })
      : new Response(null, { status: 401 }))
      .then(async (response) => {
        if (response.status === 401) { removeToken(); setChecked(true); return; }
        if (!response.ok) {
          const status: { logout_pending?: boolean } = await response.json();
          setLogoutPending(status.logout_pending === true);
          throw new Error("Session unavailable");
        }
        const profile: JWTClaims = await response.json();
        setClaims(profile); setChecked(true);
        if (location.pathname === "/login") navigate("/admin", { replace: true });
      }).catch(() => setUnavailable(true));
  }, [sessionAttempt]); // eslint-disable-line react-hooks/exhaustive-deps

  async function retrySession() {
    if (!logoutPending) { setUnavailable(false); setSessionAttempt(value => value + 1); return; }
    const response = await fetch("/auth/logout", { method: "POST", headers: { Authorization: `Bearer ${getToken()}` }, redirect: "error" }).catch(() => null);
    if (response?.ok) { removeToken(); window.location.replace("/login"); }
  }

  if (unavailable) return <div className="h-full flex flex-col items-center justify-center gap-4"><p>Session temporarily unavailable.</p><button onClick={() => void retrySession()}>Retry</button></div>;
  if (!checked) return null;

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/admin"
        element={
          <RequireAuth claims={claims}>
            <Layout claims={claims} />
          </RequireAuth>
        }
      >
        <Route index element={<OverviewPage />} />
        <Route path="devices" element={<DevicesPage />} />
        <Route path="sessions" element={<SessionsPage />} />
        <Route path="services" element={<ServicesPage />} />
        <Route path="relay" element={<RelayPage />} />
        <Route path="system" element={<SystemPage />} />
        <Route path="pair" element={<PairPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/admin" replace />} />
    </Routes>
  );
}
