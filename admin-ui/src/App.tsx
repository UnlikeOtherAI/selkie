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
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const stored = tokenForExchange;
    if (stored && !isTokenValid(stored)) removeToken();
    const controller = new AbortController();
    void (async () => {
      try {
        if (stored && isTokenValid(stored)) {
          // Old profile-bearing JWTs must leave persistent storage before exchange.
          const oldClaims = parseJWT(stored) as Record<string, unknown> | null;
          if (oldClaims && ["email", "display_name", "picture"].some((key) => key in oldClaims)) {
            removeToken();
          }
          const response = await fetch("/api/v1/auth/session", {
            headers: { Authorization: `Bearer ${stored}` },
            credentials: "omit", redirect: "error", signal: controller.signal,
          });
          if (!response.ok) { removeToken(); return; }
          const session = await response.json() as { token: string };
          if (controller.signal.aborted) return;
          setToken(session.token);
          setClaims(parseJWT(session.token));
          if (location.pathname === "/login") navigate("/admin", { replace: true });
        }
      } catch {
        // A failed exchange never restores a copied profile-bearing session.
      } finally {
        if (!controller.signal.aborted) setChecked(true);
      }
    })();
    return () => controller.abort();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

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
