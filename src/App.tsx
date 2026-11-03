import { useEffect, useState } from "react";
import { LoginPage } from "./components/LoginPage";
import { DnsDashboard } from "./components/DnsDashboard";

export function App() {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);
  const [authEnabled, setAuthEnabled] = useState<boolean | null>(null);

  useEffect(() => {
    fetch("/api/auth/me", { credentials: "include" })
      .then(async (response) => {
        const payload = await response.json().catch(() => ({}));
        setAuthenticated(response.ok && payload.authenticated === true);
        setAuthEnabled(payload.authEnabled !== false);
      })
      .catch(() => { setAuthenticated(false); setAuthEnabled(true); });
  }, []);

  if (authenticated === null || authEnabled === null) return <div className="login-viewport" />;
  if (!authEnabled) return <DnsDashboard authEnabled={false} onLogout={() => undefined} />;
  if (!authenticated) return <LoginPage onLogin={() => setAuthenticated(true)} />;

  return <DnsDashboard authEnabled onLogout={() => setAuthenticated(false)} />;
}
