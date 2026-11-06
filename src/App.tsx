import { useEffect, useState } from "react";
import { LoginPage } from "./components/LoginPage";
import { DnsDashboard } from "./components/DnsDashboard";
import { SetupWizard } from "./components/SetupWizard";

export function App() {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);
  const [authEnabled, setAuthEnabled] = useState<boolean | null>(null);
  const [mustChangePassword, setMustChangePassword] = useState(false);
  const [initialized, setInitialized] = useState<boolean | null>(null);
  const [bindReady, setBindReady] = useState<boolean | null>(null);

  useEffect(() => {
    fetch("/api/auth/me", { credentials: "include" })
      .then(async (response) => {
        const payload = await response.json().catch(() => ({}));
        setAuthenticated(response.ok && payload.authenticated === true);
        setAuthEnabled(payload.authEnabled !== false);
        setMustChangePassword(payload.mustChangePassword === true);
        setInitialized(payload.initialized !== false);
        setBindReady(payload.bindReady !== false);
      })
      .catch(() => { setAuthenticated(false); setAuthEnabled(true); setInitialized(false); setBindReady(false); });
  }, []);

  if (authenticated === null || authEnabled === null || initialized === null || bindReady === null) return <div className="login-viewport" />;
  if (!initialized) return <SetupWizard platformOnly onComplete={() => { setInitialized(true); setAuthenticated(true); setAuthEnabled(true); setBindReady(false); }} />;
  if (!authEnabled) return <DnsDashboard authEnabled={false} onLogout={() => undefined} />;
  if (!authenticated) return <LoginPage onLogin={(required) => { setAuthenticated(true); setMustChangePassword(required); }} />;
  if (!bindReady) return <SetupWizard onComplete={() => setBindReady(true)} />;

  return <DnsDashboard authEnabled mustChangePassword={mustChangePassword} onLogout={() => { setAuthenticated(false); setMustChangePassword(false); }} />;
}
