import { FormEvent, useEffect, useState } from "react";

type CaptchaResponse = { id: string; svg: string };

export function LoginPage({ onLogin }: { onLogin: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [captchaId, setCaptchaId] = useState("");
  const [captchaSvg, setCaptchaSvg] = useState("");
  const [captchaCode, setCaptchaCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [title, setTitle] = useState("网络态势中枢");
  const [subtitle, setSubtitle] = useState("数据中心核心网络实时监控与智能分析平台");
  const [clock, setClock] = useState(() => new Date());

  const refreshCaptcha = async () => {
    try {
      const response = await fetch("/api/auth/captcha", { cache: "no-store" });
      if (!response.ok) throw new Error("captcha unavailable");
      const value = (await response.json()) as CaptchaResponse;
      setCaptchaId(value.id);
      setCaptchaSvg(value.svg);
      setCaptchaCode("");
    } catch {
      setCaptchaId("");
      setCaptchaSvg("");
    }
  };

  useEffect(() => {
    fetch("/api/settings")
      .then((response) => response.ok ? response.json() as Promise<{ title?: string; subtitle?: string }> : Promise.reject(new Error("settings unavailable")))
      .then((value) => {
        if (value.title) setTitle(value.title);
        if (value.subtitle) setSubtitle(value.subtitle);
      })
      .catch(() => undefined);
    void refreshCaptcha();
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => setClock(new Date()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!captchaId || captchaCode.trim().length !== 4) {
      setError("请输入 4 位验证码");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ username, password, captchaId, captcha: captchaCode }),
      });
      if (!response.ok) throw new Error("登录失败");
      onLogin();
    } catch {
      setError("用户名、密码或验证码错误，或认证服务不可用");
      void refreshCaptcha();
    } finally {
      setLoading(false);
    }
  };

  const captchaImage = captchaSvg ? `data:image/svg+xml;charset=utf-8,${encodeURIComponent(captchaSvg)}` : "";

  return (
    <main className="login-viewport">
      <div className="login-grid" />
      <div className="login-radar" aria-hidden="true" />
      <div className="login-telemetry login-telemetry-left"><b>◉ SYSTEM SCANNING</b><span>NETWORK NODES <strong>128</strong></span><span>THREAT LEVEL <strong className="safe">LOW</strong></span></div>
      <div className="login-telemetry login-telemetry-right"><b>{clock.toISOString().slice(0, 19).replace("T", " ")} UTC</b><span>SECURITY LEVEL <strong>HIGH</strong></span><span>ENCRYPTED CHANNEL <strong className="safe">ACTIVE</strong></span></div>
      <div className="login-scan" />
      <section className="login-card">
        <div className="login-corner login-corner-a" /><div className="login-corner login-corner-b" />
        <div className="login-brand"><b>▥</b><span>DNS<small>RESOLUTION CENTER</small></span></div>
        <div className="login-title"><h1>{title}</h1><span>DNS RESOLUTION CONTROL CENTER</span><small>{subtitle}</small></div>
        <div className="login-divider"><i /><b>SECURE ACCESS</b><i /></div>
        <form onSubmit={submit}>
          <label>用户标识<input autoFocus value={username} onChange={(event) => setUsername(event.target.value)} placeholder="请输入用户名" autoComplete="username" /></label>
          <label>访问密码<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="请输入密码" autoComplete="current-password" /></label>
          <label>图形验证码
            <div className="captcha-row">
              <input value={captchaCode} onChange={(event) => setCaptchaCode(event.target.value.toUpperCase().replace(/[^0-9A-Z]/g, "").slice(0, 4))} placeholder="请输入验证码" autoComplete="off" maxLength={4} />
              <button className="captcha-image" type="button" onClick={() => void refreshCaptcha()} aria-label="刷新验证码">{captchaImage ? <img src={captchaImage} alt="验证码" /> : "加载中"}</button>
            </div>
          </label>
          {error && <p className="login-error">{error}</p>}
          <button type="submit" disabled={loading || captchaCode.trim().length !== 4}>{loading ? "认证中…" : "进入监控驾驶舱"}</button>
        </form>
        <footer><span>AUTHORIZED DNS CONSOLE</span><b>● SECURE</b></footer>
        <div className="login-card-status"><span><i /> AUTH SERVICE ONLINE</span><span><i /> RPZ CONTROL READY</span></div>
      </section>
    </main>
  );
}
