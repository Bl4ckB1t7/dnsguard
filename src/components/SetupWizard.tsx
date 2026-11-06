import { FormEvent, useEffect, useState } from "react";

type SetupCheck = { name: string; status: "pass" | "fail" | "not_run"; detail: string; impact?: string; cleanup?: string };
type SetupStatus = { tsigKeyPath?: string; keyCandidates?: string[]; writeTestRequired?: boolean; policyMode?: "global" | "legacy"; globalDenySetupDeferred?: boolean; platformReady?: boolean; bindReady?: boolean; platformBootstrap?: boolean; whitelistSeed?: { available?: boolean; count?: number; mode?: string; error?: string }; error?: string };
type SetupPayload = { ready?: boolean; checks?: SetupCheck[]; error?: string };

function csrfHeaders(): Record<string, string> {
  const token = document.cookie.split(";").map((item) => item.trim()).find((item) => item.startsWith("dnsguard_csrf="))?.split("=").slice(1).join("=");
  return token ? { "X-CSRF-Token": decodeURIComponent(token) } : {};
}

export function SetupWizard({ onComplete, platformOnly = false }: { onComplete: () => void; platformOnly?: boolean }) {
  const [bootstrapToken, setBootstrapToken] = useState("");
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [zone, setZone] = useState("rpz.local");
  const [primary, setPrimary] = useState("");
  const [secondaries, setSecondaries] = useState("");
  const [tsigKeyPath, setTsigKeyPath] = useState("");
  const [checks, setChecks] = useState<SetupCheck[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [complete, setComplete] = useState(false);
  const [policyMode, setPolicyMode] = useState<SetupStatus["policyMode"]>("legacy");
  const [globalDenySetupDeferred, setGlobalDenySetupDeferred] = useState(false);
  const [whitelistSeed, setWhitelistSeed] = useState<SetupStatus["whitelistSeed"]>();
  const [validationReady, setValidationReady] = useState(false);

  useEffect(() => {
    fetch("/api/setup/status", { cache: "no-store" })
      .then((response) => response.json() as Promise<SetupStatus>)
      .then((value) => {
        setTsigKeyPath(value.tsigKeyPath ?? value.keyCandidates?.[0] ?? "");
        setPolicyMode(value.policyMode ?? "legacy");
        setGlobalDenySetupDeferred(value.globalDenySetupDeferred === true);
        setWhitelistSeed(value.whitelistSeed);
        if (value.error) setError(value.error);
      })
      .catch(() => setError("无法读取初始化状态，请检查 API 服务"));
  }, []);

  const requestBody = () => ({
    username,
    password,
    zone,
    primary: { name: "BIND-PRIMARY", role: "primary", address: primary.trim() },
    secondaries: secondaries.split(/[\n,]/).map((address) => address.trim()).filter(Boolean).map((address, index) => ({ name: `BIND-SECONDARY-${index + 1}`, role: "secondary", address })),
    tsigKeyPath: tsigKeyPath.trim(),
    writeTest: true,
    platformOnly,
  });

  const submit = async (event: FormEvent, endpoint: "validate" | "complete") => {
    event.preventDefault();
    setError("");
    if (platformOnly && password !== confirmPassword) { setError("两次输入的管理员密码不一致"); return; }
    if (platformOnly && !bootstrapToken.trim()) { setError("请输入部署终端提供的 Bootstrap Token"); return; }
    setLoading(true);
    try {
      const response = await fetch(`/api/setup/${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(platformOnly ? { "X-DNSGuard-Bootstrap": bootstrapToken.trim() } : csrfHeaders()) },
        credentials: "include",
        body: JSON.stringify(requestBody()),
      });
      const payload = await response.json().catch(() => ({})) as SetupPayload;
      setChecks(payload.checks ?? []);
      if (!response.ok) throw new Error(payload.error ?? (response.status === 401 ? "Bootstrap Token 无效" : "初始化检查未通过"));
      if (endpoint === "validate") setValidationReady(payload.ready === true);
      if (endpoint === "complete") {
        setComplete(true);
        setBootstrapToken("");
        onComplete();
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "初始化失败");
    } finally {
      setLoading(false);
    }
  };

  if (complete) return <main className="setup-viewport"><section className="setup-card"><h1>{platformOnly ? "DNSGuard 平台已启动" : "BIND 接入完成"}</h1><p>{platformOnly ? "管理员会话已建立，下一步在此页面接入 BIND。" : "BIND 节点和 TSIG 已验证，可以进入 RPZ 管理页面。"}</p></section></main>;
  return (
    <main className="setup-viewport">
      <section className="setup-card">
        <p className="setup-eyebrow">DNSGuard · FIRST RUN</p>
        <h1>{platformOnly ? "先启动 DNSGuard 平台" : "接入已有 BIND"}</h1>
        <p className="setup-intro">{platformOnly ? "当前阶段不要求 BIND、RPZ Zone 或 TSIG。平台启动后即可登录，再从向导接入已有 BIND；Bootstrap Token 只从部署终端获取。" : "平台已启动。请配置已有的 BIND Primary、Secondary、RPZ Zone 和 TSIG；未完成检查前，DNSGuard 不会执行任何 RPZ 发布。"}</p>
        {platformOnly ? <div className="setup-steps" aria-label="首次部署步骤"><span className="active"><b>1</b>启动平台</span><span><b>2</b>接入 BIND</span><span><b>3</b>发布白名单并验证</span></div> : <div className="setup-steps" aria-label="首次部署步骤"><span className="active"><b>1</b>接入 BIND</span><span><b>2</b>发布白名单</span><span><b>3</b>启用并验证全局 DENY</span></div>}
        {!platformOnly && <div className="setup-warning">策略模式：{policyMode === "global" ? "全局默认拒绝" : "普通 RPZ"}。DNSGuard 不会修改 BIND 配置；全局模式必须由 BIND 管理员独立准备 deny Zone。{globalDenySetupDeferred && "当前为分阶段首次部署：请先发布并确认白名单，再由 BIND 管理员启用全局 DENY。"}</div>}
        {!platformOnly && whitelistSeed?.available && <div className="setup-warning">已发现 {whitelistSeed.count ?? 0} 条部署前白名单。接入完成后将以草稿导入，不会自动写入 BIND。</div>}
        {!platformOnly && whitelistSeed?.error && <div className="setup-warning">部署前白名单不可用：{whitelistSeed.error}。请修正挂载文件后重新加载页面。</div>}
        <form onSubmit={(event) => void submit(event, "validate")}>
          {platformOnly && <label>Bootstrap Token<input type="password" value={bootstrapToken} onChange={(event) => setBootstrapToken(event.target.value)} autoComplete="off" /></label>}
          <div className="setup-grid">
            {platformOnly && <label>管理员用户名<input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" /></label>}
            {!platformOnly && <label>RPZ Zone<input value={zone} onChange={(event) => setZone(event.target.value)} /></label>}
            {platformOnly && <label>管理员密码<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" /></label>}
            {platformOnly && <label>确认密码<input type="password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} autoComplete="new-password" /></label>}
          </div>
          {!platformOnly && <><label>Primary 地址（host:port）<input value={primary} onChange={(event) => setPrimary(event.target.value)} placeholder="例如 10.0.0.10:53" /></label>
          <label>Secondary 地址（每行一台，至少一台）<textarea value={secondaries} onChange={(event) => setSecondaries(event.target.value)} placeholder="例如 10.0.0.11:53" rows={3} /></label>
          <label>受保护 TSIG Key 文件路径<input value={tsigKeyPath} onChange={(event) => setTsigKeyPath(event.target.value)} placeholder="先将已有 Key 安全放入部署 secrets 目录" /></label>
          <div className="setup-warning">验证会在 Primary Zone 临时写入 TXT 记录，然后立即清理。只有写入和清理都成功，才会允许接入 BIND；只读 SOA 检查不能证明 TSIG 写权限。</div></>}
          {validationReady && <div className="setup-success">BIND 连接成功，可以进入白名单配置。点击“验证通过并完成初始化”后，白名单仍会保持 <code>draft</code>，不会自动发布。</div>}
          {error && <p className="setup-error">{error}</p>}
          <div className="setup-actions"><button type="submit" disabled={loading}>{loading ? "检查中…" : platformOnly ? "检查平台并继续" : "验证节点和 TSIG"}</button><button type="button" disabled={loading} onClick={(event) => void submit(event, "complete")}>{loading ? "处理中…" : platformOnly ? "创建管理员并启动平台" : "验证通过并接入 BIND"}</button></div>
        </form>
        {checks.length > 0 && <div className="setup-checks"><h2>检查结果</h2>{checks.map((check) => <article key={check.name} className={`setup-check ${check.status}`}><b>{check.status === "pass" ? "通过" : check.status === "fail" ? "失败" : "未执行"} · {check.name}</b><span>{check.detail}</span>{check.impact && <small>影响：{check.impact}</small>}{check.cleanup && <small>清理：{check.cleanup}</small>}</article>)}</div>}
      </section>
    </main>
  );
}
