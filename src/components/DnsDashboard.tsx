import { FormEvent, useEffect, useState } from "react";

type Overview = { nodes: number; healthyNodes: number; rules: number; publishedRules: number; pendingPublish: boolean; rpzHits: number | null; rpzHitStatus: string; lastSync: string; publisherMode: string; lastPublish: string; publishMessage: string; publishJobId: string; publishJobStatus: string };
type DnsNode = { id: string; name: string; role: string; address: string; status: string; rpzVersion: string; lastSync: string };
type Rule = { id: string; domain: string; action: string; reason: string; status: string; updatedAt: string };
type RPZChange = { type: string; domain: string; before: string; after: string };
type RPZPreview = { pending: boolean; currentCount: number; publishedCount: number; changes: RPZChange[] };
type RPZVersion = { id: string; createdAt: string; mode: string; ruleCount: number };
type PublishJob = { id: string; status: string; message?: string; error?: string };

function csrfHeaders(): Record<string, string> {
  const token = document.cookie.split(";").map((item) => item.trim()).find((item) => item.startsWith("network_csrf="))?.split("=").slice(1).join("=");
  return token ? { "X-CSRF-Token": decodeURIComponent(token) } : {};
}

async function readJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, { credentials: "include", ...init });
  if (!response.ok) throw new Error((await response.json().catch(() => null))?.error ?? "请求失败");
  return response.json() as Promise<T>;
}

async function waitForPublishJob(id: string): Promise<PublishJob> {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const job = await readJSON<PublishJob>(`/api/dns/rpz/jobs/${encodeURIComponent(id)}`);
    if (job.status === "succeeded") return job;
    if (job.status === "failed") throw new Error(job.error ?? "RPZ 发布失败");
    await new Promise((resolve) => window.setTimeout(resolve, 250));
  }
  throw new Error("RPZ 发布任务超时，请查看任务状态");
}

export function DnsDashboard({ onLogout, authEnabled = true }: { onLogout: () => void; authEnabled?: boolean }) {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [nodes, setNodes] = useState<DnsNode[]>([]);
  const [nodeDrafts, setNodeDrafts] = useState<Record<string, string>>({});
  const [rules, setRules] = useState<Rule[]>([]);
  const [preview, setPreview] = useState<RPZPreview | null>(null);
  const [versions, setVersions] = useState<RPZVersion[]>([]);
  const [ruleSearch, setRuleSearch] = useState("");
  const [rulePage, setRulePage] = useState(1);
  const [rulePageSize, setRulePageSize] = useState(20);
  const [domain, setDomain] = useState("");
  const [reason, setReason] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const load = async () => {
    const [nextOverview, nextNodes, nextRules, nextPreview, nextVersions] = await Promise.all([
      readJSON<Overview>("/api/dns/overview"),
      readJSON<DnsNode[]>("/api/dns/nodes"),
      readJSON<Rule[]>("/api/dns/rpz"),
      readJSON<RPZPreview>("/api/dns/rpz/preview"),
      readJSON<RPZVersion[]>("/api/dns/rpz/versions"),
    ]);
    setOverview(nextOverview);
    setNodes(nextNodes ?? []);
    setNodeDrafts(Object.fromEntries((nextNodes ?? []).map((node) => [node.id, node.address])));
    setRules(nextRules ?? []);
    setPreview(nextPreview);
    setVersions(nextVersions ?? []);
  };

  useEffect(() => { void load().catch((error: Error) => setNotice(error.message)); }, []);

  const addRule = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setNotice("");
    try {
      await readJSON<Rule>("/api/dns/rpz", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...csrfHeaders() },
        body: JSON.stringify({ domain, reason }),
      });
      setDomain(""); setReason("");
      setNotice("RPZ 白名单规则已保存");
      await load();
    } catch (error) { setNotice((error as Error).message); }
    finally { setBusy(false); }
  };

  const saveNode = async (node: DnsNode) => {
    setBusy(true);
    setNotice("");
    try {
      await readJSON(`/api/dns/nodes`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...csrfHeaders() },
        body: JSON.stringify({ id: node.id, address: nodeDrafts[node.id] ?? node.address }),
      });
      setNotice(`${node.name} 配置已保存`);
      await load();
    } catch (error) { setNotice((error as Error).message); }
    finally { setBusy(false); }
  };

  const removeRule = async (id: string) => {
    if (!window.confirm("确认删除这条 RPZ 规则？")) return;
    try {
      await readJSON(`/api/dns/rpz/${encodeURIComponent(id)}`, { method: "DELETE", headers: csrfHeaders() });
      setNotice("规则已删除");
      await load();
    } catch (error) { setNotice((error as Error).message); }
  };

  const publish = async () => {
    setBusy(true);
    setNotice("");
    try {
      const queued = await readJSON<PublishJob>("/api/dns/rpz/publish", { method: "POST", headers: csrfHeaders() });
      const result = await waitForPublishJob(queued.id);
      setNotice(result.message ?? "RPZ 发布成功");
      await load();
    } catch (error) { setNotice((error as Error).message); }
    finally { setBusy(false); }
  };

  const rollback = async (versionId: string) => {
    if (!window.confirm("确认回滚并立即发布这个 RPZ 版本？")) return;
    setBusy(true);
    setNotice("");
    try {
      const queued = await readJSON<PublishJob>("/api/dns/rpz/rollback", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...csrfHeaders() },
        body: JSON.stringify({ versionId }),
      });
      const result = await waitForPublishJob(queued.id);
      setNotice(`回滚成功：${result.message ?? "RPZ 已重新发布"}`);
      await load();
    } catch (error) { setNotice((error as Error).message); }
    finally { setBusy(false); }
  };

  const logout = async () => {
    await fetch("/api/auth/logout", { method: "POST", credentials: "include" });
    onLogout();
  };

  const filteredRules = rules.filter((rule) => {
    const query = ruleSearch.trim().toLowerCase();
    if (!query) return true;
    return [rule.domain, rule.action, rule.reason, rule.status].some((value) => value.toLowerCase().includes(query));
  });
  const rulePageCount = Math.max(1, Math.ceil(filteredRules.length / rulePageSize));
  const currentRulePage = Math.min(rulePage, rulePageCount);
  const visibleRules = filteredRules.slice((currentRulePage - 1) * rulePageSize, currentRulePage * rulePageSize);
  const ruleStart = filteredRules.length === 0 ? 0 : (currentRulePage - 1) * rulePageSize + 1;
  const ruleEnd = Math.min(currentRulePage * rulePageSize, filteredRules.length);

  return (
    <main className="dns-shell">
      <header className="dns-header">
        <div><span className="dns-kicker">DNS OPERATIONS CONTROL</span><h1>企业 DNS / RPZ 管理平台</h1><p>文件型策略控制面，不使用数据库。</p></div>
        <div className="dns-header-actions"><button onClick={() => void load()}>刷新状态</button>{authEnabled && <button className="ghost" onClick={() => void logout()}>退出登录</button>}</div>
      </header>

      <section className="dns-cards">
        <article><span>DNS 节点</span><strong>{overview ? `${overview.healthyNodes}/${overview.nodes}` : "—"}</strong><small>健康节点</small></article>
        <article><span>RPZ 规则</span><strong>{overview?.rules ?? "—"}</strong><small>{overview?.publishedRules ?? 0} 条已发布</small></article>
        <article><span>RPZ 命中</span><strong>{overview?.rpzHits?.toLocaleString() ?? "—"}</strong><small>{overview?.rpzHitStatus === "ready" ? "BIND 日志去重累计" : "未配置 RPZ 日志"}</small></article>
        <article><span>最后同步</span><strong className="sync-value">{overview?.lastSync ?? "—"}</strong><small>Primary → Secondary</small></article>
      </section>

      <section className="dns-grid">
        <div className="dns-panel dns-panel-wide"><div className="panel-heading"><h2>DNS 节点</h2><span>LIVE DIG / SOA PROBE</span></div><div className="table-wrap"><table><thead><tr><th>名称</th><th>角色</th><th>地址配置</th><th>状态</th><th>RPZ 版本</th><th>最近同步</th><th /></tr></thead><tbody>{nodes.map((node) => <tr key={node.id}><td>{node.name}</td><td>{node.role}</td><td><input className="node-address" value={nodeDrafts[node.id] ?? node.address} onChange={(event) => setNodeDrafts((drafts) => ({ ...drafts, [node.id]: event.target.value }))} /></td><td><i className={`status-dot ${node.status === "healthy" ? "ok" : "warn"}`} />{node.status === "healthy" ? "正常" : node.status === "degraded" ? "版本不一致" : "不可达"}</td><td className="mono">{node.rpzVersion}</td><td>{node.lastSync}</td><td><button className="table-action node-save" disabled={busy} onClick={() => void saveNode(node)}>保存</button></td></tr>)}</tbody></table></div></div>

        <div className="dns-panel"><div className="panel-heading"><h2>添加 RPZ 白名单</h2><span>FILE-BACKED</span></div><form className="rule-form" onSubmit={addRule}><label>域名<input value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="例如 baidu.com" required /></label><p className="form-hint">输入 baidu.com 将同时覆盖 baidu.com 和 *.baidu.com。</p><label>原因<input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="业务系统依赖" required /></label><button disabled={busy}>{busy ? "保存中…" : "保存白名单规则"}</button></form>{notice && <p className="notice">{notice}</p>}</div>
      </section>

      <section className="release-grid">
        <section className="dns-panel"><div className="panel-heading"><div><h2>发布预览</h2><span>{preview?.pending ? `${preview.changes.length} 项待发布变更` : "当前版本已同步"}</span></div><span>{preview?.currentCount ?? 0} / {preview?.publishedCount ?? 0} 条</span></div>{preview?.changes.length ? <div className="change-list">{preview.changes.slice(0, 20).map((change) => <div className="change-item" key={`${change.type}-${change.domain}`}><strong className={`change-${change.type}`}>{change.type === "added" ? "新增" : change.type === "removed" ? "删除" : "变更"}</strong><span className="mono">{change.domain}</span><small>{change.after || change.before}</small></div>)}{preview.changes.length > 20 && <p className="notice">仅显示前 20 项变更。</p>}</div> : <div className="empty">暂无待发布变更</div>}</section>
        <section className="dns-panel"><div className="panel-heading"><div><h2>版本记录</h2><span>最多保留 20 个发布版本</span></div></div>{versions.length ? <div className="version-list">{versions.map((version) => <div className="version-item" key={version.id}><div><strong>{version.createdAt}</strong><small>{version.ruleCount} 条规则 · {version.mode}</small></div><button className="table-action" disabled={busy} onClick={() => void rollback(version.id)}>回滚并发布</button></div>)}</div> : <div className="empty">暂无发布版本</div>}</section>
      </section>

      <section className="dns-panel"><div className="panel-heading"><div><h2>RPZ 规则</h2><span>ALLOW / PASSTHRU · 显示 {ruleStart}-{ruleEnd} / {filteredRules.length} 条 · 当前模式：{overview?.publisherMode ?? "artifact"} · 任务：{overview?.publishJobStatus ?? "idle"}</span></div><div className="record-tools"><input className="record-search" value={ruleSearch} onChange={(event) => { setRuleSearch(event.target.value); setRulePage(1); }} placeholder="搜索域名 / 原因" aria-label="搜索 RPZ 规则" /><button className="publish-button" disabled={busy || !overview?.pendingPublish} onClick={() => void publish()}>{overview?.pendingPublish ? "生成 / 发布 RPZ" : "已是最新"}</button></div></div><div className="table-wrap"><table><thead><tr><th>域名</th><th>动作</th><th>原因</th><th>状态</th><th>更新时间</th><th /></tr></thead><tbody>{visibleRules.map((rule) => <tr key={rule.id}><td className="mono">{rule.domain}</td><td>{rule.action}</td><td>{rule.reason}</td><td><span className={`rule-status ${rule.status}`}>{rule.status === "published" ? "已发布" : rule.status === "compiled" ? "已生成" : "待发布"}</span></td><td>{rule.updatedAt}</td><td><button className="table-action" onClick={() => void removeRule(rule.id)}>删除</button></td></tr>)}</tbody></table>{rules.length === 0 ? <div className="empty">暂无 RPZ 规则</div> : filteredRules.length === 0 ? <div className="empty">没有匹配的 RPZ 规则</div> : null}</div>{filteredRules.length > 0 && <div className="pagination"><span>第 {currentRulePage} / {rulePageCount} 页</span><div className="pagination-actions"><label>每页 <select value={rulePageSize} onChange={(event) => { setRulePageSize(Number(event.target.value)); setRulePage(1); }}><option value={10}>10</option><option value={20}>20</option><option value={50}>50</option></select> 条</label><button disabled={currentRulePage <= 1} onClick={() => setRulePage(Math.max(1, currentRulePage - 1))}>上一页</button><button disabled={currentRulePage >= rulePageCount} onClick={() => setRulePage(Math.min(rulePageCount, currentRulePage + 1))}>下一页</button></div></div>}</section>
      <footer className="dns-footer">当前版本：文件型控制面 · DNS 节点状态通过 dig / SOA Serial 实时探测</footer>
    </main>
  );
}
