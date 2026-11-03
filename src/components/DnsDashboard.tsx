import { FormEvent, useEffect, useState } from "react";

type Overview = { nodes: number; healthyNodes: number; rules: number; publishedRules: number; pendingPublish: boolean; rpzHits: number; lastSync: string; publisherMode: string; lastPublish: string; publishMessage: string };
type DnsNode = { id: string; name: string; role: string; address: string; status: string; rpzVersion: string; lastSync: string };
type Rule = { id: string; domain: string; action: string; reason: string; status: string; updatedAt: string };
const RULE_PAGE_SIZE = 10;

function csrfHeaders(): Record<string, string> {
  const token = document.cookie.split(";").map((item) => item.trim()).find((item) => item.startsWith("network_csrf="))?.split("=").slice(1).join("=");
  return token ? { "X-CSRF-Token": decodeURIComponent(token) } : {};
}

async function readJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, { credentials: "include", ...init });
  if (!response.ok) throw new Error((await response.json().catch(() => null))?.error ?? "请求失败");
  return response.json() as Promise<T>;
}

export function DnsDashboard({ onLogout, authEnabled = true }: { onLogout: () => void; authEnabled?: boolean }) {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [nodes, setNodes] = useState<DnsNode[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [ruleSearch, setRuleSearch] = useState("");
  const [rulePage, setRulePage] = useState(1);
  const [domain, setDomain] = useState("");
  const [reason, setReason] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const load = async () => {
    const [nextOverview, nextNodes, nextRules] = await Promise.all([
      readJSON<Overview>("/api/dns/overview"),
      readJSON<DnsNode[]>("/api/dns/nodes"),
      readJSON<Rule[]>("/api/dns/rpz"),
    ]);
    setOverview(nextOverview);
    setNodes(nextNodes ?? []);
    setRules(nextRules ?? []);
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
      const result = await readJSON<{ message: string }>("/api/dns/rpz/publish", { method: "POST", headers: csrfHeaders() });
      setNotice(result.message);
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
  const rulePageCount = Math.max(1, Math.ceil(filteredRules.length / RULE_PAGE_SIZE));
  const currentRulePage = Math.min(rulePage, rulePageCount);
  const visibleRules = filteredRules.slice((currentRulePage - 1) * RULE_PAGE_SIZE, currentRulePage * RULE_PAGE_SIZE);

  return (
    <main className="dns-shell">
      <header className="dns-header">
        <div><span className="dns-kicker">DNS OPERATIONS CONTROL</span><h1>企业 DNS / RPZ 管理平台</h1><p>文件型策略控制面，不使用数据库。</p></div>
        <div className="dns-header-actions"><button onClick={() => void load()}>刷新状态</button>{authEnabled && <button className="ghost" onClick={() => void logout()}>退出登录</button>}</div>
      </header>

      <section className="dns-cards">
        <article><span>DNS 节点</span><strong>{overview ? `${overview.healthyNodes}/${overview.nodes}` : "—"}</strong><small>健康节点</small></article>
        <article><span>RPZ 规则</span><strong>{overview?.rules ?? "—"}</strong><small>{overview?.publishedRules ?? 0} 条已发布</small></article>
        <article><span>RPZ 命中</span><strong>{overview?.rpzHits?.toLocaleString() ?? "—"}</strong><small>最近统计窗口</small></article>
        <article><span>最后同步</span><strong className="sync-value">{overview?.lastSync ?? "—"}</strong><small>Primary → Secondary</small></article>
      </section>

      <section className="dns-grid">
        <div className="dns-panel dns-panel-wide"><div className="panel-heading"><h2>DNS 节点</h2><span>LIVE DIG / SOA PROBE</span></div><div className="table-wrap"><table><thead><tr><th>名称</th><th>角色</th><th>地址</th><th>状态</th><th>RPZ 版本</th><th>最近同步</th></tr></thead><tbody>{nodes.map((node) => <tr key={node.id}><td>{node.name}</td><td>{node.role}</td><td className="mono">{node.address}</td><td><i className={`status-dot ${node.status === "healthy" ? "ok" : "warn"}`} />{node.status === "healthy" ? "正常" : node.status === "degraded" ? "版本不一致" : "不可达"}</td><td className="mono">{node.rpzVersion}</td><td>{node.lastSync}</td></tr>)}</tbody></table></div></div>

        <div className="dns-panel"><div className="panel-heading"><h2>添加 RPZ 白名单</h2><span>FILE-BACKED</span></div><form className="rule-form" onSubmit={addRule}><label>域名<input value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="例如 baidu.com" required /></label><p className="form-hint">输入 baidu.com 将同时覆盖 baidu.com 和 *.baidu.com。</p><label>原因<input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="业务系统依赖" required /></label><button disabled={busy}>{busy ? "保存中…" : "保存白名单规则"}</button></form>{notice && <p className="notice">{notice}</p>}</div>
      </section>

      <section className="dns-panel"><div className="panel-heading"><div><h2>RPZ 规则</h2><span>ALLOW / PASSTHRU · {filteredRules.length}/{rules.length} 条 · 当前模式：{overview?.publisherMode ?? "artifact"}</span></div><div className="record-tools"><input className="record-search" value={ruleSearch} onChange={(event) => { setRuleSearch(event.target.value); setRulePage(1); }} placeholder="搜索域名 / 原因" aria-label="搜索 RPZ 规则" /><button className="publish-button" disabled={busy || !overview?.pendingPublish} onClick={() => void publish()}>{overview?.pendingPublish ? "生成 / 发布 RPZ" : "已是最新"}</button></div></div><div className="table-wrap"><table><thead><tr><th>域名</th><th>动作</th><th>原因</th><th>状态</th><th>更新时间</th><th /></tr></thead><tbody>{visibleRules.map((rule) => <tr key={rule.id}><td className="mono">{rule.domain}</td><td>{rule.action}</td><td>{rule.reason}</td><td><span className={`rule-status ${rule.status}`}>{rule.status === "published" ? "已发布" : rule.status === "compiled" ? "已生成" : "待发布"}</span></td><td>{rule.updatedAt}</td><td><button className="table-action" onClick={() => void removeRule(rule.id)}>删除</button></td></tr>)}</tbody></table>{rules.length === 0 ? <div className="empty">暂无 RPZ 规则</div> : filteredRules.length === 0 ? <div className="empty">没有匹配的 RPZ 规则</div> : null}</div>{filteredRules.length > 0 && <div className="pagination"><span>第 {currentRulePage} / {rulePageCount} 页</span><div><button disabled={currentRulePage <= 1} onClick={() => setRulePage((page) => Math.max(1, page - 1))}>上一页</button><button disabled={currentRulePage >= rulePageCount} onClick={() => setRulePage((page) => Math.min(rulePageCount, page + 1))}>下一页</button></div></div>}</section>
      <footer className="dns-footer">当前版本：文件型控制面 · DNS 节点状态通过 dig / SOA Serial 实时探测</footer>
    </main>
  );
}
