import { FormEvent, useEffect, useState } from "react";
import { AuditPanel, type AuditEntry } from "./AuditPanel";
import { DnsNodePanel, type DnsNode } from "./DnsNodePanel";

type Overview = { nodes: number; healthyNodes: number; rules: number; publishedRules: number; pendingPublish: boolean; rpzHits: number | null; rpzHitStatus: string; lastSync: string; publisherMode: string; policyMode?: string; globalDenyZone?: string; lastPublish: string; publishMessage: string; publishJobId: string; publishJobStatus: string };
type Rule = { id: string; domain: string; action: string; type?: string; value?: string; reason: string; status: string; updatedAt: string };
type RPZChange = { type: string; domain: string; before: string; after: string };
type RPZPreview = { pending: boolean; currentCount: number; publishedCount: number; changes: RPZChange[] };
type RPZVersion = { id: string; createdAt: string; mode: string; ruleCount: number };
type PublishJob = { id: string; status: string; message?: string; error?: string };
type AuditResponse = { items: AuditEntry[]; total: number; page: number; pageSize: number };
type TelegramSettings = { enabled: boolean; botTokenSet: boolean; botTokenHint?: string; chatId: string; events: string[]; cooldownSeconds: number };
type DashboardView = "overview" | "audit";

const telegramEventOptions = [
  { value: "publish_failed", label: "RPZ 发布失败" },
  { value: "rpz_rule_create", label: "新增 RPZ 规则" },
  { value: "rpz_rule_update", label: "编辑 RPZ 规则" },
  { value: "rpz_rule_delete", label: "删除 RPZ 规则" },
  { value: "rpz_publish_success", label: "RPZ 发布成功" },
  { value: "rpz_rollback", label: "RPZ 回滚" },
  { value: "node_down", label: "DNS 节点不可达" },
  { value: "node_degraded", label: "RPZ Serial 不一致" },
  { value: "node_recovered", label: "节点恢复正常" },
];

function dashboardViewFromURL(): DashboardView {
  return new URLSearchParams(window.location.search).get("view") === "audit" ? "audit" : "overview";
}

function csrfHeaders(): Record<string, string> {
  const token = document.cookie.split(";").map((item) => item.trim()).find((item) => item.startsWith("dnsguard_csrf="))?.split("=").slice(1).join("=");
  return token ? { "X-CSRF-Token": decodeURIComponent(token) } : {};
}

async function readJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(url, { credentials: "include", ...init, signal: controller.signal });
    if (!response.ok) throw new Error((await response.json().catch(() => null))?.error ?? `请求失败（HTTP ${response.status}）`);
    return response.json() as Promise<T>;
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw new Error("请求超时，请检查 API 或 DNS 节点状态");
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
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

function formatDateTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value.replace(/Z$/, "");
  return date.toLocaleString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

function ruleActionLabel(rule: Rule): string {
  if (rule.type === "A" || rule.action === "redirect") return `A → ${rule.value || "未配置"}`;
  return "白名单";
}

export function DnsDashboard({ onLogout, authEnabled = true, mustChangePassword = false }: { onLogout: () => void; authEnabled?: boolean; mustChangePassword?: boolean }) {
  const [activeView, setActiveView] = useState<DashboardView>(dashboardViewFromURL);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [nodes, setNodes] = useState<DnsNode[]>([]);
  const [nodeDrafts, setNodeDrafts] = useState<Record<string, string>>({});
  const [editingNodeId, setEditingNodeId] = useState<string | null>(null);
  const [showNodeForm, setShowNodeForm] = useState(false);
  const [nodeName, setNodeName] = useState("");
  const [nodeRole, setNodeRole] = useState("辅节点");
  const [nodeAddress, setNodeAddress] = useState("");
  const [rules, setRules] = useState<Rule[]>([]);
  const [preview, setPreview] = useState<RPZPreview | null>(null);
  const [versions, setVersions] = useState<RPZVersion[]>([]);
  const [ruleSearch, setRuleSearch] = useState("");
  const [rulePage, setRulePage] = useState(1);
  const [rulePageSize, setRulePageSize] = useState(20);
  const [selectedRuleIds, setSelectedRuleIds] = useState<string[]>([]);
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [editDomain, setEditDomain] = useState("");
  const [editType, setEditType] = useState<"CNAME" | "A">("CNAME");
  const [editValue, setEditValue] = useState("");
  const [editReason, setEditReason] = useState("");
  const [domain, setDomain] = useState("");
  const [ruleType, setRuleType] = useState<"CNAME" | "A">("CNAME");
  const [recordValue, setRecordValue] = useState("");
  const [reason, setReason] = useState("");
  const [notice, setNotice] = useState("");
  const [loadError, setLoadError] = useState("");
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [showPasswordPanel, setShowPasswordPanel] = useState(mustChangePassword);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const [auditSearchDraft, setAuditSearchDraft] = useState("");
  const [auditSearch, setAuditSearch] = useState("");
  const [auditPage, setAuditPage] = useState(1);
  const [auditPageSize, setAuditPageSize] = useState(20);
  const [auditTotal, setAuditTotal] = useState(0);
  const [showTelegramPanel, setShowTelegramPanel] = useState(false);
  const [telegramSettings, setTelegramSettings] = useState<TelegramSettings | null>(null);
  const [telegramToken, setTelegramToken] = useState("");
  const [telegramChatId, setTelegramChatId] = useState("");
  const [telegramEvents, setTelegramEvents] = useState<string[]>([]);
  const [telegramCooldown, setTelegramCooldown] = useState(300);
  const selectView = (view: DashboardView) => {
    setActiveView(view);
    const url = new URL(window.location.href);
    if (view === "audit") url.searchParams.set("view", "audit");
    else url.searchParams.delete("view");
    window.history.replaceState({}, "", `${url.pathname}${url.search}${url.hash}`);
  };

  const load = async () => {
    setLoading(true);
    setLoadError("");
    try {
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
      setSelectedRuleIds((selected) => selected.filter((id) => (nextRules ?? []).some((rule) => rule.id === id)));
      setPreview(nextPreview);
      setVersions(nextVersions ?? []);
    } catch (error) {
      setLoadError(`状态加载失败：${(error as Error).message}。`);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const loadAudit = async (search = auditSearch, page = auditPage, pageSize = auditPageSize) => {
    try {
      const result = await readJSON<AuditResponse>(`/api/audit?q=${encodeURIComponent(search)}&page=${page}&pageSize=${pageSize}`);
      setAuditEntries(result.items ?? []);
      setAuditTotal(result.total ?? 0);
      setAuditPage(result.page ?? page);
    } catch (error) {
      setLoadError(`审计日志加载失败：${(error as Error).message}。`);
    }
  };

  const openTelegramPanel = async () => {
    setShowTelegramPanel(true);
    setNotice("");
    try {
      const result = await readJSON<TelegramSettings>("/api/settings/telegram");
      setTelegramSettings(result);
      setTelegramToken("");
      setTelegramChatId(result.chatId);
      setTelegramEvents(result.events ?? telegramEventOptions.map((event) => event.value));
      setTelegramCooldown(result.cooldownSeconds ?? 300);
    } catch (error) {
      setNotice(`Telegram 配置加载失败：${(error as Error).message}`);
    }
  };

  const saveTelegramSettings = async (event: FormEvent) => {
    event.preventDefault();
    if (!telegramChatId.trim()) {
      setNotice("请填写 Telegram Chat ID");
      return;
    }
    if (telegramEvents.length === 0) {
      setNotice("至少选择一项告警事件");
      return;
    }
    setBusy(true);
    setNotice("");
    try {
      const result = await readJSON<TelegramSettings>("/api/settings/telegram", {
        method: "PUT",
        headers: { "Content-Type": "application/json", ...csrfHeaders() },
        body: JSON.stringify({ botToken: telegramToken.trim(), chatId: telegramChatId.trim(), events: telegramEvents, cooldownSeconds: telegramCooldown }),
      });
      setTelegramSettings(result);
      setTelegramToken("");
      setNotice("Telegram 告警配置已保存");
    } catch (error) {
      setNotice(`Telegram 配置保存失败：${(error as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  const sendTelegramTest = async () => {
    setBusy(true);
    setNotice("");
    try {
      await readJSON("/api/settings/telegram/test", { method: "POST", headers: csrfHeaders() });
      setNotice("Telegram 测试消息已发送");
    } catch (error) {
      setNotice(`Telegram 测试失败：${(error as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  const clearTelegramSettings = async () => {
    if (!window.confirm("确认清除 Telegram Bot 配置？清除后将停止告警。")) return;
    setBusy(true);
    setNotice("");
    try {
      const result = await readJSON<TelegramSettings>("/api/settings/telegram", {
        method: "PUT",
        headers: { "Content-Type": "application/json", ...csrfHeaders() },
        body: JSON.stringify({ clearToken: true, chatId: "", events: telegramEvents, cooldownSeconds: telegramCooldown }),
      });
      setTelegramSettings(result);
      setTelegramChatId("");
      setTelegramToken("");
      setNotice("Telegram 告警已停用");
    } catch (error) {
      setNotice(`Telegram 配置清除失败：${(error as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (mustChangePassword) return;
    void load().catch((error: Error) => setNotice(error.message));
  }, [mustChangePassword]);

  useEffect(() => {
    if (mustChangePassword || activeView !== "audit") return;
    void loadAudit();
  }, [activeView, mustChangePassword]);

  useEffect(() => {
    const handlePopState = () => setActiveView(dashboardViewFromURL());
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  const addRule = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setNotice("");
    try {
      await readJSON<Rule>("/api/dns/rpz", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...csrfHeaders() },
        body: JSON.stringify({ domain, type: ruleType, value: ruleType === "A" ? recordValue : "", reason }),
      });
      setDomain(""); setRecordValue(""); setReason(""); setRuleType("CNAME");
      setNotice("RPZ 白名单规则已保存");
      await load();
    } catch (error) { setNotice(`RPZ 发布失败：${(error as Error).message}`); }
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
      setEditingNodeId(null);
      await load();
    } catch (error) { setNotice(`RPZ 回滚失败：${(error as Error).message}`); }
    finally { setBusy(false); }
  };

  const cancelNodeEdit = (node: DnsNode) => {
    setNodeDrafts((drafts) => ({ ...drafts, [node.id]: node.address }));
    setEditingNodeId(null);
  };

  const addNode = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setNotice("");
    try {
      await readJSON("/api/dns/nodes", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...csrfHeaders() },
        body: JSON.stringify({ name: nodeName, role: nodeRole, address: nodeAddress }),
      });
      setNodeName(""); setNodeRole("辅节点"); setNodeAddress(""); setShowNodeForm(false);
      setNotice("DNS 节点已添加");
      await load();
    } catch (error) { setNotice(`DNS 节点添加失败：${(error as Error).message}`); }
    finally { setBusy(false); }
  };

  const removeNode = async (node: DnsNode) => {
    if (!window.confirm(`确认删除节点“${node.name}”？删除后不会修改该节点上的 BIND 配置。`)) return;
    setBusy(true);
    setNotice("");
    try {
      await readJSON(`/api/dns/nodes/${encodeURIComponent(node.id)}`, { method: "DELETE", headers: csrfHeaders() });
      setNotice(`${node.name} 已删除`);
      await load();
    } catch (error) { setNotice(`DNS 节点删除失败：${(error as Error).message}`); }
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

  const startEditRule = (rule: Rule) => {
    setEditingRuleId(rule.id);
    setEditDomain(rule.domain);
    setEditType(rule.type === "A" || rule.action === "redirect" ? "A" : "CNAME");
    setEditValue(rule.value ?? "");
    setEditReason(rule.reason);
  };

  const cancelEditRule = () => setEditingRuleId(null);

  const saveRule = async (id: string) => {
    setBusy(true);
    setNotice("");
    try {
      await readJSON<Rule>(`/api/dns/rpz/${encodeURIComponent(id)}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", ...csrfHeaders() },
        body: JSON.stringify({ domain: editDomain, type: editType, value: editType === "A" ? editValue : "", reason: editReason }),
      });
      setEditingRuleId(null);
      setNotice("RPZ 规则已更新，等待发布");
      await load();
    } catch (error) { setNotice(`RPZ 规则更新失败：${(error as Error).message}`); }
    finally { setBusy(false); }
  };

  const bulkRemoveRules = async () => {
    if (selectedRuleIds.length === 0 || !window.confirm(`确认批量删除 ${selectedRuleIds.length} 条 RPZ 规则？`)) return;
    setBusy(true);
    setNotice("");
    try {
      const result = await readJSON<{ deleted: number }>("/api/dns/rpz/bulk", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...csrfHeaders() },
        body: JSON.stringify({ ids: selectedRuleIds }),
      });
      setSelectedRuleIds([]);
      setNotice(`已批量删除 ${result.deleted} 条规则`);
      await load();
    } catch (error) { setNotice((error as Error).message); }
    finally { setBusy(false); }
  };

  const publish = async () => {
    const changes = preview?.changes ?? [];
    if (changes.length === 0) {
      setNotice("当前没有待发布的 RPZ 变更");
      return;
    }
    const added = changes.filter((change) => change.type === "added").length;
    const changed = changes.filter((change) => change.type === "changed").length;
    const removed = changes.filter((change) => change.type === "removed").length;
    const summary = [`新增 ${added} 条`, `变更 ${changed} 条`, `删除 ${removed} 条`].join("，");
    if (!window.confirm(`确认发布 RPZ 变更？\n${summary}\n发布后将同步到 Primary 和 Secondary。`)) return;
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

  const changePassword = async (event: FormEvent) => {
    event.preventDefault();
    if (newPassword.length < 8) {
      setNotice("新密码至少需要 8 位");
      return;
    }
    if (newPassword !== confirmPassword) {
      setNotice("两次输入的新密码不一致");
      return;
    }
    setBusy(true);
    setNotice("");
    try {
      await readJSON<{ changed: boolean }>("/api/auth/password", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...csrfHeaders() },
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setShowPasswordPanel(false);
      setNotice("密码已修改，请使用新密码重新登录");
      onLogout();
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
  const auditPageCount = Math.max(1, Math.ceil(auditTotal / auditPageSize));
  const currentAuditPage = Math.min(auditPage, auditPageCount);
  const visibleRuleIds = visibleRules.map((rule) => rule.id);
  const allVisibleSelected = visibleRuleIds.length > 0 && visibleRuleIds.every((id) => selectedRuleIds.includes(id));
  const toggleVisibleRules = () => {
    setSelectedRuleIds((selected) => allVisibleSelected ? selected.filter((id) => !visibleRuleIds.includes(id)) : Array.from(new Set([...selected, ...visibleRuleIds])));
  };

  const renderRuleRow = (rule: Rule) => {
    if (editingRuleId === rule.id) {
      return <tr key={rule.id} className="rule-edit-row"><td>—</td><td><input className="rule-edit-input mono" value={editDomain} onChange={(event) => setEditDomain(event.target.value)} aria-label="编辑域名" /></td><td className="rule-edit-type"><select value={editType} onChange={(event) => setEditType(event.target.value as "CNAME" | "A")} aria-label="编辑记录类型"><option value="CNAME">白名单</option><option value="A">A</option></select>{editType === "A" && <input className="rule-edit-input" value={editValue} onChange={(event) => setEditValue(event.target.value)} placeholder="目标 IPv4" aria-label="编辑目标 IPv4" />}</td><td><input className="rule-edit-input" value={editReason} onChange={(event) => setEditReason(event.target.value)} aria-label="编辑原因" /></td><td><span className="rule-status draft">待发布</span></td><td>保存后更新</td><td className="node-actions"><button className="table-action node-save" disabled={busy} onClick={() => void saveRule(rule.id)}>保存</button><button className="table-action node-cancel" disabled={busy} onClick={cancelEditRule}>取消</button></td></tr>;
    }
    return <tr key={rule.id}><td><input type="checkbox" aria-label={`选择 ${rule.domain}`} checked={selectedRuleIds.includes(rule.id)} onChange={() => setSelectedRuleIds((selected) => selected.includes(rule.id) ? selected.filter((id) => id !== rule.id) : [...selected, rule.id])} /></td><td className="mono">{rule.domain}</td><td>{ruleActionLabel(rule)}</td><td>{rule.reason || "—"}</td><td><span className={`rule-status ${rule.status}`}>{rule.status === "published" ? "已发布" : rule.status === "compiled" ? "已生成" : "待发布"}</span></td><td>{formatDateTime(rule.updatedAt)}</td><td className="node-actions"><button className="table-action node-edit" onClick={() => startEditRule(rule)}>编辑</button><button className="table-action" onClick={() => void removeRule(rule.id)}>删除</button></td></tr>;
  };

  return (
    <main className="dns-shell">
      <header className="dns-header">
        <div><span className="dns-kicker">DNSGUARD OPERATIONS</span><h1>域盾 DNSGuard</h1><p className="dns-subtitle">DNS 安全策略管理平台</p><nav className="dns-nav" aria-label="平台导航"><button className={activeView === "overview" ? "active" : ""} onClick={() => selectView("overview")}>运行总览</button><button className={activeView === "audit" ? "active" : ""} onClick={() => selectView("audit")}>审计日志</button></nav></div>
        <div className="dns-header-actions"><button disabled={loading} onClick={() => void (activeView === "audit" ? loadAudit() : load()).catch(() => undefined)}>{loading ? "加载中…" : "刷新状态"}</button>{!mustChangePassword && <button className="ghost" onClick={() => void openTelegramPanel()}>告警配置</button>}{authEnabled && <><button className="ghost" onClick={() => setShowPasswordPanel(true)}>修改密码</button><button className="ghost" onClick={() => void logout()}>退出登录</button></>}</div>
      </header>

      {loadError && <div className="global-notice" role="alert"><span>{loadError}</span><button onClick={() => void load().catch(() => undefined)}>重试</button></div>}

      {showPasswordPanel && <div className="password-overlay" role="presentation" onMouseDown={(event) => { if (!mustChangePassword && event.target === event.currentTarget && !busy) setShowPasswordPanel(false); }}><section className="password-panel" role="dialog" aria-modal="true" aria-labelledby="password-title"><div className="panel-heading"><div><h2 id="password-title">{mustChangePassword ? "首次登录请修改密码" : "修改密码"}</h2><span>{mustChangePassword ? "为保障生产安全，修改密码后才能继续使用" : "修改成功后当前会话将退出"}</span></div>{!mustChangePassword && <button className="password-close" type="button" disabled={busy} onClick={() => setShowPasswordPanel(false)} aria-label="关闭">×</button>}</div><form className="password-form" onSubmit={changePassword}><label>当前密码<input type="password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} autoComplete="current-password" required /></label><label>新密码<input type="password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} autoComplete="new-password" minLength={8} required /></label><label>确认新密码<input type="password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} autoComplete="new-password" minLength={8} required /></label><p className="form-hint">新密码至少 8 位，修改后需要重新登录。</p><div className="password-actions">{!mustChangePassword && <button type="button" className="password-cancel" disabled={busy} onClick={() => setShowPasswordPanel(false)}>取消</button>}<button type="submit" disabled={busy}>{busy ? "保存中…" : "保存新密码"}</button></div></form></section></div>}

      {showTelegramPanel && <div className="password-overlay" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) setShowTelegramPanel(false); }}><section className="password-panel telegram-panel" role="dialog" aria-modal="true" aria-labelledby="telegram-title"><div className="panel-heading"><div><h2 id="telegram-title">告警配置</h2><span>{telegramSettings?.enabled ? "已启用 · 配置保存在服务端" : "未启用 · 配置保存在服务端"}</span></div><button className="password-close" type="button" disabled={busy} onClick={() => setShowTelegramPanel(false)} aria-label="关闭">×</button></div><form className="password-form" onSubmit={saveTelegramSettings}><label>Bot Token<input type="password" value={telegramToken} onChange={(event) => setTelegramToken(event.target.value)} placeholder={telegramSettings?.botTokenSet ? `已保存 ${telegramSettings.botTokenHint ?? "Token"}，留空保持不变` : "请输入 BotFather 生成的 Token"} autoComplete="new-password" /></label><label>Chat ID<input value={telegramChatId} onChange={(event) => setTelegramChatId(event.target.value)} placeholder="例如 -1001234567890" /></label><fieldset className="telegram-events"><legend>告警事件</legend>{telegramEventOptions.map((event) => <label key={event.value}><input type="checkbox" checked={telegramEvents.includes(event.value)} onChange={() => setTelegramEvents((selected) => selected.includes(event.value) ? selected.filter((item) => item !== event.value) : [...selected, event.value])} />{event.label}</label>)}</fieldset><label>重复告警冷却时间（秒）<input type="number" min={0} max={86400} value={telegramCooldown} onChange={(event) => setTelegramCooldown(Number(event.target.value))} /></label><p className="form-hint">Token 只会提交到后端，页面不会回显完整 Token。</p><div className="password-actions"><button type="button" className="password-cancel" disabled={busy || !telegramSettings?.enabled} onClick={() => void clearTelegramSettings()}>停用并清除</button><button type="button" className="password-cancel" disabled={busy || !telegramSettings?.enabled} onClick={() => void sendTelegramTest()}>发送测试</button><button type="submit" disabled={busy}>{busy ? "保存中…" : "保存配置"}</button></div></form></section></div>}

      {activeView === "overview" ? <>
      <section className="dns-cards">
        <article><span>DNS 节点</span><strong>{overview ? `${overview.healthyNodes}/${overview.nodes}` : "—"}</strong><small>健康节点</small></article>
        <article><span>RPZ 规则</span><strong>{overview?.rules ?? "—"}</strong><small>{overview?.publishedRules ?? 0} 条已发布</small></article>
        <article className={overview?.policyMode === "global" ? "" : "muted"}><span>默认拒绝策略</span><strong>{overview?.policyMode === "global" ? "全局 DENY" : "普通 RPZ"}</strong><small>{overview?.policyMode === "global" ? `Zone：${overview.globalDenyZone || "已配置"} · 白名单 / A 重定向优先` : "兼容模式，不启用全局默认拒绝"}</small></article>
        <article><span>最后同步</span><strong className="sync-value">{overview?.lastSync ?? "—"}</strong><small>Primary → Secondary</small></article>
      </section>

      <section className="dns-grid">
        <DnsNodePanel
          nodes={nodes}
          nodeDrafts={nodeDrafts}
          editingNodeId={editingNodeId}
          showNodeForm={showNodeForm}
          nodeName={nodeName}
          nodeRole={nodeRole}
          nodeAddress={nodeAddress}
          busy={busy}
          onToggleForm={() => setShowNodeForm((shown) => !shown)}
          onNodeNameChange={setNodeName}
          onNodeRoleChange={setNodeRole}
          onNodeAddressChange={setNodeAddress}
          onAddNode={addNode}
          onDraftChange={(id, value) => setNodeDrafts((drafts) => ({ ...drafts, [id]: value }))}
          onEdit={setEditingNodeId}
          onSave={(node) => { void saveNode(node); }}
          onCancel={cancelNodeEdit}
          onRemove={(node) => { void removeNode(node); }}
        />

        <div className="dns-panel"><div className="panel-heading"><h2>添加 RPZ 规则</h2><span>FILE-BACKED</span></div><form className="rule-form" onSubmit={addRule}><label>域名<input value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="例如 baidu.com" required /></label><p className="form-hint">输入 baidu.com 将同时覆盖 baidu.com 和 *.baidu.com。</p><label>记录类型<select value={ruleType} onChange={(event) => setRuleType(event.target.value as "CNAME" | "A")}><option value="CNAME">白名单（CNAME / passthru）</option><option value="A">A 记录重定向</option></select></label>{ruleType === "A" && <label>目标 IPv4<input value={recordValue} onChange={(event) => setRecordValue(event.target.value)} placeholder="例如 192.0.2.10" inputMode="numeric" pattern="(?:[0-9]{1,3}\.){3}[0-9]{1,3}" required /></label>}<label>原因（可选）<input value={reason} onChange={(event) => setReason(event.target.value)} placeholder={ruleType === "A" ? "业务流量导向指定服务" : "业务系统依赖"} /></label><button disabled={busy}>{busy ? "保存中…" : "保存 RPZ 规则"}</button></form>{notice && <p className="notice">{notice}</p>}</div>
      </section>

      <section className="release-grid">
        <section className="dns-panel"><div className="panel-heading"><div><h2>发布预览</h2><span>{preview?.pending ? `${preview.changes?.length ?? 0} 项待发布变更` : "当前版本已同步"}</span></div><span>规则 {preview?.currentCount ?? 0} 条 · 已发布 {preview?.publishedCount ?? 0} 条</span></div>{preview?.changes?.length ? <div className="change-list">{preview.changes.slice(0, 20).map((change) => <div className="change-item" key={`${change.type}-${change.domain}`}><strong className={`change-${change.type}`}>{change.type === "added" ? "新增" : change.type === "removed" ? "删除" : "变更"}</strong><span className="mono">{change.domain}</span><small>{change.after || change.before}</small></div>)}{preview.changes.length > 20 && <p className="notice">仅显示前 20 项变更。</p>}</div> : <div className="empty">暂无待发布变更</div>}</section>
        <section className="dns-panel"><div className="panel-heading"><div><h2>版本记录</h2><span>最多保留 20 个发布版本</span></div></div>{versions.length ? <div className="version-list">{versions.map((version) => <div className="version-item" key={version.id}><div><strong>{formatDateTime(version.createdAt)}</strong><small>{version.ruleCount} 条规则 · {version.mode}</small></div><button className="table-action" disabled={busy} onClick={() => void rollback(version.id)}>回滚并发布</button></div>)}</div> : <div className="empty">暂无发布版本</div>}</section>
      </section>

        <section className="dns-panel"><div className="panel-heading"><div><h2>RPZ 规则</h2><span>ALLOW / PASSTHRU / A · 显示 {ruleStart}-{ruleEnd} / {filteredRules.length} 条 · 当前模式：{overview?.publisherMode ?? "artifact"} · 任务：{overview?.publishJobStatus ?? "idle"}</span></div><div className="record-tools"><input className="record-search" value={ruleSearch} onChange={(event) => { setRuleSearch(event.target.value); setRulePage(1); }} placeholder="搜索域名 / 原因" aria-label="搜索 RPZ 规则" /><button className="table-action bulk-action" disabled={busy || selectedRuleIds.length === 0} onClick={() => void bulkRemoveRules()}>批量删除{selectedRuleIds.length ? `（${selectedRuleIds.length}）` : ""}</button><button className="publish-button" disabled={busy || !overview?.pendingPublish} onClick={() => void publish()}>{overview?.pendingPublish ? "生成 / 发布 RPZ" : "已是最新"}</button></div></div><div className="table-wrap"><table><thead><tr><th><input type="checkbox" aria-label="选择当前页规则" checked={allVisibleSelected} onChange={toggleVisibleRules} /></th><th>域名</th><th>动作</th><th>原因</th><th>状态</th><th>更新时间</th><th /></tr></thead><tbody>{visibleRules.map(renderRuleRow)}</tbody></table>{rules.length === 0 ? <div className="empty">暂无 RPZ 规则</div> : filteredRules.length === 0 ? <div className="empty">没有匹配的 RPZ 规则</div> : null}</div>{filteredRules.length > 0 && <div className="pagination"><span>第 {currentRulePage} / {rulePageCount} 页</span><div className="pagination-actions"><label>每页 <select value={rulePageSize} onChange={(event) => { setRulePageSize(Number(event.target.value)); setRulePage(1); }}><option value={10}>10</option><option value={20}>20</option><option value={50}>50</option></select> 条</label><button disabled={currentRulePage <= 1} onClick={() => setRulePage(Math.max(1, currentRulePage - 1))}>上一页</button><button disabled={currentRulePage >= rulePageCount} onClick={() => setRulePage(Math.min(rulePageCount, currentRulePage + 1))}>下一页</button></div></div>}</section>
      </> : <AuditPanel
        entries={auditEntries}
        total={auditTotal}
        pageSize={auditPageSize}
        pageCount={auditPageCount}
        currentPage={currentAuditPage}
        searchDraft={auditSearchDraft}
        onSearchDraftChange={setAuditSearchDraft}
        onSearch={() => {
          setAuditSearch(auditSearchDraft);
          setAuditPage(1);
          void loadAudit(auditSearchDraft, 1, auditPageSize);
        }}
        onPageSizeChange={(size) => {
          setAuditPageSize(size);
          setAuditPage(1);
          void loadAudit(auditSearch, 1, size);
        }}
        onPrevious={() => void loadAudit(auditSearch, currentAuditPage - 1, auditPageSize)}
        onNext={() => void loadAudit(auditSearch, currentAuditPage + 1, auditPageSize)}
      />}
      <footer className="dns-footer">当前版本：文件型控制面 · DNS 节点状态通过 dig / SOA Serial 实时探测</footer>
    </main>
  );
}
