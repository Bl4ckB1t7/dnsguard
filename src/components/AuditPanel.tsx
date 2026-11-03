import { useState, type KeyboardEvent } from "react";

export type AuditEntry = { timestamp: string; actor: string; action: string; result: string; ip?: string; hash?: string };
type RuleAuditDetail = { domain: string; type: string; value?: string; reason?: string };

type AuditPanelProps = {
  entries: AuditEntry[];
  total: number;
  pageSize: number;
  pageCount: number;
  currentPage: number;
  searchDraft: string;
  onSearchDraftChange: (value: string) => void;
  onSearch: () => void;
  onPageSizeChange: (size: number) => void;
  onPrevious: () => void;
  onNext: () => void;
};

function formatDateTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value.replace(/Z$/, "");
  return date.toLocaleString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

function auditActionLabel(action: string): string {
  const labels: Record<string, string> = {
    login: "登录",
    logout: "退出登录",
    "password.change": "修改密码",
    "dns.node.create": "增加 DNS 节点",
    "dns.node.update": "更新 DNS 节点",
    "dns.node.delete": "删除 DNS 节点",
    "rpz.rule.create": "新增 RPZ 规则",
    "rpz.rule.update": "编辑 RPZ 规则",
    "rpz.rule.delete": "删除 RPZ 规则",
    "rpz.publish": "发布 RPZ",
    "rpz.rollback": "回滚 RPZ",
  };
  return labels[action] ?? action;
}

function parseRuleAuditDetail(entry: AuditEntry): RuleAuditDetail | null {
  if (entry.action !== "rpz.rule.create" && entry.action !== "rpz.rule.update" && entry.action !== "rpz.rule.delete") return null;
  try {
    const parsed = JSON.parse(entry.result) as RuleAuditDetail;
    if (parsed && typeof parsed.domain === "string" && typeof parsed.type === "string") return parsed;
  } catch {
    // Older entries stored only the domain and remain readable in the summary.
  }
  return entry.result ? { domain: entry.result, type: "未知" } : null;
}

function auditRuleTypeLabel(type: string): string {
  return type === "CNAME" || type === "PASSTHRU" ? "白名单（PASSTHRU）" : type;
}

function auditDetail(entry: AuditEntry): string {
  const readableNodeDetail = (verb: string): string => {
    if (entry.result.includes(" / ")) return `${verb}：${entry.result}`;
    const separator = entry.result.indexOf(":");
    return separator > 0 ? `${verb}：节点 ID ${entry.result.slice(0, separator)} · 地址 ${entry.result.slice(separator + 1)}` : `${verb}：${entry.result}`;
  };
  if (entry.action === "login") return entry.result === "success" ? "登录成功" : "登录失败";
  if (entry.action === "logout") return "会话已退出";
  if (entry.action === "password.change") return "账户密码已更新";
  if (entry.action === "dns.node.create") return readableNodeDetail("已添加");
  if (entry.action === "dns.node.update") return readableNodeDetail("已更新");
  if (entry.action === "dns.node.delete") return readableNodeDetail("已删除");
  const ruleDetail = parseRuleAuditDetail(entry);
  if (ruleDetail) return `域名：${ruleDetail.domain}`;
  if (entry.action === "rpz.publish") {
    const status = entry.result.includes(":") ? entry.result.split(":").slice(1).join(":") : entry.result;
    return status === "published" ? "发布成功" : status === "compiled" ? "RPZ 文件已生成" : status;
  }
  if (entry.action === "rpz.rollback") return `版本 ${entry.result}`;
  return entry.result;
}

function auditResult(entry: AuditEntry): { label: string; tone: "success" | "failure" | "info" } {
  if (entry.action === "login" && entry.result === "failure") return { label: "失败", tone: "failure" };
  if (entry.result.toLowerCase().includes("fail")) return { label: "失败", tone: "failure" };
  if (entry.action === "rpz.publish") return { label: "已发布", tone: "success" };
  return { label: "已完成", tone: "success" };
}

export function AuditPanel({ entries, total, pageSize, pageCount, currentPage, searchDraft, onSearchDraftChange, onSearch, onPageSizeChange, onPrevious, onNext }: AuditPanelProps) {
  const [expandedAuditKey, setExpandedAuditKey] = useState<string | null>(null);

  const handleSearchKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Enter") onSearch();
  };

  return <section className="dns-panel audit-page audit-panel"><div className="panel-heading"><div><h2>审计日志</h2><span>共 {total} 条 · 最新操作优先</span></div><div className="record-tools"><input className="record-search" value={searchDraft} onChange={(event) => onSearchDraftChange(event.target.value)} onKeyDown={handleSearchKeyDown} placeholder="搜索日志" aria-label="搜索审计日志" /><button className="table-action" onClick={onSearch}>搜索</button></div></div><div className="audit-list">{entries.map((entry, index) => { const result = auditResult(entry); const entryKey = `${entry.timestamp}-${entry.action}-${index}`; const ruleDetail = parseRuleAuditDetail(entry); const expanded = expandedAuditKey === entryKey; const toggle = () => { if (ruleDetail) setExpandedAuditKey(expanded ? null : entryKey); }; return <div className="audit-entry-wrap" key={entryKey}><article className={`audit-row ${ruleDetail ? "is-clickable" : ""}`} onClick={toggle} onKeyDown={(event) => { if (ruleDetail && (event.key === "Enter" || event.key === " ")) { event.preventDefault(); toggle(); } }} role={ruleDetail ? "button" : undefined} tabIndex={ruleDetail ? 0 : undefined} aria-expanded={ruleDetail ? expanded : undefined}><time className="audit-time" dateTime={entry.timestamp}>{formatDateTime(entry.timestamp)}</time><div className="audit-event"><div><strong className="audit-action">{auditActionLabel(entry.action)}</strong><span className="audit-detail">{auditDetail(entry)}</span></div><small>{entry.actor || "系统"} · 来源 {entry.ip || "未知"}</small></div><span className={`audit-result ${result.tone}`}>{result.label}</span><span className="audit-verified" title={entry.hash || "无哈希校验"}>{entry.hash ? "日志校验通过" : "未校验"}</span></article>{expanded && ruleDetail && <div className="audit-expanded"><span><b>域名</b>{ruleDetail.domain}</span><span><b>类型</b>{auditRuleTypeLabel(ruleDetail.type)}</span>{ruleDetail.value && <span><b>目标</b>{ruleDetail.value}</span>}<span><b>原因</b>{ruleDetail.reason || "未填写"}</span></div>}</div>; })}{entries.length === 0 && <div className="empty">暂无匹配的审计日志</div>}</div>{total > 0 && <div className="pagination"><span>第 {currentPage} / {pageCount} 页</span><div className="pagination-actions"><label>每页 <select value={pageSize} onChange={(event) => onPageSizeChange(Number(event.target.value))}><option value={10}>10</option><option value={20}>20</option><option value={50}>50</option></select> 条</label><button disabled={currentPage <= 1} onClick={onPrevious}>上一页</button><button disabled={currentPage >= pageCount} onClick={onNext}>下一页</button></div></div>}</section>;
}
