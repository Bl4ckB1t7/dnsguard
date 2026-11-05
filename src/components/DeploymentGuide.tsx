type GuideOverview = {
  rules: number;
  publishedRules: number;
  pendingPublish: boolean;
  publishEvidenceReady?: boolean;
  publishEvidence?: { status: string; syncStatus?: string };
  policyMode?: string;
  globalDenyZone?: string;
};

type GuideNode = { status: string };
type GuidePreview = { pending: boolean; changes: number };
type GuideCheck = { name: string; status: "pass" | "fail" | "not_run"; detail: string };
type SetupStatus = { globalDenySetupDeferred?: boolean; policyMode?: "global" | "legacy" };

type DeploymentGuideProps = {
  overview: GuideOverview | null;
  nodes: GuideNode[];
  preview: GuidePreview | null;
  setupStatus: SetupStatus | null;
  checkingDeny: boolean;
  denyNotice: string;
  denyReady: boolean;
  denyChecks: GuideCheck[];
  onRefresh: () => void;
  onCheckDeny: () => void;
};

function nodeStatusLabel(nodes: GuideNode[]): string {
  if (nodes.length === 0) return "未配置";
  const healthy = nodes.filter((node) => node.status === "healthy").length;
  return `${healthy}/${nodes.length} 个节点已通过检查`;
}

export function DeploymentGuide({ overview, nodes, preview, setupStatus, checkingDeny, denyNotice, denyReady, denyChecks, onRefresh, onCheckDeny }: DeploymentGuideProps) {
  const bindReady = nodes.length > 0 && nodes.every((node) => node.status === "healthy");
  const deferred = setupStatus?.globalDenySetupDeferred === true;
  const configuredMode = setupStatus?.policyMode ?? overview?.policyMode;
  const globalMode = configuredMode === "global";
  const evidenceStatus = overview?.publishEvidence?.status;
  const evidenceSyncStatus = overview?.publishEvidence?.syncStatus;
  const whitelistPublished = Boolean(overview?.publishEvidenceReady === true && overview.rules > 0 && overview.rules === overview.publishedRules && !overview.pendingPublish && bindReady);
  const denyVerified = denyReady && !deferred;
  const currentStep = !bindReady ? 1 : !whitelistPublished ? 2 : 3;

  if (!configuredMode) return null;
  if (!globalMode) return <section className="deployment-guide deployment-guide-legacy" aria-labelledby="deployment-guide-title"><div className="deployment-guide-heading"><div><p className="guide-eyebrow">DEPLOYMENT MODE</p><h2 id="deployment-guide-title">普通 RPZ 兼容模式</h2><p>当前部署为 legacy 模式，不需要执行全局 DENY 上线步骤。</p></div><button className="refresh-button" type="button" onClick={onRefresh} disabled={checkingDeny}>刷新状态</button></div><div className="guide-callout guide-callout-info"><strong>保持现有管理流程</strong><span>历史策略、发布和审计数据保持不变。DNSGuard 不会自动迁移到 global，也不会要求创建或启用 deny Zone。</span></div></section>;

  return <section className="deployment-guide" aria-labelledby="deployment-guide-title">
    <div className="deployment-guide-heading">
      <div><p className="guide-eyebrow">FIRST DEPLOYMENT</p><h2 id="deployment-guide-title">首次上线引导</h2><p>按顺序完成连接 BIND、审核发布白名单，最后由 BIND 管理员启用并验证全局 DENY。</p></div>
      <button className="refresh-button" type="button" onClick={onRefresh} disabled={checkingDeny}>刷新引导状态</button>
    </div>
    <div className="deployment-steps" role="list">
      <article className={currentStep === 1 ? "current" : bindReady ? "done" : "pending"} role="listitem"><b>1</b><div><strong>连接 BIND</strong><span>{bindReady ? nodeStatusLabel(nodes) : "等待 Primary / Secondary 通过检查"}</span></div></article>
      <article className={currentStep === 2 ? "current" : whitelistPublished ? "done" : "pending"} role="listitem"><b>2</b><div><strong>发布白名单</strong><span>{whitelistPublished ? "已有持久化发布证据且当前节点已健康" : evidenceStatus === "running" ? "发布任务正在运行" : evidenceStatus === "failed" ? "最近发布失败，禁止进入下一步" : evidenceSyncStatus === "pending_verification" ? "等待 Secondary 验证" : evidenceSyncStatus === "reconcile_required" ? "需要人工核对" : preview?.pending ? `${preview.changes} 项待发布变更` : "缺少完整发布/同步证据，不能判定完成"}</span></div></article>
      <article className={denyVerified ? "done" : currentStep === 3 ? "current" : "pending"} role="listitem"><b>3</b><div><strong>启用并验证全局 DENY</strong><span>{denyVerified ? "只读检查全部通过" : deferred ? "等待 BIND 管理员启用 deny Zone" : "只读验证状态：未验证"}</span></div></article>
    </div>
    <div className="deployment-guide-body">
      {currentStep === 1 && <div className="guide-callout"><strong>BIND 连接未完成</strong><span>请先确认 DNS 节点可达、RPZ Zone 和 TSIG 检查通过。当前状态：{nodeStatusLabel(nodes)}。</span></div>}
      {currentStep === 2 && <div className="guide-callout"><strong>白名单尚未完成发布</strong><span>导入的白名单只是 <code>draft</code>。请在 RPZ 规则和发布预览中审核，确认发布成功且所有 Secondary 同步后，才能启用全局 DENY。</span><button type="button" onClick={() => document.getElementById("rpz-rules")?.scrollIntoView({ behavior: "smooth", block: "start" })}>查看白名单和发布预览</button></div>}
      {currentStep === 3 && <div className={`guide-callout ${denyVerified ? "guide-callout-success" : ""}`}><strong>{denyVerified ? "全局 DENY 只读检查通过" : deferred ? "白名单已同步，等待 BIND 管理员操作" : "全局 DENY 需要只读核验"}</strong><span>{denyVerified ? "Primary / Secondary、触发项和递归拒绝检查均已通过当前接口核验。此结果只代表全局 DENY 检查，不代表白名单和 A 重定向的完整业务验收；请管理员按实际域名查询确认。DNSGuard 仍不会修改 BIND。" : deferred ? `请由 BIND 管理员将 ${overview?.globalDenyZone || "deny Zone"} 加入 response-policy，然后重新加载服务并移除临时配置。DNSGuard 不会修改 BIND。` : `当前模式为${globalMode ? "全局 DENY" : "普通 RPZ"}，点击只读检查后才会显示实际结果；没有证据时保持“未验证”。`}</span><button type="button" onClick={onCheckDeny} disabled={checkingDeny}>{checkingDeny ? "检查中…" : "验证全局 DENY（只读检查）"}</button>{denyNotice && <small>{denyNotice}</small>}{denyChecks.length > 0 && <div className="guide-checks">{denyChecks.map((check) => <span className={check.status} key={check.name}><b>{check.status === "pass" ? "通过" : check.status === "fail" ? "失败" : "未执行"}</b>{check.name}：{check.detail}</span>)}</div>}</div>}
    </div>
  </section>;
}
