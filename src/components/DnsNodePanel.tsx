import type { FormEvent } from "react";

export type DnsNode = { id: string; name: string; role: string; address: string; status: string; rpzVersion: string; lastSync: string; lastChecked?: string };

type DnsNodePanelProps = {
  nodes: DnsNode[];
  nodeDrafts: Record<string, string>;
  editingNodeId: string | null;
  showNodeForm: boolean;
  nodeName: string;
  nodeRole: string;
  nodeAddress: string;
  busy: boolean;
  onToggleForm: () => void;
  onNodeNameChange: (value: string) => void;
  onNodeRoleChange: (value: string) => void;
  onNodeAddressChange: (value: string) => void;
  onAddNode: (event: FormEvent<HTMLFormElement>) => void;
  onDraftChange: (id: string, value: string) => void;
  onEdit: (id: string) => void;
  onSave: (node: DnsNode) => void;
  onCancel: (node: DnsNode) => void;
  onRemove: (node: DnsNode) => void;
};

function nodeRoleLabel(role: string): string {
  return role.includes("主") && !role.includes("辅") ? "主节点" : "辅节点";
}

function nodeIsPrimary(node: DnsNode): boolean {
  return node.id === "primary-1" || node.role.includes("主");
}

export function DnsNodePanel({ nodes, nodeDrafts, editingNodeId, showNodeForm, nodeName, nodeRole, nodeAddress, busy, onToggleForm, onNodeNameChange, onNodeRoleChange, onNodeAddressChange, onAddNode, onDraftChange, onEdit, onSave, onCancel, onRemove }: DnsNodePanelProps) {
  return <div className="dns-panel dns-panel-wide"><div className="panel-heading"><div><h2>DNS 节点</h2><span>LIVE DIG / SOA PROBE · 共 {nodes.length} 个节点</span></div><button className="table-action node-add" disabled={busy} onClick={onToggleForm}>{showNodeForm ? "取消添加" : "增加节点"}</button></div>{showNodeForm && <form className="node-create-form" onSubmit={onAddNode}><label>节点名称<input value={nodeName} onChange={(event) => onNodeNameChange(event.target.value)} placeholder="例如 DNS-SECONDARY-3" required /></label><label>角色<select value={nodeRole} onChange={(event) => onNodeRoleChange(event.target.value)}><option value="主节点">主节点</option><option value="辅节点">辅节点</option></select></label><label>地址<input value={nodeAddress} onChange={(event) => onNodeAddressChange(event.target.value)} placeholder="例如 192.168.10.13:53" required /></label><button disabled={busy}>{busy ? "保存中…" : "保存节点"}</button></form>}<div className="table-wrap"><table><thead><tr><th>名称</th><th>角色</th><th>地址配置</th><th>状态</th><th>RPZ 版本</th><th>最近检测</th><th /></tr></thead><tbody>{nodes.map((node) => { const editing = editingNodeId === node.id; const primary = nodeIsPrimary(node); return <tr key={node.id}><td>{node.name}</td><td>{nodeRoleLabel(node.role)}</td><td><input className="node-address" readOnly={!editing} value={nodeDrafts[node.id] ?? node.address} onChange={(event) => onDraftChange(node.id, event.target.value)} /></td><td><i className={`status-dot ${node.status === "healthy" ? "ok" : "warn"}`} />{node.status === "healthy" ? "正常" : node.status === "degraded" ? "版本不一致" : "不可达"}</td><td className="mono">{node.rpzVersion}</td><td>{node.lastChecked || node.lastSync}</td><td className="node-actions">{editing ? <><button className="table-action node-save" disabled={busy} onClick={() => onSave(node)}>保存</button><button className="table-action node-cancel" disabled={busy} onClick={() => onCancel(node)}>取消</button></> : <button className="table-action node-edit" disabled={busy} onClick={() => onEdit(node.id)}>编辑</button>}<button className="table-action node-delete" disabled={busy || nodes.length <= 1 || primary} title={primary ? "主节点不能直接删除" : "删除节点"} onClick={() => onRemove(node)}>删除</button></td></tr>; })}</tbody></table></div></div>;
}
