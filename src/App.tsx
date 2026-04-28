import { Activity, Boxes, Building2, CheckCircle2, Cloud, Code2, FileText, GitBranch, Network, RadioTower, ShieldAlert, Sparkles, TicketCheck, Timer } from "lucide-react";
import { useMemo, useState } from "react";
import { integrations, organization, threatSignals } from "./data/seed";
import { analyzePortfolio } from "./domain/impactEngine";
import type { ImpactReport, ImpactStatus, Severity } from "./domain/types";

const statusColors: Record<ImpactStatus, string> = { Impacted: "#b91c1c", "Possibly impacted": "#c2410c", "Not impacted": "#15803d", Unknown: "#6b7280", Monitoring: "#0f766e" };
const severityColors: Record<Severity, string> = { Critical: "#b91c1c", High: "#c2410c", Medium: "#a16207", Low: "#2563eb", "No Impact": "#15803d" };
const roadmap = [
  { phase: "Phase 1", title: "CVE Impact Discovery", status: "Live", icon: ShieldAlert },
  { phase: "Phase 2", title: "Vendor Incident Blast Radius", status: "Live", icon: Building2 },
  { phase: "Phase 3", title: "Open-Source Dependency Impact", status: "Live", icon: Code2 },
  { phase: "Phase 4", title: "Threat Campaign Relevance", status: "Live", icon: RadioTower },
  { phase: "Phase 5", title: "Autonomous Exposure Reasoning", status: "Preview", icon: Sparkles },
];

export function App() {
  const reports = useMemo(() => analyzePortfolio(threatSignals, organization), []);
  const [selectedId, setSelectedId] = useState(reports[0].id);
  const selected = reports.find((report) => report.id === selectedId) ?? reports[0];
  const impacted = reports.filter((report) => report.status === "Impacted");
  const meanRisk = Math.round(reports.reduce((sum, report) => sum + report.riskScore, 0) / reports.length);

  return <main className="app-shell">
    <aside className="sidebar">
      <div className="brand"><Network/><div><span>Mythos</span><h1>Discover</h1></div></div>
      <nav><a href="#dashboard"><Activity/>Command Center</a><a href="#queue"><ShieldAlert/>Impact Queue</a><a href="#graph"><GitBranch/>Exposure Graph</a><a href="#integrations"><Boxes/>Integrations</a><a href="#brief"><FileText/>Executive Brief</a></nav>
      <div className="org"><span>Organization</span><strong>{organization.name}</strong><small>{organization.industry}</small></div>
    </aside>
    <section className="workspace" id="dashboard">
      <header><div><span className="eyebrow">Exposure Truth Layer</span><h2>Are we impacted?</h2></div><button><TicketCheck/>Open workflow</button></header>
      <section className="metrics"><Metric icon={ShieldAlert} label="Confirmed impact" value={`${impacted.length}`}/><Metric icon={Timer} label="Mean decision" value="3m 42s"/><Metric icon={Cloud} label="Sources" value={`${integrations.length}`}/><Metric icon={Activity} label="Portfolio risk" value={`${meanRisk}/100`}/></section>
      <section className="grid"><section className="panel" id="queue"><h3>Live Impact Queue</h3>{reports.map((report) => <button className={`threat ${selected.id === report.id ? "selected" : ""}`} key={report.id} onClick={() => setSelectedId(report.id)}><strong>{report.threat.title}</strong><span>{report.threat.source}</span><em style={{color: statusColors[report.status]}}>{report.status} · {report.riskScore}/100 · {Math.round(report.confidence * 100)}%</em></button>)}</section><ImpactDetail report={selected}/></section>
      <section className="roadmap">{roadmap.map((item) => <article key={item.title}><item.icon/><span>{item.phase}</span><strong>{item.title}</strong><em>{item.status}</em></article>)}</section>
      <section className="bottom"><ExposureGraph report={selected}/><IntegrationsPanel/><ExecutiveBrief report={selected}/></section>
    </section>
  </main>;
}

function Metric({ icon: Icon, label, value }: { icon: typeof ShieldAlert; label: string; value: string }) { return <article className="metric"><Icon/><span>{label}</span><strong>{value}</strong></article>; }

function ImpactDetail({ report }: { report: ImpactReport }) { return <article className="panel"><div className="split"><div><span className="eyebrow">Impact Decision</span><h3>{report.status}</h3></div><b style={{color: severityColors[report.severity]}}>{report.severity}</b></div><p>{report.executiveSummary}</p><div className="decision"><strong>{report.riskScore}/100</strong><strong>{Math.round(report.confidence * 100)}%</strong><strong>{report.affectedAssets.length + report.affectedVendors.length + report.affectedPackages.length} items</strong></div><h4>Recommended action</h4><p>{report.recommendedAction}</p><h4>Evidence</h4><ul>{report.evidence.map((item) => <li key={item.label}><CheckCircle2/><span><b>{item.label}</b>{item.detail}</span></li>)}</ul>{report.ticket ? <div className="ticket"><TicketCheck/>{report.ticket.id} · {report.ticket.owner} · {report.ticket.status}</div> : null}</article>; }

function ExposureGraph({ report }: { report: ImpactReport }) { const nodes = [{ label: report.threat.title, type: "Threat" }, ...report.affectedAssets.map((asset) => ({ label: asset.hostname, type: asset.exposure })), ...report.affectedVendors.map((vendor) => ({ label: vendor.name, type: "Vendor" })), ...report.affectedPackages.map((pkg) => ({ label: pkg.repository, type: pkg.ecosystem }))]; return <article className="panel" id="graph"><h3>Exposure graph</h3>{nodes.map((node) => <div className="node" key={`${node.type}-${node.label}`}><small>{node.type}</small><strong>{node.label}</strong></div>)}</article>; }
function IntegrationsPanel() { return <article className="panel" id="integrations"><h3>Integration health</h3>{integrations.map((item) => <div className="integration" key={item.name}><b>{item.name}</b><span>{item.category} · {item.status} · {item.lastSync}</span></div>)}</article>; }
function ExecutiveBrief({ report }: { report: ImpactReport }) { return <article className="panel" id="brief"><h3>Executive brief</h3><p>{report.executiveSummary}</p><p>Decision: <b>{report.status}</b>. Confidence: <b>{Math.round(report.confidence * 100)}%</b>.</p><p>{report.missingData.length ? `Open validation: ${report.missingData.join(" ")}` : "No blocking data gaps are present in connected sources."}</p></article>; }
