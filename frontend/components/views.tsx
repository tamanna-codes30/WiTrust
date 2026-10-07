import { useEffect, useMemo, useState, type CSSProperties, type ReactNode } from "react";
import { Icon } from "@/components/icons";
import { Button, EmptyState, Panel, RiskBadge, Spinner } from "@/components/ui";
import type {
  ApiHealth,
  ComparisonResponse,
  DeviceHistoryEntry,
  DeviceRecord,
  EvilTwinFinding,
  NetworkAssessment,
  RiskLevel,
  WiFiNetwork,
} from "@/lib/types";

const riskColor: Record<RiskLevel, string> = {
  LOW: "#39e0a0",
  MEDIUM: "#ffbc59",
  HIGH: "#ff647b",
  CRITICAL: "#fa3e65",
};

function displaySsid(network?: WiFiNetwork | null) {
  return network?.ssid || (network?.ssid_redacted ? "Name withheld by macOS" : "Unnamed network");
}

function signalRing(signal?: string) {
  if (!signal) return 3;
  const value = Number.parseFloat(signal);
  if (!Number.isFinite(value)) return 3;
  if (signal.includes("%")) {
    if (value < 0 || value > 100) return 3;
    return value >= 70 ? 1 : value >= 35 ? 2 : 3;
  }
  if (!/dbm/i.test(signal) || value > 0 || value < -120) return 3;
  return value >= -55 ? 1 : value >= -72 ? 2 : 3;
}

export function PageHeading({ eyebrow, title, description, action }: {
  eyebrow: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return <div className="page-heading"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="page-description">{description}</p></div>{action}</div>;
}

export function MetricCard({ label, value, note, icon, tone = "blue" }: {
  label: string;
  value: string | number;
  note: string;
  icon: "wifi" | "devices" | "shield" | "signal" | "clock";
  tone?: "blue" | "green" | "amber" | "violet";
}) {
  return <div className="metric-card"><span className={`metric-icon tone-${tone}`}><Icon name={icon} /></span><div><span className="metric-label">{label}</span><strong>{value}</strong><small>{note}</small></div></div>;
}

export function RiskGauge({ assessment }: { assessment: NetworkAssessment | null }) {
  const score = assessment?.score ?? 0;
  const level = assessment?.level ?? "LOW";
  return <div className={`risk-gauge risk-gauge-${level.toLowerCase()}`}>
    <div className="gauge-ring" style={{ "--gauge-value": `${score * 3.6}deg`, "--gauge-color": riskColor[level] } as CSSProperties}>
      <div className="gauge-center"><strong>{score}</strong><span>/100</span></div>
    </div>
    <RiskBadge level={level} />
    <p>{assessment ? "Rule-based signals from the latest scan." : "Scan Wi-Fi to calculate a network score."}</p>
  </div>;
}

export function NetworkTable({ networks, assessments, findings, selectedBssid, onSelect, compact = false }: {
  networks: WiFiNetwork[];
  assessments: NetworkAssessment[];
  findings: Record<string, EvilTwinFinding>;
  selectedBssid?: string;
  onSelect: (index: number) => void;
  compact?: boolean;
}) {
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => networks.map((network, index) => ({ network, assessment: assessments[index], index }))
    .filter(({ network }) => `${network.ssid ?? ""} ${network.bssid ?? ""} ${network.authentication ?? ""}`.toLowerCase().includes(query.toLowerCase())),
  [networks, assessments, query]);

  if (!networks.length) return <EmptyState title="No Wi-Fi scan yet" detail="Scan nearby Wi-Fi to see names, security, signal, and explainable risk." />;

  return <div className="table-wrap">
    {!compact && <label className="search-field"><Icon name="search" /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search SSID, BSSID, security…" aria-label="Search networks" /></label>}
    <table className="data-table"><thead><tr><th>Network</th><th>Security</th><th>Encryption</th><th>Signal</th><th>Channel</th><th>Risk</th></tr></thead>
      <tbody>{filtered.map(({ network, assessment, index }) => {
        const selected = selectedBssid && network.bssid === selectedBssid;
        const twin = findings[String(index)];
        return <tr key={`${network.bssid ?? network.ssid ?? "wifi"}-${index}`} className={selected ? "row-selected" : ""}>
          <td><button className="table-select" onClick={() => onSelect(index)}><span className="table-wifi"><Icon name="wifi" /></span><span><strong>{displaySsid(network)}</strong>{network.connected && <small className="current-tag">CURRENT</small>}{twin && <small className="twin-tag">EVIL TWIN SIGNAL</small>}<small>{network.bssid || "BSSID unavailable"}</small></span></button></td>
          <td><span className={assessment?.security_status === "PROTECTED" ? "text-good" : assessment?.security_status === "OPEN" || assessment?.security_status === "OUTDATED" ? "text-risk" : "text-muted"}>{network.authentication || "Unknown"}</span></td>
          <td>{network.encryption || "Unknown"}</td>
          <td><Signal value={network.signal} /></td>
          <td>{network.channel || "—"}</td>
          <td>{assessment ? <RiskBadge level={assessment.level} score={assessment.score} /> : <span className="text-muted">Not assessed</span>}</td>
        </tr>;
      })}</tbody>
    </table>
    {!filtered.length && <p className="table-empty">No networks match “{query}”.</p>}
  </div>;
}

export function Signal({ value }: { value?: string }) {
  const numeric = Number.parseInt(value ?? "", 10);
  const strength = Number.isFinite(numeric) ? Math.max(0, Math.min(100, Math.round((numeric + 100) * 2))) : 0;
  return <span className="signal-meter" aria-label={value || "Signal unavailable"}><span>{value || "—"}</span><i><b style={{ width: `${strength}%` }} /></i></span>;
}

export function NetworkDetails({ network, assessment, finding }: {
  network: WiFiNetwork | null;
  assessment: NetworkAssessment | null;
  finding?: EvilTwinFinding;
}) {
  if (!network || !assessment) return <EmptyState title="Select a network" detail="Choose a row in the nearby networks table to inspect its risk assessment." />;
  return <div className="network-detail">
    <div className="detail-title-row"><div><span className="detail-icon"><Icon name="wifi" /></span><div><h3>{displaySsid(network)}</h3><p>{network.bssid || "BSSID unavailable"}</p></div></div><RiskBadge level={assessment.level} score={assessment.score} /></div>
    {finding && <div className="inline-alert"><Icon name="alert" /><span><strong>Possible evil-twin indicator</strong>{finding.reason}</span></div>}
    <div className="detail-grid">
      <Detail label="Security" value={network.authentication || "Unknown"} icon="lock" />
      <Detail label="Encryption" value={network.encryption || "Unknown"} icon="shield" />
      <Detail label="Signal strength" value={network.signal || "Unavailable"} icon="signal" />
      <Detail label="Band / channel" value={`${network.band || "Unknown"} · ${network.channel || "—"}`} icon="wifi" />
    </div>
    <div className="assessment-section"><div className="subsection-title"><h4>Why this score?</h4><span>{assessment.data_coverage_score}% evidence coverage</span></div>
      <ul className="reason-list">{assessment.reasons.map((reason, index) => <li key={`${reason}-${index}`}><span className={assessment.score ? "reason-mark reason-caution" : "reason-mark reason-ok"}><Icon name={assessment.score ? "alert" : "check"} /></span>{reason}</li>)}</ul>
    </div>
    <div className="recommendation"><Icon name="spark" /><div><strong>Recommended next step</strong><p>{assessment.recommendations[0] || "Continue to monitor this network."}</p></div></div>
    <p className="disclaimer">Prototype score—not proof that a network is malicious.</p>
  </div>;
}

function Detail({ label, value, icon }: { label: string; value: string; icon: "lock" | "shield" | "signal" | "wifi" }) {
  return <div className="detail-item"><Icon name={icon} /><div><small>{label}</small><strong>{value}</strong></div></div>;
}

export function DashboardView({ current, currentAssessment, networks, assessments, findings, devices, scannedAt, onScan, busy, onSelectNetwork, selectedNetwork }: {
  current: WiFiNetwork | null;
  currentAssessment: NetworkAssessment | null;
  networks: WiFiNetwork[];
  assessments: NetworkAssessment[];
  findings: Record<string, EvilTwinFinding>;
  devices: DeviceRecord[];
  scannedAt: string;
  onScan: () => void;
  busy: boolean;
  onSelectNetwork: (index: number) => void;
  selectedNetwork: WiFiNetwork | null;
}) {
  const high = devices.filter((device) => ["HIGH", "CRITICAL"].includes(device.risk_level)).length;
  return <>
    <PageHeading eyebrow="OVERVIEW" title="Network security at a glance" description="A clear view of your Wi-Fi environment, device trust, and risk indicators." action={<Button variant="primary" icon="scan" onClick={onScan} disabled={busy}>{busy ? "Scan in progress…" : "Scan Wi-Fi"}</Button>} />
    <div className="metrics-grid">
      <MetricCard label="Networks nearby" value={scannedAt ? networks.length : "—"} note={scannedAt ? `Last scan · ${formatTime(scannedAt)}` : "Ready for first scan"} icon="wifi" />
      <MetricCard label="Current network" value={current?.ssid || (current?.connected ? "Name unavailable" : "Not connected")} note={current?.authentication || "Scan to check connection"} icon="shield" tone="green" />
      <MetricCard label="Known devices" value={devices.length} note="From local scan history" icon="devices" tone="violet" />
      <MetricCard label="Needs review" value={high} note="High or critical device indicators" icon="signal" tone={high ? "amber" : "green"} />
    </div>
    <div className="dashboard-top-grid">
      <Panel title="Current network" icon="wifi" className="current-card">
        {current ? <><div className="current-network-title"><div className="network-orb"><Icon name="wifi" /></div><div><h3>{current.ssid || "Network name unavailable"}</h3><p>{current.bssid || "BSSID unavailable"}</p></div><span className={`connection-pill ${current.connected ? "connected" : ""}`}><i />{current.connected ? "CONNECTED" : "AVAILABLE"}</span></div>
          <div className="current-facts"><div><small>Security</small><strong>{current.authentication || "Unknown"}</strong></div><div><small>Encryption</small><strong>{current.encryption || "Unknown"}</strong></div><div><small>Signal</small><strong>{current.signal || "Unknown"}</strong></div><div><small>Band</small><strong>{current.band || "Unknown"}</strong></div><div><small>Channel</small><strong>{current.channel || "—"}</strong></div><div><small>Status</small><strong className="text-good">{currentAssessment?.security_status || "Not assessed"}</strong></div></div>
        </> : <EmptyState title="No Wi-Fi connection detected" detail="Connect to a Wi-Fi network, then scan to assess its reported security." action={<Button icon="scan" onClick={onScan} disabled={busy}>Scan Wi-Fi</Button>} />}
      </Panel>
      <Panel title="Network risk" icon="signal" className="gauge-panel"><RiskGauge assessment={currentAssessment} /></Panel>
      <Panel title="WiTrust assessment" icon="shield" className="assessment-card">{currentAssessment ? <AssessmentChecklist assessment={currentAssessment} /> : <EmptyState title="Waiting for a scan" detail="Network safety checks will appear here." />}</Panel>
    </div>
    <div className="dashboard-bottom-grid">
      <Panel title="Nearby networks" icon="wifi" action={<span className="panel-count">{networks.length} found</span>} className="network-panel">
        <NetworkTable networks={networks.slice(0, 5)} assessments={assessments.slice(0, 5)} findings={findings} selectedBssid={selectedNetwork?.bssid} onSelect={onSelectNetwork} compact />
      </Panel>
      <Panel title="Selected network" icon="info" className="selected-panel"><NetworkDetails network={selectedNetwork} assessment={selectedNetwork ? assessments[networks.indexOf(selectedNetwork)] ?? null : null} finding={selectedNetwork ? findings[String(networks.indexOf(selectedNetwork))] : undefined} /></Panel>
    </div>
  </>;
}

function AssessmentChecklist({ assessment }: { assessment: NetworkAssessment }) {
  const items = [
    [assessment.security_status === "PROTECTED", assessment.security_status === "PROTECTED" ? "Protected Wi-Fi security reported" : "Security requires review"],
    [assessment.security_status === "PROTECTED" || assessment.security_status === "OUTDATED", assessment.security_status === "OPEN" ? "Open network reported" : assessment.security_status === "UNKNOWN" ? "Open-access status unknown" : "Encrypted access reported"],
    [assessment.observations.length > 0, assessment.observations.length ? "Risk observations reviewed" : "No additional risk observations"],
    [assessment.data_quality !== "LOW", `Evidence coverage · ${assessment.data_coverage_score}%`],
  ] as const;
  return <ul className="checklist">{items.map(([okay, text]) => <li key={text}><span className={okay ? "check-icon" : "warn-icon"}><Icon name={okay ? "check" : "alert"} /></span>{text}</li>)}</ul>;
}

export function WifiView({ networks, assessments, findings, selectedIndex, onSelect, onScan, busy }: {
  networks: WiFiNetwork[];
  assessments: NetworkAssessment[];
  findings: Record<string, EvilTwinFinding>;
  selectedIndex: number;
  onSelect: (index: number) => void;
  onScan: () => void;
  busy: boolean;
}) {
  const selected = networks[selectedIndex] ?? null;
  return <><PageHeading eyebrow="WI-FI INTELLIGENCE" title="Nearby Wi-Fi networks" description="Inspect discovered access points, reported security, and explainable risk." action={<Button variant="primary" icon="refresh" onClick={onScan} disabled={busy}>{busy ? "Scanning…" : "Scan again"}</Button>} />
    <Panel title="Scan results" icon="wifi" action={<span className="panel-count">{networks.length} network{networks.length === 1 ? "" : "s"}</span>}><NetworkTable networks={networks} assessments={assessments} findings={findings} selectedBssid={selected?.bssid} onSelect={onSelect} /></Panel>
    <Panel title="Network assessment" icon="shield" className="screen-detail"><NetworkDetails network={selected} assessment={selected ? assessments[selectedIndex] ?? null : null} finding={findings[String(selectedIndex)]} /></Panel>
  </>;
}

export function DevicesView({ devices, selectedId, onSelect, history, onScan, onOpenNmap, busy, nmapAvailable, scannedAt }: {
  devices: DeviceRecord[];
  selectedId: string;
  onSelect: (device: DeviceRecord) => void;
  history: DeviceHistoryEntry[];
  onScan: () => void;
  onOpenNmap: () => void;
  busy: boolean;
  nmapAvailable: boolean;
  scannedAt: string;
}) {
  const selected = devices.find((device) => device.device_id === selectedId) ?? devices[0] ?? null;
  return <><PageHeading eyebrow="DEVICE INTELLIGENCE" title="Local devices" description="Build a local inventory and inspect trust changes across observations." action={<div className="heading-actions"><Button icon="refresh" onClick={onScan} disabled={busy}>{busy ? "Scan in progress…" : "Refresh ARP"}</Button><Button variant="primary" icon="scan" onClick={onOpenNmap} disabled={!nmapAvailable || busy}>{nmapAvailable ? "Nmap service scan" : "Nmap unavailable"}</Button></div>} />
    <div className="metrics-grid device-metrics"><MetricCard label="Known devices" value={devices.length} note={scannedAt ? `Last scan · ${formatTime(scannedAt)}` : "From local scan history"} icon="devices" tone="violet"/><MetricCard label="Low risk" value={devices.filter((d) => d.risk_level === "LOW").length} note="No major indicators in scan data" icon="shield" tone="green"/><MetricCard label="Needs review" value={devices.filter((d) => d.risk_level === "MEDIUM" || d.risk_level === "HIGH" || d.risk_level === "CRITICAL").length} note="Review reasons before acting" icon="signal" tone="amber"/><MetricCard label="History tracked" value={devices.filter((d) => d.observation_count > 1).length} note="Seen in more than one scan" icon="clock"/></div>
    <div className="device-layout"><Panel title="Device inventory" icon="devices" className="device-table-panel">{devices.length ? <div className="table-wrap"><table className="data-table device-table"><thead><tr><th>Device</th><th>IP address</th><th>Vendor</th><th>Trust</th><th>Risk</th><th>Last seen</th></tr></thead><tbody>{devices.map((device) => <tr key={device.device_id} className={selected?.device_id === device.device_id ? "row-selected" : ""}><td><button className="table-select" onClick={() => onSelect(device)}><span className="device-avatar"><Icon name="devices" /></span><span><strong>{device.hostname || device.mac || "Unknown device"}</strong><small>{device.mac || device.device_id}</small></span></button></td><td>{device.ip || "—"}</td><td>{device.vendor || "Unavailable"}</td><td><strong className="trust-value">{device.trust_score}</strong><small className="out-of">/100</small></td><td><RiskBadge level={device.risk_level} score={device.risk_score}/></td><td>{formatTime(device.last_seen)}</td></tr>)}</tbody></table></div> : <EmptyState title="No devices observed yet" detail="ARP discovery only sees devices in your system cache. Use Nmap on an authorized local subnet to discover hosts." action={<Button icon="refresh" onClick={onScan} disabled={busy}>{busy ? "Scanning…" : "Scan local devices"}</Button>} />}</Panel>
      {selected && <Panel title="Device trust profile" icon="shield" className="device-profile"><DeviceDetails device={selected} history={history}/></Panel>}
    </div>
  </>;
}

function DeviceDetails({ device, history }: { device: DeviceRecord; history: DeviceHistoryEntry[] }) {
  return <div className="device-details"><div className="device-profile-head"><div className="device-avatar large"><Icon name="devices"/></div><div><h3>{device.hostname || "Unknown device"}</h3><p>{device.ip || "IP unavailable"} · {device.mac || "MAC unavailable"}</p></div><RiskBadge level={device.risk_level}/></div>
    <div className="trust-score-row"><div><small>Trust score</small><strong>{device.trust_score}<span>/100</span></strong></div><div className="drift-chip"><Icon name="arrow"/><span>Drift<strong>{device.trust_drift === null ? "First seen" : `${device.trust_drift > 0 ? "+" : ""}${device.trust_drift}`}</strong></span></div><div className="evidence-chip">{device.data_coverage_score}%<small>evidence coverage</small></div></div>
    <div className="device-facts"><div><small>Vendor</small><strong>{device.vendor || "Unavailable"}</strong></div><div><small>First observed</small><strong>{formatTime(device.first_seen)}</strong></div><div><small>Observations</small><strong>{device.observation_count}</strong></div><div><small>SSID context</small><strong>{device.ssid || "Unavailable"}</strong></div></div>
    <div className="profile-section"><div className="subsection-title"><h4>Why this device?</h4><span>{device.risk_score}/100 risk</span></div>{device.reasons.length ? <ul className="reason-list">{device.reasons.map((reason, index) => <li key={`${reason.type}-${index}`}><span className={`weight-pill ${reason.weight < 0 ? "weight-positive" : ""}`}>{reason.weight > 0 ? "+" : ""}{reason.weight}</span>{reason.description}</li>)}</ul> : <p className="muted-copy">No risk indicators from available data.</p>}</div>
    <div className="profile-section"><div className="subsection-title"><h4>Detected services</h4><span>{device.ports_scanned ? "Latest Nmap scan" : "Last service scan"}</span></div>{device.service_details.length ? <div className="service-chips">{device.service_details.map((service) => <span key={service}>{service}</span>)}</div> : <p className="muted-copy">No service scan data. Run the authorized Nmap service profile to inspect open TCP ports.</p>}</div>
    <div className="profile-section"><div className="subsection-title"><h4>Observation history</h4><span>{history.length} recent</span></div>{history.length ? <ol className="history-list">{history.slice(0, 5).map((item, index) => <li key={`${item.observed_at}-${index}`}><span className="history-dot"/><div><strong>{formatTime(item.observed_at)}</strong><small>{item.ip || "IP unavailable"} · trust {item.trust_score} · {item.open_ports.length} port(s)</small></div></li>)}</ol> : <p className="muted-copy">History appears after repeated scans.</p>}</div>
    <div className="recommendation compact-recommendation"><Icon name="spark"/><p>{device.risk_level === "HIGH" || device.risk_level === "CRITICAL" ? "Investigate and verify authorization. Consider isolation only if the device is confirmed unauthorized." : device.risk_level === "MEDIUM" ? "Verify unfamiliar devices and review after a service scan." : "No major device-level indicators in the available observations."}</p></div>
    <p className="disclaimer">Evidence coverage is field completeness, not confidence or probability. Heuristic score—not proof that a device is malicious.</p></div>;
}

export function NmapDialog({ open, target, onClose, onScan, busy, error, nmapAvailable }: {
  open: boolean;
  target: string;
  onClose: () => void;
  onScan: (target: string, profile: "discovery" | "common_tcp") => void;
  busy: boolean;
  error: string;
  nmapAvailable: boolean;
}) {
  const [value, setValue] = useState(target);
  const [profile, setProfile] = useState<"discovery" | "common_tcp">("common_tcp");
  const [authorized, setAuthorized] = useState(false);
  useEffect(() => { if (open) setValue(target); }, [open, target]);
  if (!open) return null;
  return <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><section className="modal-card" role="dialog" aria-modal="true" aria-labelledby="nmap-title" onKeyDown={(event) => { if (event.key === "Escape" && !busy) onClose(); }}>
    <button className="modal-close" aria-label="Close" onClick={onClose}><Icon name="close"/></button><span className="modal-icon"><Icon name="scan"/></span><p className="eyebrow">AUTHORIZED DISCOVERY</p><h2 id="nmap-title">Nmap service assessment</h2><p className="page-description">Scan a private IPv4 subnet you own or have permission to assess. WiTrust limits targets to 256 addresses.</p>
    {!nmapAvailable && <div className="inline-alert"><Icon name="alert"/><span>Nmap is not installed or could not be found on this machine.</span></div>}
    <label className="form-label" htmlFor="nmap-target">Private subnet (CIDR)<input id="nmap-target" value={value} onChange={(event) => setValue(event.target.value)} placeholder="For example, 192.168.1.0/24" autoFocus /></label>
    <label className="form-label" htmlFor="nmap-profile">Scan profile<select id="nmap-profile" value={profile} onChange={(event) => setProfile(event.target.value as typeof profile)}><option value="common_tcp">Common TCP ports + light service detection</option><option value="discovery">Host discovery only (no port scan)</option></select></label>
    <p className="form-hint">No UDP scanning, OS fingerprinting, vulnerability scripts, or exploitation.</p>
    <label className="authorization-check"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)}/><span>I own this subnet or have explicit permission to scan it.</span></label>
    {error && <div className="inline-alert error-alert" role="alert"><Icon name="alert"/>{error}</div>}
    <div className="modal-actions"><Button onClick={onClose} disabled={busy}>Cancel</Button><Button variant="primary" icon="scan" disabled={!nmapAvailable || !authorized || !value.trim() || busy} onClick={() => onScan(value.trim(), profile)}>{busy ? "Scanning safely…" : "Start assessment"}</Button></div>
  </section></div>;
}

export function CompareView({ data, busy, onCompare }: { data: ComparisonResponse | null; busy: boolean; onCompare: () => void }) {
  return <><PageHeading eyebrow="NETWORK COMPARISON" title="Check your current connection" description="Compare connected-network security against nearby Wi-Fi observations." action={<Button variant="primary" icon="compare" onClick={onCompare} disabled={busy}>{busy ? "Comparing…" : "Compare now"}</Button>} />
    {!data ? <Panel title="Current vs nearby" icon="compare"><EmptyState title="No comparison yet" detail="Run a comparison to assess the connected network and summarize nearby security conditions." action={<Button variant="primary" icon="compare" onClick={onCompare} disabled={busy}>{busy ? "Comparing…" : "Compare network"}</Button>} /></Panel> : <div className="compare-layout"><Panel title="Connected network" icon="wifi"><div className="comparison-score"><RiskGauge assessment={data.result.current}/><div><h3>{data.result.current.security_status}</h3><p>Reported security classification</p><RiskBadge level={data.result.current.level} score={data.result.current.score}/></div></div></Panel><Panel title="Comparison findings" icon="compare"><ul className="comparison-list">{data.result.comparison.map((item, index) => <li key={`${item}-${index}`}><span className={item.startsWith("⚠") ? "warn-icon" : "check-icon"}><Icon name={item.startsWith("⚠") ? "alert" : "check"}/></span>{item}</li>)}</ul><p className="disclaimer">This comparison uses scan observations and rule-based heuristics; it does not verify network ownership.</p></Panel></div>}
  </>;
}

export function ReportsView({ network, assessment, onDownload }: { network: WiFiNetwork | null; assessment: NetworkAssessment | null; onDownload: () => void }) {
  return <><PageHeading eyebrow="REPORTING" title="Security report" description="Export an explainable snapshot of a selected network assessment." />
    <Panel title="Report preview" icon="report" action={<Button variant="primary" icon="download" onClick={onDownload} disabled={!network || !assessment}>Download .txt</Button>}>
      {network && assessment ? <div className="report-preview"><div className="report-cover"><span className="brand-mark"><Icon name="shield"/></span><div><p className="eyebrow">WITRUST · NETWORK ASSESSMENT</p><h2>{displaySsid(network)}</h2><p>{network.bssid || "BSSID unavailable"}</p></div><RiskBadge level={assessment.level} score={assessment.score}/></div><div className="report-grid"><div><small>Authentication</small><strong>{network.authentication || "Unknown"}</strong></div><div><small>Encryption</small><strong>{network.encryption || "Unknown"}</strong></div><div><small>Signal</small><strong>{network.signal || "Unknown"}</strong></div><div><small>Evidence coverage</small><strong>{assessment.data_coverage_score}%</strong></div></div><div className="profile-section"><h3>Assessment reasons</h3><ul className="reason-list">{assessment.reasons.map((reason, index) => <li key={`${reason}-${index}`}><span className="reason-mark reason-caution"><Icon name="info"/></span>{reason}</li>)}</ul></div><div className="profile-section"><h3>Recommendations</h3><ul className="reason-list">{assessment.recommendations.map((reason, index) => <li key={`${reason}-${index}`}><span className="reason-mark reason-ok"><Icon name="arrow"/></span>{reason}</li>)}</ul></div><p className="disclaimer">Rule-based prototype assessment, not proof of malicious activity.</p></div> : <EmptyState title="Select a scanned network first" detail="Run a Wi-Fi scan and choose a network to build an exportable report." />}
    </Panel>
  </>;
}

export function MapView({ networks, assessments }: { networks: WiFiNetwork[]; assessments: NetworkAssessment[] }) {
  if (!networks.length) return <><PageHeading eyebrow="VISUALIZATION" title="Relative Wi-Fi map" description="Visualize relative signal tiers and safety scores; not geographic distance or direction."/><Panel title="Nearby access points" icon="map"><EmptyState title="No networks to map" detail="Run a Wi-Fi scan to create a relative signal map."/></Panel></>;
  const points = networks.map((network, index) => {
    const ring = signalRing(network.signal);
    const angle = (index / networks.length) * Math.PI * 2 - Math.PI / 2;
    const radius = ring * 13;
    return {
      x: 50 + Math.cos(angle) * radius,
      y: 48 + Math.sin(angle) * radius,
      ring,
      network,
      assessment: assessments[index],
    };
  });
  return <>
    <PageHeading eyebrow="VISUALIZATION" title="Relative Wi-Fi map" description="Signal tiers are approximate. Position around the hub is arbitrary, not direction." />
    <Panel title="Signal and risk overview" icon="map">
      <div className="map-legend">
        <span><i className="dot-low" />Low risk</span>
        <span><i className="dot-medium" />Medium risk</span>
        <span><i className="dot-high" />High risk</span>
        <span className="map-disclaimer">Relative signal only · no geographic location</span>
      </div>
      <div className="network-map">
        <svg viewBox="0 0 100 100" role="img" aria-label="Diagram of nearby Wi-Fi networks by relative signal strength">
          <circle cx="50" cy="48" r="13" className="map-ring" />
          <circle cx="50" cy="48" r="26" className="map-ring" />
          <circle cx="50" cy="48" r="39" className="map-ring" />
          <circle cx="50" cy="48" r="4.2" className="map-hub" />
          <text x="50" y="56" textAnchor="middle" className="map-hub-label">YOU</text>
          {points.map((point, index) => {
            const level = point.assessment?.level.toLowerCase() ?? "unknown";
            return <g key={`${point.network.bssid ?? index}`}>
              <line x1="50" y1="48" x2={point.x} y2={point.y} className="map-edge" />
              <circle cx={point.x} cy={point.y} r="2.1" className={`map-point map-${level}`}>
                <title>{displaySsid(point.network)} — {point.assessment?.level ?? "Unassessed"}</title>
              </circle>
              <text x={point.x} y={point.y - 3} textAnchor="middle" className="map-node-label">
                {point.network.ssid?.slice(0, 12) || `AP ${index + 1}`}
              </text>
            </g>;
          })}
        </svg>
      </div>
      <div className="map-list">
        {points.map((point, index) => <div key={`${point.network.bssid ?? index}`}>
          <span className={`map-list-dot map-${point.assessment?.level.toLowerCase() ?? "unknown"}`} />
          <strong>{displaySsid(point.network)}</strong>
          <span>{point.network.signal || "RSSI unavailable"}</span>
          <span>{point.ring === 1 ? "Strong" : point.ring === 2 ? "Moderate" : "Weak / unknown"}</span>
          {point.assessment ? <RiskBadge level={point.assessment.level} score={point.assessment.score} /> : <span className="text-muted">Not assessed</span>}
        </div>)}
      </div>
    </Panel>
  </>;
}

export function SettingsView({ health, apiError, onRefresh }: { health: ApiHealth | null; apiError: string; onRefresh: () => void }) {
  return <><PageHeading eyebrow="SYSTEM" title="Settings & connection" description="Check the local Python adapter and optional scanning capabilities." action={<Button icon="refresh" onClick={onRefresh}>Refresh status</Button>}/><div className="settings-grid"><Panel title="Backend connection" icon="network"><div className="setting-row"><div><strong>WiTrust local API</strong><p>Loopback adapter for existing Python scanner and risk modules</p></div><span className={`status-pill ${health ? "status-online" : "status-offline"}`}><i/>{health ? "Connected" : "Offline"}</span></div><div className="setting-row"><div><strong>Nmap</strong><p>Optional host and common TCP service discovery</p></div><span className={`status-pill ${health?.nmap_available ? "status-online" : "status-neutral"}`}><i/>{health ? health.nmap_available ? "Available" : "Not installed" : "Unknown"}</span></div>{apiError && <div className="inline-alert error-alert" role="alert"><Icon name="alert"/>{apiError}</div>}<div className="api-endpoint"><small>Web app proxy</small><code>Next.js /api → Python 127.0.0.1:8765</code></div></Panel><Panel title="Privacy & safety" icon="shield"><ul className="privacy-list"><li><Icon name="lock"/><span><strong>Local only</strong><small>Python API binds to loopback; no cloud service is used.</small></span></li><li><Icon name="check"/><span><strong>Authorized scans</strong><small>Nmap requires an explicit confirmation and a bounded private subnet.</small></span></li><li><Icon name="info"/><span><strong>Explainable scores</strong><small>Risk is heuristic, transparent, and not proof of compromise.</small></span></li></ul></Panel></div></>;
}

export function formatTime(value?: string) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", day: "2-digit", month: "short" }).format(date);
}
