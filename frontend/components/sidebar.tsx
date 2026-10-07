import { Icon, type IconName } from "@/components/icons";

export type ViewName = "dashboard" | "wifi" | "devices" | "reports" | "compare" | "map" | "settings";

const navItems: { id: ViewName; label: string; icon: IconName; group: string }[] = [
  { id: "dashboard", label: "Dashboard", icon: "dashboard", group: "Workspace" },
  { id: "wifi", label: "Wi-Fi networks", icon: "wifi", group: "Workspace" },
  { id: "devices", label: "Local devices", icon: "devices", group: "Workspace" },
  { id: "reports", label: "Security reports", icon: "report", group: "Insights" },
  { id: "compare", label: "Compare network", icon: "compare", group: "Insights" },
  { id: "map", label: "Network map", icon: "map", group: "Insights" },
  { id: "settings", label: "Settings", icon: "settings", group: "System" },
];

export function Sidebar({ active, onNavigate, open, onClose, nmapAvailable }: {
  active: ViewName;
  onNavigate: (view: ViewName) => void;
  open: boolean;
  onClose: () => void;
  nmapAvailable: boolean;
}) {
  let group = "";
  return <>
    <button className={`sidebar-backdrop ${open ? "is-visible" : ""}`} onClick={onClose} aria-label="Close navigation" tabIndex={open ? 0 : -1} />
    <aside className={`sidebar ${open ? "sidebar-open" : ""}`} aria-label="Main navigation">
      <div className="brand-lockup">
        <span className="brand-mark"><Icon name="shield" /></span>
        <span><strong>WiTrust</strong><small>WI-FI SECURITY ASSISTANT</small></span>
      </div>
      <div className="sidebar-network"><span className="live-dot" /> LOCAL NETWORK <span className="sidebar-version">v1.0</span></div>
      <nav className="sidebar-nav">
        {navItems.map((item) => {
          const showGroup = group !== item.group;
          group = item.group;
          return <div key={item.id}>
            {showGroup && <p className="nav-group-label">{item.group}</p>}
            <button className={`nav-item ${active === item.id ? "nav-item-active" : ""}`} onClick={() => { onNavigate(item.id); onClose(); }} aria-current={active === item.id ? "page" : undefined}>
              <Icon name={item.icon} /><span>{item.label}</span><Icon className="nav-chevron" name="chevron" />
            </button>
          </div>;
        })}
      </nav>
      <div className="sidebar-footer">
        <div className="sidebar-art" aria-hidden="true"><div className="art-shield"><Icon name="wifi" /></div><div className="art-glow" /></div>
        <strong>Safer networks.<br />Stronger connections.</strong>
        <div className="footer-meter"><i /><i /><i /></div>
        <p><span className={`nmap-dot ${nmapAvailable ? "online" : ""}`} /> Nmap {nmapAvailable ? "available" : "optional"}</p>
      </div>
    </aside>
  </>;
}
