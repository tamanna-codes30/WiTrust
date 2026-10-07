import type { ReactNode, SVGProps } from "react";

export type IconName =
  | "dashboard" | "wifi" | "devices" | "report" | "compare" | "map"
  | "settings" | "refresh" | "search" | "shield" | "check" | "alert"
  | "arrow" | "chevron" | "signal" | "lock" | "menu" | "download"
  | "clock" | "scan" | "spark" | "close" | "network" | "info";

const paths: Record<IconName, ReactNode> = {
  dashboard: <><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></>,
  wifi: <><path d="M5 9.5a11 11 0 0 1 14 0"/><path d="M8 13a6.5 6.5 0 0 1 8 0"/><path d="M11 16.5a2 2 0 0 1 2 0"/><path d="M12 20h.01"/></>,
  devices: <><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8M12 17v4"/></>,
  report: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h8"/></>,
  compare: <><path d="M4 19V5M4 19h17"/><path d="m7 14 4-4 3 2 5-6"/><path d="M16 6h3v3"/></>,
  map: <><path d="m3 6 6-3 6 3 6-3v15l-6 3-6-3-6 3z"/><path d="M9 3v15M15 6v15"/></>,
  settings: <><circle cx="12" cy="12" r="3"/><path d="m19.4 15 .1.1 1.4 1.1-1.4 2.4-1.7-.6a8 8 0 0 1-1.7 1l-.3 1.8h-2.8l-.3-1.8a8 8 0 0 1-1.7-1l-1.7.6-1.4-2.4L7.3 15a8 8 0 0 1 0-2l-1.4-1.1 1.4-2.4 1.7.6a8 8 0 0 1 1.7-1l.3-1.8h2.8l.3 1.8a8 8 0 0 1 1.7 1l1.7-.6 1.4 2.4-1.4 1.1a8 8 0 0 1-.1 2z" transform="translate(-1 -1) scale(1.08)"/></>,
  refresh: <><path d="M20 7v5h-5"/><path d="M4 17v-5h5"/><path d="M5.6 9a7 7 0 0 1 11.6-2L20 12M4 12l2.8 5a7 7 0 0 0 11.6-2"/></>,
  search: <><circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 4.5 4.5"/></>,
  shield: <><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11z"/><path d="m9 12 2 2 4-4"/></>,
  check: <path d="m5 12 4 4L19 6"/>,
  alert: <><path d="M10.3 3.9 2.6 17.2A2 2 0 0 0 4.3 20h15.4a2 2 0 0 0 1.7-2.8L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/></>,
  arrow: <><path d="M5 12h14M13 6l6 6-6 6"/></>,
  chevron: <path d="m9 18 6-6-6-6"/>,
  signal: <><path d="M3 20h18"/><path d="M6 16v-3M10 16V9M14 16V5M18 16v-7"/></>,
  lock: <><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/></>,
  menu: <><path d="M4 6h16M4 12h16M4 18h16"/></>,
  download: <><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5M12 15V3"/></>,
  clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
  scan: <><path d="M4 8V5a1 1 0 0 1 1-1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3M8 20H5a1 1 0 0 1-1-1v-3M7 12h10"/></>,
  spark: <><path d="m12 3 1.9 5.8L20 11l-6.1 2.2L12 19l-1.9-5.8L4 11l6.1-2.2L12 3z"/><path d="m19 14 1 2.5 2 1-2 1-1 2.5-1-2.5-2-1 2-1 1-2.5z"/></>,
  close: <><path d="m18 6-12 12M6 6l12 12"/></>,
  network: <><circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="m11 7-5 10m7-10 5 10M7 19h10"/></>,
  info: <><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></>,
};

export function Icon({ name, ...props }: SVGProps<SVGSVGElement> & { name: IconName }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>
      {paths[name]}
    </svg>
  );
}
