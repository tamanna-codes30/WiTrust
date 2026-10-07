"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Icon } from "@/components/icons";
import { Sidebar, type ViewName } from "@/components/sidebar";
import { Button } from "@/components/ui";
import {
  CompareView,
  DashboardView,
  DevicesView,
  MapView,
  NmapDialog,
  ReportsView,
  SettingsView,
  WifiView,
} from "@/components/views";
import { api, WiTrustApiError } from "@/lib/api";
import type {
  ApiHealth,
  ComparisonResponse,
  DeviceHistoryEntry,
  DeviceRecord,
  EvilTwinFinding,
  NetworkAssessment,
  WiFiNetwork,
  WifiScanResponse,
} from "@/lib/types";

const navTitles: Record<ViewName, { title: string; subtitle: string }> = {
  dashboard: { title: "Dashboard", subtitle: "Your local network overview" },
  wifi: { title: "Wi-Fi intelligence", subtitle: "Nearby networks and risk signals" },
  devices: { title: "Device trust", subtitle: "Inventory, behavior, and trust drift" },
  reports: { title: "Security reports", subtitle: "Explainable assessment snapshots" },
  compare: { title: "Network comparison", subtitle: "Your connection versus nearby Wi-Fi" },
  map: { title: "Network map", subtitle: "Relative signal tiers and risk" },
  settings: { title: "Settings", subtitle: "Local services and privacy" },
};

export default function HomePage() {
  const [view, setView] = useState<ViewName>("dashboard");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [health, setHealth] = useState<ApiHealth | null>(null);
  const [apiError, setApiError] = useState("");
  const [actionError, setActionError] = useState("");
  const [toast, setToast] = useState("");
  const [current, setCurrent] = useState<WiFiNetwork | null>(null);
  const [currentAssessment, setCurrentAssessment] = useState<NetworkAssessment | null>(null);
  const [networks, setNetworks] = useState<WiFiNetwork[]>([]);
  const [assessments, setAssessments] = useState<NetworkAssessment[]>([]);
  const [findings, setFindings] = useState<Record<string, EvilTwinFinding>>({});
  const [scannedAt, setScannedAt] = useState("");
  const [selectedNetworkIndex, setSelectedNetworkIndex] = useState(0);
  const [devices, setDevices] = useState<DeviceRecord[]>([]);
  const [selectedDeviceId, setSelectedDeviceId] = useState("");
  const [deviceHistory, setDeviceHistory] = useState<DeviceHistoryEntry[]>([]);
  const [historyRefresh, setHistoryRefresh] = useState(0);
  const [deviceScannedAt, setDeviceScannedAt] = useState("");
  const [comparison, setComparison] = useState<ComparisonResponse | null>(null);
  const [wifiBusy, setWifiBusy] = useState(false);
  const [deviceBusy, setDeviceBusy] = useState(false);
  const [compareBusy, setCompareBusy] = useState(false);
  const [nmapBusy, setNmapBusy] = useState(false);
  const [nmapOpen, setNmapOpen] = useState(false);
  const [nmapTarget, setNmapTarget] = useState("");
  const [nmapError, setNmapError] = useState("");
  const toastTimer = useRef<number | null>(null);
  const scanLock = useRef(false);
  const scanBusy = wifiBusy || deviceBusy || compareBusy || nmapBusy;

  const selectedNetwork = networks[selectedNetworkIndex] ?? null;
  const selectedAssessment = assessments[selectedNetworkIndex] ?? null;
  const selectedFinding = findings[String(selectedNetworkIndex)];
  const selectedDevice = devices.find((device) => device.device_id === selectedDeviceId) ?? devices[0] ?? null;

  const showError = useCallback((error: unknown) => {
    const message = error instanceof Error ? error.message : "The request failed unexpectedly.";
    setActionError(message);
    setToast("");
  }, []);

  const showToast = useCallback((message: string) => {
    if (toastTimer.current !== null) window.clearTimeout(toastTimer.current);
    setToast(message);
    toastTimer.current = window.setTimeout(() => {
      setToast("");
      toastTimer.current = null;
    }, 4200);
  }, []);

  useEffect(() => () => {
    if (toastTimer.current !== null) window.clearTimeout(toastTimer.current);
  }, []);

  const refreshConnection = useCallback(async () => {
    try {
      const result = await api.health();
      setHealth(result);
      setApiError("");
    } catch (error) {
      setHealth(null);
      setApiError(error instanceof Error ? error.message : "Could not reach the local WiTrust API.");
    }
  }, []);

  useEffect(() => {
    let active = true;
    api.health().then((result) => {
      if (active) { setHealth(result); setApiError(""); }
    }).catch((error: unknown) => {
      if (active) setApiError(error instanceof Error ? error.message : "Could not reach the local WiTrust API.");
    });
    api.currentNetwork().then(({ network }) => {
      if (active) setCurrent(network?.connected ? network as WiFiNetwork : null);
    }).catch((error: unknown) => {
      if (active) setActionError(error instanceof Error ? error.message : "Could not read current Wi-Fi status.");
    });
    api.devices().then(({ devices: savedDevices }) => {
      if (active) setDevices(savedDevices);
    }).catch((error: unknown) => {
      if (active) setActionError(error instanceof Error ? error.message : "Could not load local device history.");
    });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (!selectedDevice) { setDeviceHistory([]); return; }
    let active = true;
    setDeviceHistory([]);
    api.deviceHistory(selectedDevice.device_id).then(({ history }) => {
      if (active) setDeviceHistory(history);
    }).catch((error: unknown) => {
      if (active) {
        setDeviceHistory([]);
        setActionError(error instanceof Error ? error.message : "Could not load device observation history.");
      }
    });
    return () => { active = false; };
  }, [selectedDevice?.device_id, historyRefresh]);

  const applyWifiResult = (result: WifiScanResponse) => {
    setNetworks(result.networks);
    setAssessments(result.assessments);
    setFindings(result.findings);
    const connectedNetwork = result.current_network?.connected ? result.current_network : null;
    setCurrent(connectedNetwork);
    setCurrentAssessment(connectedNetwork ? result.current_assessment : null);
    setScannedAt(result.scanned_at);
    setSelectedNetworkIndex(0);
    if (result.warning) setActionError(result.warning);
    else if (result.current_error) setActionError(`Nearby scan finished; current connection details are unavailable: ${result.current_error}`);
  };

  const scanWifi = async () => {
    if (scanLock.current) return;
    scanLock.current = true;
    setWifiBusy(true);
    setActionError("");
    try {
      const result = await api.scanWifi();
      applyWifiResult(result);
      if (result.warning || result.current_error) {
        if (toastTimer.current !== null) window.clearTimeout(toastTimer.current);
        toastTimer.current = null;
        setToast("");
      }
      else showToast(`${result.networks.length} nearby network${result.networks.length === 1 ? "" : "s"} scanned.`);
    } catch (error) { showError(error); }
    finally { scanLock.current = false; setWifiBusy(false); }
  };

  const scanDevices = async () => {
    if (scanLock.current) return;
    scanLock.current = true;
    setDeviceBusy(true);
    setActionError("");
    try {
      const result = await api.scanDevices();
      setDevices(result.devices);
      setSelectedDeviceId(result.devices[0]?.device_id ?? "");
      setDeviceScannedAt(result.scanned_at);
      setHistoryRefresh((revision) => revision + 1);
      showToast(`${result.observed_count} device${result.observed_count === 1 ? "" : "s"} observed in the local ARP cache.`);
    } catch (error) { showError(error); }
    finally { scanLock.current = false; setDeviceBusy(false); }
  };

  const openNmap = async () => {
    setNmapError("");
    setActionError("");
    setNmapOpen(true);
    try {
      const result = await api.nmapTarget();
      setNmapTarget(result.target ?? "");
    } catch { setNmapTarget(""); }
  };

  const scanNmap = async (target: string, profile: "discovery" | "common_tcp") => {
    if (scanLock.current) return;
    scanLock.current = true;
    setNmapBusy(true);
    setNmapError("");
    try {
      const result = await api.scanNmap(target, profile);
      setDevices(result.devices);
      setSelectedDeviceId(result.devices[0]?.device_id ?? "");
      setDeviceScannedAt(result.scanned_at);
      setHistoryRefresh((revision) => revision + 1);
      setNmapOpen(false);
      setView("devices");
      showToast(`Nmap completed · ${result.observed_count} responsive host${result.observed_count === 1 ? "" : "s"}.`);
    } catch (error) {
      const message = error instanceof WiTrustApiError ? error.message : "Nmap scan failed.";
      setNmapError(message);
    } finally { scanLock.current = false; setNmapBusy(false); }
  };

  const compareWifi = async () => {
    if (scanLock.current) return;
    scanLock.current = true;
    setCompareBusy(true);
    setActionError("");
    try {
      const result = await api.compareWifi();
      setComparison(result);
      showToast("Current network comparison completed.");
    } catch (error) { showError(error); }
    finally { scanLock.current = false; setCompareBusy(false); }
  };

  const downloadReport = () => {
    if (!selectedNetwork || !selectedAssessment) return;
    setActionError("");
    const report = [
      "WITRUST · WI-FI SECURITY REPORT",
      `Generated: ${new Date().toLocaleString()}`,
      "",
      `SSID: ${selectedNetwork.ssid || "Unnamed network"}`,
      `BSSID: ${selectedNetwork.bssid || "Unavailable"}`,
      `Authentication: ${selectedNetwork.authentication || "Unknown"}`,
      `Encryption: ${selectedNetwork.encryption || "Unknown"}`,
      `Signal: ${selectedNetwork.signal || "Unknown"}`,
      `Channel / band: ${selectedNetwork.channel || "Unknown"} / ${selectedNetwork.band || "Unknown"}`,
      "",
      `Risk: ${selectedAssessment.score}/100 · ${selectedAssessment.level}`,
      `Security status: ${selectedAssessment.security_status}`,
      `Evidence coverage: ${selectedAssessment.data_coverage_score}% (field completeness, not probability)`,
      "",
      "WHY:",
      ...selectedAssessment.reasons.map((reason) => `- ${reason}`),
      "",
      "RECOMMENDATIONS:",
      ...selectedAssessment.recommendations.map((tip) => `- ${tip}`),
      "",
      "Prototype heuristic; this report is not proof that a network is malicious.",
    ].join("\n");
    const file = new Blob([report], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(file);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `WiTrust_Report_${(selectedNetwork.ssid || "Network").replace(/[^a-z0-9_-]+/gi, "_").slice(0, 60)}.txt`;
    anchor.click();
    URL.revokeObjectURL(url);
    showToast("Security report downloaded.");
  };

  const onSelectNetwork = (index: number) => setSelectedNetworkIndex(index);
  const onSelectDevice = (device: DeviceRecord) => setSelectedDeviceId(device.device_id);
  const title = navTitles[view];

  return <div className="app-frame">
    <Sidebar active={view} onNavigate={setView} open={sidebarOpen} onClose={() => setSidebarOpen(false)} nmapAvailable={Boolean(health?.nmap_available)} />
    <main className="main-shell">
      <header className="topbar">
        <button className="mobile-menu" onClick={() => setSidebarOpen(true)} aria-label="Open navigation"><Icon name="menu"/></button>
        <div className="topbar-title"><strong>{title.title}</strong><span>{title.subtitle}</span></div>
        <div className="topbar-right"><div className={`api-indicator ${health ? "api-connected" : "api-disconnected"}`} title={health ? "Local API connected" : "Local API unavailable"}><i/>{health ? "LOCAL API CONNECTED" : "API OFFLINE"}</div><Button variant="primary" icon="scan" onClick={scanWifi} disabled={scanBusy}>{wifiBusy ? "Scanning…" : "Scan Wi-Fi"}</Button></div>
      </header>
      {apiError && <div className="connection-banner" role="alert"><Icon name="alert"/><span><strong>Connect the WiTrust backend</strong>{apiError}<small>Start the Python API with <code>python3 api_server.py</code>.</small></span><Button variant="quiet" onClick={refreshConnection}>Retry</Button></div>}
      {actionError && <div className="action-banner" role="alert"><Icon name="info"/><span>{actionError}</span><button aria-label="Dismiss message" onClick={() => setActionError("")}><Icon name="close"/></button></div>}
      {toast && <div className="toast" role="status"><Icon name="check"/>{toast}</div>}
      <div className="page-content" key={view}>
        {view === "dashboard" && <DashboardView current={current} currentAssessment={currentAssessment} networks={networks} assessments={assessments} findings={findings} devices={devices} scannedAt={scannedAt} onScan={scanWifi} busy={scanBusy} onSelectNetwork={onSelectNetwork} selectedNetwork={selectedNetwork} />}
        {view === "wifi" && <WifiView networks={networks} assessments={assessments} findings={findings} selectedIndex={selectedNetworkIndex} onSelect={onSelectNetwork} onScan={scanWifi} busy={scanBusy} />}
        {view === "devices" && <DevicesView devices={devices} selectedId={selectedDeviceId} onSelect={onSelectDevice} history={deviceHistory} onScan={scanDevices} onOpenNmap={openNmap} busy={scanBusy} nmapAvailable={Boolean(health?.nmap_available)} scannedAt={deviceScannedAt} />}
        {view === "reports" && <ReportsView network={selectedNetwork} assessment={selectedAssessment} onDownload={downloadReport} />}
        {view === "compare" && <CompareView data={comparison} busy={scanBusy} onCompare={compareWifi} />}
        {view === "map" && <MapView networks={networks} assessments={assessments} />}
        {view === "settings" && <SettingsView health={health} apiError={apiError} onRefresh={refreshConnection} />}
      </div>
      <footer className="app-footer"><span>WiTrust · Local-first Wi-Fi security</span><span><Icon name="lock"/> Scan only networks you’re authorized to assess</span></footer>
    </main>
    <NmapDialog open={nmapOpen} target={nmapTarget} onClose={() => { if (!nmapBusy) setNmapOpen(false); }} onScan={scanNmap} busy={nmapBusy} error={nmapError} nmapAvailable={Boolean(health?.nmap_available)} />
    <div className="sr-only" aria-live="polite">{wifiBusy ? "Wi-Fi scan in progress" : deviceBusy ? "Device scan in progress" : nmapBusy ? "Nmap scan in progress" : ""}</div>
  </div>;
}
