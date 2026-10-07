import type {
  ApiHealth,
  ComparisonResponse,
  DeviceHistoryEntry,
  DeviceRecord,
  WifiScanResponse,
} from "@/lib/types";

export class WiTrustApiError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = "WiTrustApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      cache: "no-store",
      headers: { "Content-Type": "application/json", ...init?.headers },
      signal: init?.signal ?? AbortSignal.timeout(
        path.includes("nmap") ? 210_000 : path.includes("compare") ? 170_000 : 100_000,
      ),
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "TimeoutError") {
      throw new WiTrustApiError("The local scan took too long. Please retry.");
    }
    throw new WiTrustApiError("Could not reach the WiTrust API. Start the Python API and try again.");
  }

  const body = await response.json().catch(() => null) as { error?: string } | null;
  if (!response.ok) {
    throw new WiTrustApiError(body?.error ?? `Request failed (${response.status}).`, response.status);
  }
  return body as T;
}

export const api = {
  health: () => request<ApiHealth>("/api/health"),
  currentNetwork: () => request<{ network: Record<string, string | boolean> }>("/api/wifi/current"),
  scanWifi: () => request<WifiScanResponse>("/api/wifi/scan", { method: "POST", body: "{}" }),
  compareWifi: () => request<ComparisonResponse>("/api/wifi/compare", { method: "POST", body: "{}" }),
  devices: () => request<{ devices: DeviceRecord[] }>("/api/devices"),
  scanDevices: () => request<{ devices: DeviceRecord[]; observed_count: number; source: string; scanned_at: string }>("/api/devices/scan", { method: "POST", body: "{}" }),
  nmapTarget: () => request<{ target: string | null }>("/api/nmap/target"),
  scanNmap: (target: string, profile: "discovery" | "common_tcp") => request<{
    devices: DeviceRecord[];
    observed_count: number;
    source: string;
    profile: string;
    scanned_at: string;
  }>("/api/devices/nmap", {
    method: "POST",
    body: JSON.stringify({ target, profile, authorized: true }),
  }),
  deviceHistory: (deviceId: string) => request<{ history: DeviceHistoryEntry[] }>(
    `/api/devices/${encodeURIComponent(deviceId)}/history`,
  ),
};
