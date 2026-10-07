export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type WiFiNetwork = {
  ssid?: string;
  ssid_redacted?: boolean;
  bssid?: string;
  signal?: string;
  channel?: string;
  band?: string;
  authentication?: string;
  encryption?: string;
  connected?: boolean;
};

export type NetworkAssessment = {
  score: number;
  level: RiskLevel;
  security_status: string;
  data_quality: string;
  data_coverage_score: number;
  limitations: string[];
  signals: { code: string; points: number }[];
  observations: string[];
  reasons: string[];
  recommendations: string[];
};

export type EvilTwinFinding = {
  ssid: string;
  bssid: string;
  security: string;
  trusted_security: string;
  reason: string;
};

export type WifiScanResponse = {
  networks: WiFiNetwork[];
  assessments: NetworkAssessment[];
  findings: Record<string, EvilTwinFinding>;
  current_network: WiFiNetwork | null;
  current_assessment: NetworkAssessment | null;
  current_error: string;
  warning: string;
  scanned_at: string;
};

export type DeviceReason = { type: string; description: string; weight: number };

export type DeviceRecord = {
  device_id: string;
  ip: string;
  mac: string;
  hostname: string;
  vendor: string;
  interface: string;
  ssid: string;
  bssid: string;
  signal: string;
  wifi_security: string;
  encryption: string;
  ports_scanned: boolean;
  open_ports: string[];
  services: string[];
  service_details: string[];
  trust_score: number;
  risk_score: number;
  risk_level: RiskLevel;
  trust_drift: number | null;
  confidence: number;
  data_coverage_score: number;
  reasons: DeviceReason[];
  new_ports: string[];
  new_services: string[];
  changed_services: string[];
  previously_observed: boolean;
  first_seen: string;
  last_seen: string;
  observation_count: number;
};

export type DeviceHistoryEntry = {
  observed_at: string;
  ip: string;
  open_ports: string[];
  services: string[];
  service_details: string[];
  trust_score: number;
  risk_score: number;
  reasons: DeviceReason[];
};

export type ComparisonResponse = {
  result: {
    current: NetworkAssessment;
    total_nearby: number;
    comparison: string[];
  };
  networks: WiFiNetwork[];
  findings: Record<string, EvilTwinFinding>;
};

export type ApiHealth = {
  status: string;
  service: string;
  nmap_available: boolean;
};

export type ApiErrorPayload = { error: string };
