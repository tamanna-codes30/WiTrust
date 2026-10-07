"""Explainable device fingerprints, local history, and trust assessments."""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wifi_reputation import normalize_bssid


DEFAULT_HISTORY_DB = Path.home() / ".witrust" / "device_history.sqlite3"
RISK_WEIGHTS = {
    "new_device": 10,
    "new_port": 12,
    "new_service": 15,
    "service_changed": 10,
    "telnet_service": 50,
    "ftp_service": 20,
    "smb_service": 12,
    "remote_admin_service": 10,
    "known_device": -5,
    "stable_behavior": -5,
}
RISK_LEVELS = ((80, "CRITICAL"), (60, "HIGH"), (30, "MEDIUM"), (0, "LOW"))
_PORT_PATTERN = re.compile(r"^(\d{1,5})/(?:tcp|udp)\b", re.IGNORECASE)


def _clean_text(value: Any) -> str:
    return " ".join(str(value or "").split())


def _canonical_ip(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value))) if value else ""
    except ValueError:
        return ""


def _device_ports(device: dict[str, Any]) -> list[str]:
    ports = device.get("open_ports") or []
    if isinstance(ports, str):
        ports = [item.strip() for item in ports.split(",") if item.strip()]
    result = set()
    for port in ports:
        value = _clean_text(port)
        match = _PORT_PATTERN.match(value)
        if match and int(match.group(1)) <= 65535:
            result.add(f"{int(match.group(1))}/{value.split('/', 1)[1].split()[0].lower()}")
        elif value.isdigit() and 1 <= int(value) <= 65535:
            result.add(f"{int(value)}/tcp")
    return sorted(result, key=lambda item: (int(item.split("/", 1)[0]), item))


def _data_coverage_score(fingerprint: dict[str, Any]) -> int:
    has_vendor = _clean_text(fingerprint.get("vendor")) not in {
        "", "Unknown (not available)"
    }
    evidence_fields = (
        bool(fingerprint.get("ip")), bool(fingerprint.get("mac")),
        bool(fingerprint.get("hostname")), has_vendor,
        bool(fingerprint.get("ssid")), bool(fingerprint.get("bssid")),
        bool(fingerprint.get("wifi_security")), bool(fingerprint.get("encryption")),
        bool(fingerprint.get("signal")), bool(fingerprint.get("ports_scanned")),
    )
    return round(100 * sum(evidence_fields) / len(evidence_fields))


def fingerprint_device(
    device: dict[str, Any], connected_network: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Normalize observed fields and derive a stable, non-secret device ID."""
    if not isinstance(device, dict):
        raise ValueError("A device record must be a dictionary.")
    connected_network = connected_network if isinstance(connected_network, dict) else {}
    mac = normalize_bssid(device.get("mac"))
    ip = _canonical_ip(device.get("ip"))
    hostname = _clean_text(device.get("hostname"))
    if mac:
        device_id = f"mac:{mac}"
    elif hostname:
        device_id = f"host:{hostname.casefold()}"
    elif ip:
        device_id = f"ip:{ip}"
    else:
        raise ValueError("A device needs a valid MAC address, hostname, or IP address.")

    ports = _device_ports(device)
    raw_ports = device.get("open_ports") or []
    if isinstance(raw_ports, str):
        raw_ports = [item.strip() for item in raw_ports.split(",") if item.strip()]
    bssid = normalize_bssid(connected_network.get("bssid"))
    return {
        "device_id": device_id,
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "vendor": _clean_text(device.get("vendor")) or "Unknown (not available)",
        "interface": _clean_text(device.get("interface")),
        "ports_scanned": bool(device.get("ports_scanned", False)),
        "ssid": _clean_text(connected_network.get("ssid")),
        "bssid": bssid,
        "signal": _clean_text(connected_network.get("signal")),
        "wifi_security": _clean_text(connected_network.get("authentication")),
        "encryption": _clean_text(connected_network.get("encryption")),
        "open_ports": ports,
        "services": sorted({
            match.group(1).split("(", 1)[0].strip().casefold()
            for value in raw_ports
            if isinstance(value, str)
            for match in [re.match(r"^\d+/(?:tcp|udp)\s+(.+)$", value, re.IGNORECASE)]
            if match
        }),
        "service_details": sorted({
            _clean_text(value)
            for value in raw_ports
            if isinstance(value, str)
            and re.match(r"^\d+/(?:tcp|udp)\s+", value, re.IGNORECASE)
        }),
    }


def assess_device(
    fingerprint: dict[str, Any],
    previous: dict[str, Any] | None = None,
    observed_at: str | None = None,
) -> dict[str, Any]:
    """Score device-level evidence; reasons are safe for direct UI rendering."""
    previous = previous or {}
    prior_ports = set(previous.get("open_ports", []))
    prior_services = set(previous.get("services", []))
    current_ports = set(fingerprint.get("open_ports", []))
    current_services = set(fingerprint.get("services", []))
    prior_details = {
        match.group(1): detail
        for detail in previous.get("service_details", [])
        if isinstance(detail, str)
        for match in [re.match(r"^(\d+/(?:tcp|udp))\s+", detail, re.IGNORECASE)]
        if match
    }
    current_details = {
        match.group(1): detail
        for detail in fingerprint.get("service_details", [])
        if isinstance(detail, str)
        for match in [re.match(r"^(\d+/(?:tcp|udp))\s+", detail, re.IGNORECASE)]
        if match
    }
    reasons: list[dict[str, Any]] = []

    def add_reason(code: str, description: str, weight: int) -> None:
        reasons.append({"type": code, "description": description, "weight": weight})

    is_new = not previous
    if is_new:
        add_reason("new_device", "Device was observed for the first time.", RISK_WEIGHTS["new_device"])
    else:
        add_reason("known_device", "Device has been observed before.", RISK_WEIGHTS["known_device"])

    new_ports = sorted(current_ports - prior_ports) if previous else []
    for port in new_ports[:2]:
        add_reason("new_port", f"Newly observed open port: {port}.", RISK_WEIGHTS["new_port"])
    new_services = sorted(current_services - prior_services) if previous else []
    for service in new_services[:2]:
        add_reason("new_service", f"Previously unseen service: {service}.", RISK_WEIGHTS["new_service"])
    changed_services = sorted(
        port for port, detail in current_details.items()
        if port in prior_details and prior_details[port] != detail
    ) if previous else []
    for port in changed_services[:2]:
        add_reason(
            "service_changed",
            f"Service identification or version changed on {port}.",
            RISK_WEIGHTS["service_changed"],
        )

    port_numbers = {int(value.split("/", 1)[0]) for value in current_ports}
    risky_services = (
        (23, "telnet_service", "Telnet is unencrypted and exposes remote access."),
        (21, "ftp_service", "FTP may transmit credentials without encryption."),
        (445, "smb_service", "SMB is exposed on this device."),
        (3389, "remote_admin_service", "Remote Desktop is exposed on this device."),
    )
    for port, code, description in risky_services:
        if port in port_numbers:
            add_reason(code, description, RISK_WEIGHTS[code])

    if not is_new and not new_ports and not new_services and not changed_services:
        add_reason("stable_behavior", "No new ports or services versus the previous observation.", RISK_WEIGHTS["stable_behavior"])

    risk_score = max(0, min(100, sum(reason["weight"] for reason in reasons)))
    if 23 in port_numbers:
        risk_score = max(risk_score, RISK_WEIGHTS["telnet_service"])
    if 21 in port_numbers:
        risk_score = max(risk_score, 20)
    risk_level = next(level for boundary, level in RISK_LEVELS if risk_score >= boundary)
    trust_score = 100 - risk_score
    previous_trust = previous.get("trust_score")
    trust_drift = trust_score - previous_trust if isinstance(previous_trust, int) else None
    data_coverage_score = _data_coverage_score(fingerprint)
    confidence = round(data_coverage_score / 100, 2)
    return {
        "device_id": fingerprint["device_id"],
        "risk_score": risk_score,
        "trust_score": trust_score,
        "risk_level": risk_level,
        "trust_drift": trust_drift,
        "confidence": confidence,
        "data_coverage_score": data_coverage_score,
        "reasons": reasons,
        "new_ports": new_ports,
        "new_services": new_services,
        "changed_services": changed_services,
        "previously_observed": not is_new,
        "observed_at": observed_at or datetime.now(timezone.utc).isoformat(),
    }


class DeviceHistoryStore:
    """Small SQLite store for device snapshots and observation history."""

    def __init__(self, path: str | Path = DEFAULT_HISTORY_DB):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    observation_count INTEGER NOT NULL,
                    last_ip TEXT NOT NULL,
                    fingerprint_json TEXT NOT NULL,
                    assessment_json TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS observations (
                    observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    open_ports_json TEXT NOT NULL,
                    services_json TEXT NOT NULL,
                    service_details_json TEXT NOT NULL DEFAULT '[]',
                    trust_score INTEGER NOT NULL,
                    risk_score INTEGER NOT NULL,
                    reasons_json TEXT NOT NULL,
                    FOREIGN KEY(device_id) REFERENCES devices(device_id)
                )"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS observations_by_device ON observations(device_id, observation_id DESC)"
            )
            observation_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(observations)")
            }
            if "service_details_json" not in observation_columns:
                connection.execute(
                    "ALTER TABLE observations ADD COLUMN service_details_json TEXT NOT NULL DEFAULT '[]'"
                )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def observe(
        self,
        device: dict[str, Any],
        connected_network: dict[str, Any] | None = None,
        observed_at: str | None = None,
    ) -> dict[str, Any]:
        fingerprint = fingerprint_device(device, connected_network)
        timestamp = observed_at or datetime.now(timezone.utc).isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM devices WHERE device_id = ?", (fingerprint["device_id"],)
            ).fetchone()
            previous = None
            first_seen = timestamp
            observation_count = 0
            if row:
                previous = json.loads(row["fingerprint_json"])
                previous_assessment = json.loads(row["assessment_json"])
                previous = {**previous, "trust_score": previous_assessment.get("trust_score")}
                first_seen = row["first_seen"]
                observation_count = row["observation_count"]
                if not fingerprint["ports_scanned"]:
                    fingerprint["open_ports"] = previous.get("open_ports", [])
                    fingerprint["services"] = previous.get("services", [])
                    fingerprint["service_details"] = previous.get("service_details", [])

            assessment = assess_device(fingerprint, previous, timestamp)
            observation_count += 1
            record = {
                **fingerprint,
                **assessment,
                "first_seen": first_seen,
                "last_seen": timestamp,
                "observation_count": observation_count,
            }
            connection.execute(
                """INSERT INTO devices VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(device_id) DO UPDATE SET
                   last_seen=excluded.last_seen,
                   observation_count=excluded.observation_count,
                   last_ip=excluded.last_ip,
                   fingerprint_json=excluded.fingerprint_json,
                   assessment_json=excluded.assessment_json""",
                (
                    fingerprint["device_id"], first_seen, timestamp, observation_count,
                    fingerprint["ip"], json.dumps(fingerprint), json.dumps(assessment),
                ),
            )
            connection.execute(
                """INSERT INTO observations
                   (device_id, observed_at, ip, open_ports_json, services_json, service_details_json,
                    trust_score, risk_score, reasons_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    fingerprint["device_id"], timestamp, fingerprint["ip"],
                    json.dumps(fingerprint["open_ports"]), json.dumps(fingerprint["services"]),
                    json.dumps(fingerprint["service_details"]),
                    assessment["trust_score"], assessment["risk_score"],
                    json.dumps(assessment["reasons"]),
                ),
            )
        return record

    def list_devices(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
        records = []
        for row in rows:
            fingerprint = json.loads(row["fingerprint_json"])
            assessment = json.loads(row["assessment_json"])
            assessment.setdefault(
                "data_coverage_score", _data_coverage_score(fingerprint)
            )
            records.append({
                **fingerprint,
                **assessment,
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "observation_count": row["observation_count"],
            })
        return records

    def get_history(self, device_id: str, limit: int = 20) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 100))
        with self._connection() as connection:
            rows = connection.execute(
                """SELECT * FROM observations WHERE device_id = ?
                   ORDER BY observation_id DESC LIMIT ?""",
                (device_id, limit),
            ).fetchall()
        return [{
            "observed_at": row["observed_at"],
            "ip": row["ip"],
            "open_ports": json.loads(row["open_ports_json"]),
            "services": json.loads(row["services_json"]),
            "service_details": json.loads(row["service_details_json"]),
            "trust_score": row["trust_score"],
            "risk_score": row["risk_score"],
            "reasons": json.loads(row["reasons_json"]),
        } for row in rows]
