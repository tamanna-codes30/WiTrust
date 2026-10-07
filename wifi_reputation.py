"""Local Wi-Fi threat intelligence and reputation tools.

The reputation database is stored locally in ``~/.witrust/reputation.json``.
Threat feed files are JSON objects with a ``networks`` list; each entry may
contain ``bssid``, ``status`` (``malicious`` or ``trusted``),
``reason``, and ``source`` fields.
"""

import argparse
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_DB = Path.home() / ".witrust" / "reputation.json"
MAC_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
TERMINAL_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _terminal_text(value):
    return TERMINAL_CONTROL_CHARS.sub(" ", str(value)).strip()


def normalize_bssid(value):
    """Return a normalized MAC address, or an empty string if invalid."""
    candidate = str(value or "").strip().replace("-", ":").upper()
    if not MAC_PATTERN.fullmatch(candidate):
        return ""
    octets = bytes.fromhex(candidate.replace(":", ""))
    if not any(octets) or all(octet == 0xFF for octet in octets) or octets[0] & 1:
        return ""
    return candidate


def _empty_database():
    return {"version": 1, "networks": {}}


def load_database(path=DEFAULT_DB):
    """Load local intelligence, treating a missing database as empty."""
    try:
        with Path(path).expanduser().open(encoding="utf-8") as database_file:
            database = json.load(database_file)
    except FileNotFoundError:
        return _empty_database()
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not read reputation database: {error}") from error

    if not isinstance(database, dict) or not isinstance(database.get("networks"), dict):
        raise ValueError("Reputation database has an invalid format.")
    normalized_entries = {}
    for bssid, entry in database["networks"].items():
        normalized_bssid = normalize_bssid(bssid)
        if not normalized_bssid or not isinstance(entry, dict):
            raise ValueError("Reputation database contains an invalid network entry.")
        status = str(entry.get("status", "")).strip().casefold()
        if status not in {"malicious", "trusted"}:
            raise ValueError(f"Reputation entry for {bssid} has an invalid status.")
        normalized_entries[normalized_bssid] = {**entry, "status": status}
    database["networks"] = normalized_entries
    return database


def save_database(database, path=DEFAULT_DB):
    """Atomically save local intelligence."""
    destination = Path(path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_path = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
        text=True,
    )
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as database_file:
            json.dump(database, database_file, indent=2)
            database_file.write("\n")
        os.replace(temporary_path, destination)
    except Exception:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        raise


def set_reputation(bssid, status, reason="", source="local", path=DEFAULT_DB):
    """Add or update reputation for a BSSID. Status is malicious or trusted."""
    normalized = normalize_bssid(bssid)
    if not normalized:
        raise ValueError("A valid BSSID (MAC address) is required.")
    if status not in {"malicious", "trusted"}:
        raise ValueError("Status must be 'malicious' or 'trusted'.")

    database = load_database(path)
    database["networks"][normalized] = {
        "status": status,
        "reason": str(reason).strip(),
        "source": str(source).strip() or "local",
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    save_database(database, path)


def import_feed(feed_path, database_path=DEFAULT_DB):
    """Import a JSON threat feed and return the number of accepted entries."""
    try:
        with Path(feed_path).expanduser().open(encoding="utf-8") as feed_file:
            feed = json.load(feed_file)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not read threat feed: {error}") from error

    entries = feed.get("networks") if isinstance(feed, dict) else feed
    if not isinstance(entries, list):
        raise ValueError("Threat feed must be a list or contain a 'networks' list.")

    database = load_database(database_path)
    imported = 0
    timestamp = datetime.now(timezone.utc).isoformat()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        bssid = normalize_bssid(entry.get("bssid"))
        status = str(entry.get("status", "")).strip().casefold()
        if not bssid or status not in {"malicious", "trusted"}:
            continue
        database["networks"][bssid] = {
            "status": status,
            "reason": str(entry.get("reason", "")).strip(),
            "source": str(entry.get("source", "imported feed")).strip(),
            "updated_at": timestamp,
        }
        imported += 1

    save_database(database, database_path)
    return imported


def assess_reputation(network, database):
    """Assess a scanned network using the app's shared risk rules."""
    if not isinstance(network, dict):
        raise ValueError("A network must be provided as a dictionary.")
    if not isinstance(database, dict) or not isinstance(database.get("networks"), dict):
        raise ValueError("Reputation database has an invalid format.")
    bssid = normalize_bssid(network.get("bssid"))
    entry = database.get("networks", {}).get(bssid, {})
    if not isinstance(entry, dict):
        raise ValueError("Reputation database contains an invalid network entry.")
    from risk_engine import assess_network as assess_wifi_risk

    context = {"reputation": entry} if entry else None
    assessment = assess_wifi_risk(network, context=context)
    reasons = list(assessment["reasons"])
    if entry.get("reason"):
        reasons.append(f"Intelligence: {entry['reason']}")
    if entry.get("source"):
        reasons.append(f"Source: {entry['source']}")

    return {
        "bssid": bssid or "Unknown",
        "ssid": str(network.get("ssid") or "Hidden network"),
        "score": assessment["score"],
        "level": assessment["level"],
        "status": entry.get("status", "unknown"),
        "reasons": reasons,
        "signals": assessment["signals"],
        "data_quality": assessment["data_quality"],
        "data_coverage_score": assessment["data_coverage_score"],
    }


def _read_networks(args):
    if args.input:
        try:
            with Path(args.input).expanduser().open(encoding="utf-8") as input_file:
                networks = json.load(input_file)
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"Could not read network input: {error}") from error
        if not isinstance(networks, list) or any(
            not isinstance(network, dict) for network in networks
        ):
            raise ValueError("Network input must be a JSON list of network objects.")
        return networks

    from wifi_scanner import scan_wifi

    return scan_wifi()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local Wi-Fi threat reputation system")
    parser.add_argument("--db", default=str(DEFAULT_DB), help="Local reputation database path")
    commands = parser.add_subparsers(dest="command", required=True)

    assess_parser = commands.add_parser("assess", help="Assess scanned or JSON-provided networks")
    assess_parser.add_argument("--input", help="JSON file containing a list of scanned networks")

    for status in ("trust", "block"):
        entry_parser = commands.add_parser(status, help=f"Mark a BSSID as {status}ed locally")
        entry_parser.add_argument("bssid")
        entry_parser.add_argument("--reason", default="User supplied")

    feed_parser = commands.add_parser("import-feed", help="Import a JSON reputation feed")
    feed_parser.add_argument("file")

    args = parser.parse_args(argv)
    try:
        if args.command in {"trust", "block"}:
            status = "trusted" if args.command == "trust" else "malicious"
            set_reputation(args.bssid, status, args.reason, path=args.db)
            print(f"Saved {args.bssid.upper()} as {status}.")
        elif args.command == "import-feed":
            count = import_feed(args.file, args.db)
            print(f"Imported {count} reputation entr{'y' if count == 1 else 'ies'}.")
        else:
            database = load_database(args.db)
            results = [assess_reputation(network, database) for network in _read_networks(args)]
            for result in sorted(results, key=lambda item: item["score"], reverse=True):
                print(
                    f"{result['level']:6} {result['score']:3}/100  "
                    f"{_terminal_text(result['ssid'])} ({result['bssid']})"
                )
                for signal in result["signals"]:
                    print(
                        f"       +{signal['points']:2} "
                        f"{_terminal_text(signal['code'].replace('_', ' ').title())}"
                    )
                for reason in result["reasons"]:
                    print(f"       - {_terminal_text(reason)}")
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
