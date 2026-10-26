"""Shared durable delivery of structured tool findings to the user's OSINT Vault."""
import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import sys
import threading
import urllib.error
import urllib.request
import urllib.parse

SOURCES = {"network-mapper", "packet-vault", "wifit3"}
ROOT = Path.home() / "Library/Application Support/macOS-tools/OSINTVaultRelay"
CONFIG = Path.home() / "Library/Application Support/macOS-tools/vault-config.json"
_thread_lock = threading.Lock()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def database(root=ROOT):
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = root / "outbox.sqlite3"
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    os.fchmod(fd, 0o600)
    os.close(fd)
    connection = sqlite3.connect(path, timeout=15)
    connection.execute("PRAGMA busy_timeout=15000")
    connection.execute("CREATE TABLE IF NOT EXISTS records (id TEXT PRIMARY KEY, source TEXT NOT NULL, payload TEXT NOT NULL, sent INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_at TEXT NOT NULL)")
    return contextlib.closing(connection)


def enqueue(records, root=ROOT):
    added = 0
    with database(root) as db, db:
        for record in records:
            if record.get("source") not in SOURCES or not all(isinstance(record.get(k), str) and record[k] for k in ("source", "type", "value")):
                raise ValueError("Invalid source/type/value in Vault record")
            fingerprint = hashlib.sha256(encode(record).encode()).hexdigest()
            payload = json.loads(encode(record))
            now = dt.datetime.now(dt.timezone.utc).isoformat()
            payload["observed_at"] = now
            payload.setdefault("metadata", {})["observed_at"] = now
            cursor = db.execute("INSERT OR IGNORE INTO records (id,source,payload,created_at) VALUES (?,?,?,?)", (fingerprint, record["source"], encode(payload), now))
            added += cursor.rowcount
    return added


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send(payload, fingerprint, configuration):
    destination = configuration.get("endpoint", "")
    parsed = urllib.parse.urlsplit(destination)
    if not configuration.get("enabled") or parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or not configuration.get("apiKey"):
        raise ValueError("Vault sync is disabled or not configured")
    request = urllib.request.Request(destination, data=payload.encode(), headers={"X-API-Key": configuration["apiKey"], "Content-Type": "application/json", "Accept": "application/json", "Idempotency-Key": fingerprint}, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=10) as response:
        if not 200 <= response.status < 300:
            raise ValueError(f"Vault HTTP {response.status}")
        body = response.read(1_000_000)
        try:
            result = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            result = None
        if isinstance(result, dict) and (result.get("success") is False or result.get("error")):
            raise ValueError("Vault did not confirm acceptance")


def flush(root=ROOT, config_path=CONFIG, sender=send, limit=100):
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    sent = 0
    error = None
    with (root / "delivery.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return status(root, sent=0, error="Another app is syncing")
        with database(root) as db:
            entries = db.execute("SELECT id,payload FROM records WHERE sent=0 ORDER BY created_at,id LIMIT ?", (limit,)).fetchall()
            if entries:
                try:
                    configuration = json.loads(config_path.read_text())
                    if not configuration.get("enabled"):
                        return status(root, sent=0, error="Vault sync disabled")
                except (OSError, ValueError):
                    return status(root, sent=0, error="Vault configuration unavailable")
                for fingerprint, payload in entries:
                    try:
                        sender(payload, fingerprint, configuration)
                    except Exception as exc:
                        error = f"Vault HTTP {exc.code}" if isinstance(exc, urllib.error.HTTPError) else type(exc).__name__
                        with db:
                            db.execute("UPDATE records SET attempts=attempts+1,last_error=? WHERE id=?", (error, fingerprint))
                        if isinstance(exc, urllib.error.HTTPError) and exc.code in (400, 413, 422):
                            continue
                        break
                    with db:
                        db.execute("UPDATE records SET sent=1,attempts=attempts+1,last_error=NULL WHERE id=?", (fingerprint,))
                    sent += 1
    result = status(root, sent=sent, error=error)
    (root / "status.json").write_text(encode(result))
    return result


def status(root=ROOT, sent=0, error=None):
    with database(root) as db:
        pending = db.execute("SELECT COUNT(*) FROM records WHERE sent=0").fetchone()[0]
        delivered = db.execute("SELECT COUNT(*) FROM records WHERE sent=1").fetchone()[0]
    return {"sent": sent, "pending": pending, "delivered": delivered, "error": error}


def record(source, kind, value, metadata, tags):
    return {"source": source, "type": kind, "value": value, "tags": ["osint", source] + tags, "metadata": metadata}


def mapper_records(snapshot):
    records = []
    scan_date = snapshot.get("date")
    if isinstance(scan_date, (int, float)):
        scan_date = (dt.datetime(2001, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=scan_date)).isoformat()
    for host in snapshot.get("hosts", []):
        address = host.get("address", "")
        if not address:
            continue
        try:
            ipaddress.ip_address(address)
            kind = "ip"
        except ValueError:
            kind = "domain"
        ports = [{key: port.get(key, "") for key in ("number", "proto", "state", "service", "version")} for port in host.get("ports", [])]
        metadata = {"hostname": host.get("name", ""), "host_state": host.get("state", "unknown"), "os_guess": host.get("os", ""), "ports": ports, "scan_date": scan_date, "target_scope": snapshot.get("config", {}).get("targets", ""), "profile": snapshot.get("config", {}).get("profile", ""), "scripts_retained_locally": True}
        records.append(record("network-mapper", kind, address, metadata, ["nmap", "services"]))
    return records


def packet_wifi_records(report):
    records = []
    for ap in report.get("targets", []):
        metadata = {key: ap.get(key) for key in ("ssid", "handshakeCandidate", "readiness")}
        metadata["capture_name"] = Path(report.get("capture", "capture")).name
        records.append(record("packet-vault", "access_point", ap["bssid"], metadata, ["wifi", "capture-analysis"]))
    return records


def packet_endpoint_records(report):
    endpoints = {}
    for line in report.get("rows", "").splitlines():
        fields = line.split("\t")
        if len(fields) < 9:
            continue
        for index, text in enumerate(fields[:4]):
            try:
                address = str(ipaddress.ip_address(text))
            except ValueError:
                continue
            entry = endpoints.setdefault(address, {"ports": set(), "protocols": set(), "frames": 0})
            for port_index, protocol in [(4 + index % 2, "tcp"), (6 + index % 2, "udp")]:
                if fields[port_index].isdigit() and 0 < int(fields[port_index]) <= 65535:
                    entry["ports"].add(f"{fields[port_index]}/{protocol}")
            entry["protocols"].add(fields[8][:80])
            entry["frames"] += 1
    return [record("packet-vault", "ip", address, {"capture_name": Path(report.get("capture", "capture")).name, "observed_transport_ports_in_frames": sorted(data["ports"]), "protocols": sorted(data["protocols"]), "endpoint_occurrences": data["frames"], "input_frame_limit": 10000, "port_state": "observed traffic, not a live port check"}, ["pcap", "endpoint"]) for address, data in sorted(endpoints.items())]


def wifi_records(access_points):
    keys = ("ssid", "channel", "encryption", "akm_suites", "pairwise_cipher", "wpa3", "transition_mode", "pmf_capable", "pmf_required", "wps", "wps_locked", "client_count", "handshake_count")
    return [record("wifit3", "access_point", ap["bssid"].lower(), {key: ap.get(key) for key in keys}, ["wifi", "access-point"]) for ap in access_points if ap.get("bssid")]


def publish_wifi(access_points, on_status=None):
    """Queue Wi-Fi metadata and deliver in a background thread."""
    records = wifi_records(access_points)
    if not _thread_lock.acquire(blocking=False):
        return
    def work():
        try:
            enqueue(records)
            result = flush()
            if on_status:
                on_status(result)
        except Exception as exc:
            print(f"[Vault] {type(exc).__name__}; findings remain local", file=sys.stderr)
        finally:
            _thread_lock.release()
    threading.Thread(target=work, name="osint-vault-sync", daemon=True).start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["mapper", "packet-wifi", "packet-endpoints", "flush", "status"])
    args = parser.parse_args()
    if args.operation == "status":
        print(encode(status()))
        return
    if args.operation != "flush":
        adapters = {"mapper": mapper_records, "packet-wifi": packet_wifi_records, "packet-endpoints": packet_endpoint_records}
        enqueue(adapters[args.operation](json.load(sys.stdin)))
    print(encode(flush()))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(encode({"error": type(exc).__name__, "pending": "unknown"}))
        sys.exit(1)
