"""Reject common accidental private data in this source distribution."""
from pathlib import Path
import ipaddress
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".git", ".build", "dist", "__pycache__", ".venv", ".pytest_cache", ".ruff_cache"}
FORBIDDEN = {"vault-config.json", "vault-outbox.json", "cases.json", "snapshot.json", "status.json", ".DS_Store", ".env", "config.toml"}
SUFFIXES = {".pcap", ".pcapng", ".cap", ".hc22000", ".potfile", ".sqlite", ".sqlite3", ".db", ".log", ".pyc", ".p12", ".pfx", ".exe", ".pem", ".key"}
PATTERNS = {
    "machine home path": rb"/(?:Users|home)/[A-Za-z0-9_.-]+",
    "private key": rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "GitHub token": rb"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})",
    "cloud access key": rb"(?:AKIA|ASIA)[A-Z0-9]{16}",
    "API credential": rb"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{30,}",
    "credential assignment": rb'''(?i)(?:api[_-]?key|access[_-]?token)\s*["']?\s*[:=]\s*["'][A-Za-z0-9_+/=-]{24,}["']''',
}


def png_metadata(data):
    offset = 8
    while offset < len(data):
        size = struct.unpack(">I", data[offset:offset + 4])[0]
        if data[offset + 4:offset + 8] in (b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME"):
            return True
        offset += size + 12
    return False


issues = []
files = 0
for path in ROOT.rglob("*"):
    relative = path.relative_to(ROOT)
    if any(part in SKIP for part in relative.parts):
        continue
    if path.is_symlink():
        issues.append((relative, "symlink"))
        continue
    if not path.is_file():
        continue
    files += 1
    if path.name in FORBIDDEN or path.suffix.lower() in SUFFIXES or any(part in {"captures", "scans", "loot", "wordlists"} for part in relative.parts):
        issues.append((relative, "runtime or credential file"))
    data = path.read_bytes()
    for label, pattern in PATTERNS.items():
        if re.search(pattern, data):
            issues.append((relative, label))
    if path.suffix == ".png" and png_metadata(data):
        issues.append((relative, "PNG text/EXIF metadata"))
    for candidate in set(re.findall(rb"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])", data)):
        try:
            address = ipaddress.ip_address(candidate.decode())
        except ValueError:
            continue
        if address in ipaddress.ip_network((0x64400000, 10)):
            issues.append((relative, "overlay-network IPv4 address"))
if issues:
    for path, label in sorted(set(issues)):
        print(f"FAIL {path}: {label}")
    sys.exit(1)
print(f"PASS: {files} source files checked; no blocked files, credential patterns, personal home paths, overlay IPs or PNG text metadata found.")
