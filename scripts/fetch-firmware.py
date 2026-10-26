"""Fetch checksum-verified upstream Wifit3 firmware outside the Git source set."""
import hashlib
import json
from pathlib import Path
import urllib.request

root = Path(__file__).resolve().parents[1] / "wifit3"
manifest = json.loads((root / "firmware-manifest.json").read_text())
base = "https://raw.githubusercontent.com/derv82/wifit3/v0.6.0/"
for entry in manifest:
    destination = root / entry["path"]
    if not destination.resolve().is_relative_to(root.resolve()):
        raise ValueError("Unsafe firmware destination")
    if destination.exists() and hashlib.sha256(destination.read_bytes()).hexdigest() == entry["sha256"]:
        continue
    with urllib.request.urlopen(base + entry["path"], timeout=30) as response:
        data = response.read(8_000_000)
    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError("Firmware checksum mismatch: " + entry["path"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    print("Verified " + entry["path"])
