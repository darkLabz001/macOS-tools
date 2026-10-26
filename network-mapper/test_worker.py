"""Integration checks restricted to a synthetic service on loopback."""
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time

BINARY = str(Path(__file__).resolve().parents[1] / "dist/Network Mapper.app/Contents/MacOS/NetworkMapper")


def create_config(directory, port):
    subprocess.run([BINARY, "--write-test-config", str(directory / "config.json"), str(port)], check=True)


with tempfile.TemporaryDirectory(prefix="network-mapper-test-") as temporary:
    root = Path(temporary)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        port = listener.getsockname()[1]
        completed = root / "completed"
        completed.mkdir()
        create_config(completed, port)
        result = subprocess.run([BINARY, "--worker", str(completed)], timeout=20)
        assert result.returncode == 0, (completed / "console.log").read_text()
        snapshot = json.loads((completed / "snapshot.json").read_text())
        host = next(h for h in snapshot["hosts"] if h["address"] == "127.0.0.1")
        assert any(p["number"] == str(port) and p["state"] == "open" for p in host["ports"])
        assert all((completed / name).is_file() for name in ["scan.xml", "scan.nmap", "scan.gnmap", "snapshot.json", "status.json"])

        cancelled = root / "cancelled"
        cancelled.mkdir()
        create_config(cancelled, port)
        config = json.loads((cancelled / "config.json").read_text())
        config["ports"] = "1-100"
        config["maxRate"] = "1"
        (cancelled / "config.json").write_text(json.dumps(config))
        job = subprocess.Popen([BINARY, "--worker", str(cancelled)])
        deadline = time.monotonic() + 5
        while not (cancelled / "STARTED").exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        (cancelled / "STOP").touch()
        job.wait(timeout=8)
        status = json.loads((cancelled / "status.json").read_text())
        assert status["stopped"] is True
        assert not (cancelled / "snapshot.json").exists()

        before_start = root / "before-start"
        before_start.mkdir()
        create_config(before_start, port)
        (before_start / "STOP").touch()
        subprocess.run([BINARY, "--worker", str(before_start)], timeout=5)
        assert not (before_start / "STARTED").exists()

    print("PASS: loopback service detection, saved artifacts, running-job cancellation, and cancellation before authorization/start")
