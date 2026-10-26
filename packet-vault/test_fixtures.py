"""Exercise installed tools using a synthetic, known-password Wi-Fi capture."""
import hashlib
import hmac
from pathlib import Path
import struct
import subprocess
import tempfile
import json

AP = bytes.fromhex("021122334455")
STA = bytes.fromhex("0266778899aa")
SSID = b"PacketVaultTest"
PASSWORD = b"TestPassword123!"
ANONCE = bytes(range(32))
SNONCE = bytes(range(32, 64))


def eapol(info, nonce):
    key = struct.pack("!BHHQ", 2, info, 16, 1) + nonce
    key += bytes(16 + 8 + 8 + 16) + struct.pack("!H", 0)
    return bytearray(struct.pack("!BBH", 2, 3, len(key)) + key)


def fixture(path):
    radiotap = bytes.fromhex("0000080000000000")
    rsn = bytes.fromhex("0100000fac040100000fac040100000fac020000")
    beacon = bytes.fromhex("80000000") + b"\xff" * 6 + AP + AP + bytes(2)
    beacon += bytes(8) + struct.pack("<HH", 100, 0x0411)
    beacon += bytes([0, len(SSID)]) + SSID + bytes.fromhex("010482848b96030101")
    beacon += bytes([48, len(rsn)]) + rsn
    m1 = eapol(0x008A, ANONCE)
    m2 = eapol(0x010A, SNONCE)
    pmk = hashlib.pbkdf2_hmac("sha1", PASSWORD, SSID, 4096, 32)
    context = min(AP, STA) + max(AP, STA) + min(ANONCE, SNONCE) + max(ANONCE, SNONCE)
    ptk = b"".join(hmac.new(pmk, b"Pairwise key expansion\x00" + context + bytes([i]), hashlib.sha1).digest() for i in range(4))[:64]
    m2[81:97] = hmac.new(ptk[:16], m2, hashlib.sha1).digest()[:16]
    llc = bytes.fromhex("aaaa03000000888e")
    down = bytes.fromhex("08020000") + STA + AP + AP + bytes(2) + llc + m1
    up = bytes.fromhex("08010000") + AP + STA + AP + bytes(2) + llc + m2
    frames = [radiotap + beacon, radiotap + down, radiotap + up]
    with path.open("wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127))
        for i, frame in enumerate(frames):
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(frame), len(frame)))
            f.write(frame)


def run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=30)


with tempfile.TemporaryDirectory(prefix="packet-vault-test-") as temporary:
    root = Path(temporary)
    capture = root / "capture with spaces.pcap"
    ng = root / "copy.pcapng"
    back = root / "converted.pcap"
    words = root / "word list.txt"
    fixture(capture)
    words.write_bytes(b"IncorrectPassword\n" + PASSWORD + b"\n")
    preview = run([str(Path(__file__).resolve().parents[1] / "dist/Packet Vault.app/Contents/MacOS/PacketVault"), "--test-preview", str(capture)])
    assert preview.returncode == 0 and "02:11:22:33:44:55" in preview.stdout, preview.stderr
    assert len(preview.stdout.strip().splitlines()) == 3
    assert "_ws.col.def_src" in preview.stdout and "_ws.col.def_dst" in preview.stdout
    details = run(["/opt/homebrew/bin/tshark", "-n", "-r", str(capture), "-Y", "frame.number == 2", "-V", "-x"])
    assert details.returncode == 0 and "802.1X" in details.stdout, details.stderr
    for source, destination, kind in [(capture, ng, "pcapng"), (ng, back, "pcap")]:
        conversion = run(["/opt/homebrew/bin/tshark", "-n", "-r", str(source), "-F", kind, "-w", str(destination)])
        assert conversion.returncode == 0, conversion.stderr
    result = run(["/opt/homebrew/bin/aircrack-ng", "-a", "2", "-b", "02:11:22:33:44:55", "-w", str(words), "-p", "4", str(back)])
    assert "KEY FOUND!" in result.stdout and PASSWORD.decode() in result.stdout, result.stdout + result.stderr
    words.write_text("IncorrectPassword\n")
    exhausted = run(["/opt/homebrew/bin/aircrack-ng", "-a", "2", "-b", "02:11:22:33:44:55", "-w", str(words), "-p", "4", str(back)])
    assert "KEY FOUND!" not in exhausted.stdout
    assert "KEY NOT FOUND" in exhausted.stdout, exhausted.stdout + exhausted.stderr
    binary = str(Path(__file__).resolve().parents[1] / "dist/Packet Vault.app/Contents/MacOS/PacketVault")
    inventory = run([binary, "--inspect-targets", str(capture)])
    found = json.loads(inventory.stdout)
    assert found[0]["ssid"] == "PacketVaultTest" and found[0]["handshakeCandidate"] is True
    raw = bytearray(capture.read_bytes())
    position = 24
    for _ in range(2):
        size = struct.unpack_from("<I", raw, position + 8)[0]
        position += 16 + size
    struct.pack_into("!Q", raw, position + 16 + 40 + 9, 2)
    mismatch = root / "mismatched-replay.pcap"
    mismatch.write_bytes(raw)
    rejected = json.loads(run([binary, "--inspect-targets", str(mismatch)]).stdout)
    assert rejected[0]["handshakeCandidate"] is False
    sae = root / "sae.pcap"
    sae.write_bytes(capture.read_bytes().replace(bytes.fromhex("000fac02"), bytes.fromhex("000fac08")))
    unsupported = json.loads(run([binary, "--inspect-targets", str(sae)]).stdout)
    assert "unsupported" in unsupported[0]["readiness"]
    print("PASS: filtered packet view, decoded details, PCAPNG conversion, known-password recovery, and exhausted wordlist")
    print("PASS: AP/SSID detection, matched EAPOL candidate, mismatched-replay rejection, and WPA3 warning")
