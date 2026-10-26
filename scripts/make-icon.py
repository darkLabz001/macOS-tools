"""Package a PNG into a local macOS ICNS file without image text metadata."""
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


def clean_png(data):
    output = data[:8]
    offset = 8
    while offset < len(data):
        size = struct.unpack(">I", data[offset:offset + 4])[0]
        end = offset + size + 12
        if data[offset + 4:offset + 8] not in (b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME"):
            output += data[offset:end]
        offset = end
    return output


source, destination = map(Path, sys.argv[1:])
with tempfile.TemporaryDirectory() as temporary:
    body = b""
    for code, size in [(b"icp4", 16), (b"icp5", 32), (b"icp6", 64), (b"ic07", 128), (b"ic08", 256), (b"ic09", 512), (b"ic10", 1024)]:
        output = Path(temporary) / f"{size}.png"
        subprocess.run(["sips", "-z", str(size), str(size), str(source), "--out", str(output)], check=True, stdout=subprocess.DEVNULL)
        data = clean_png(output.read_bytes())
        body += code + struct.pack(">I", len(data) + 8) + data
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(b"icns" + struct.pack(">I", len(body) + 8) + body)
