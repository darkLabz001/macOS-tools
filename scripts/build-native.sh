#!/bin/zsh
set -euo pipefail
cd "${0:A:h:h}"
mkdir -p .build/native/packet-vault dist
cp packet-vault/PacketVault.swift .build/native/packet-vault/main.swift
swiftc osint-vault-relay/VaultRelay.swift network-mapper/Core.swift network-mapper/main.swift -o .build/native/NetworkMapper -framework AppKit -framework UniformTypeIdentifiers
swiftc osint-vault-relay/VaultRelay.swift .build/native/packet-vault/main.swift -o .build/native/PacketVault -framework AppKit -framework UniformTypeIdentifiers
for name in "Network Mapper" "Packet Vault"; do
    if [[ "$name" == "Network Mapper" ]]; then
        executable=NetworkMapper
        icon=network-mapper/cyber-raven.png
        identifier=org.macostools.networkmapper
    else
        executable=PacketVault
        icon=packet-vault/amber-vault.png
        identifier=org.macostools.packetvault
    fi
    app="$PWD/dist/$name.app"
    mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
    cp ".build/native/$executable" "$app/Contents/MacOS/$executable"
    cp osint-vault-relay/vault_relay.py "$app/Contents/Resources/vault_relay.py"
    python3 scripts/make-icon.py "$icon" "$app/Contents/Resources/$executable.icns"
    python3 - "$app" "$name" "$executable" "$identifier" <<'PY'
import plistlib,sys
from pathlib import Path
app,name,executable,identifier=sys.argv[1:]
info={"CFBundleName":name,"CFBundleDisplayName":name,"CFBundleIdentifier":identifier,"CFBundleExecutable":executable,"CFBundleIconFile":executable+".icns","CFBundlePackageType":"APPL","CFBundleShortVersionString":"0.1.0","CFBundleVersion":"1","LSMinimumSystemVersion":"14.0","NSHighResolutionCapable":True}
(Path(app)/"Contents/Info.plist").write_bytes(plistlib.dumps(info))
PY
    codesign --force --sign - "$app"
done
OUTSIDE_IN_BUILD=debug zsh outside-in/scripts/build-app.sh "$@"
cp -R "outside-in/dist/Outside In.app" dist/
print "Built native apps in $PWD/dist"
