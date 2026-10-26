#!/bin/zsh
set -euo pipefail
cd "${0:A:h:h}"
python3 scripts/audit-source.py
zsh outside-in/scripts/test.sh
(cd osint-vault-relay && python3 -m unittest -v test_relay.py)
mkdir -p .build/checks
swiftc network-mapper/Core.swift network-mapper/tests/main.swift -o .build/checks/worker-fixtures
.build/checks/worker-fixtures
if [[ -x "dist/Network Mapper.app/Contents/MacOS/NetworkMapper" ]]; then
    "dist/Network Mapper.app/Contents/MacOS/NetworkMapper" --self-test
    "dist/Packet Vault.app/Contents/MacOS/PacketVault" --self-test
    python3 packet-vault/test_fixtures.py
fi
if command -v uv >/dev/null 2>&1; then
    PYTHONPATH="$PWD/wifit3/src:$PWD/osint-vault-relay${PYTHONPATH:+:$PYTHONPATH}" uv run --project wifit3 --python 3.12 python wifit3/test_manual_controls.py
fi
