# Network Mapper

Native macOS Nmap front end with explicit targets, manual start/stop, scan profiles, service/OS detection options, script selection, completed-scan history, XML import and comparisons.

Build from the repository root with `zsh scripts/build-native.sh`, then open `dist/Network Mapper.app`. Install Nmap separately (`/opt/homebrew/bin/nmap` is the default backend). Scans never start on launch. Advanced/raw-socket modes use Terminal's ordinary sudo prompt; passwords are not handled or stored by the app.

Saved scans go to `~/Library/Application Support/macOS-tools/NetworkMapper/scans/`. The clean source tree contains no scans or target history. Intrusive Nmap options require explicit selection and manual start.

