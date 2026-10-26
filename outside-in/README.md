# Outside In

Native macOS investigation workspace with domain/IP cases, evidence graph, source links, research gaps, local persistence and Markdown/JSON exports.

Collectors include DNS records, IPv4/IPv6 reverse DNS, RDAP registration data, certificate-log hostname discovery, HTTPS headers/TLS fingerprints and checks on 17 common TCP ports. A case must be created and a scan started manually. Certificate discovery uses crt.sh with Cert Spotter fallback; names are historical evidence and are not recursively scanned.

Build all native tools from the repository root with `zsh scripts/build-native.sh`, or run `swift run OutsideIn` in this directory. Run core checks with `zsh scripts/test.sh`.

This clean copy uses `~/Library/Application Support/macOS-tools/OutsideIn/` for case data. The included training case is synthetic and uses reserved documentation names and addresses. No real case files or previous collection results are included.


Public lookups send the selected target to Cloudflare DNS, RDAP.org/the registry, and crt.sh or Cert Spotter as appropriate. HTTPS and TCP checks directly contact the chosen target. Registry country fields are not device geolocation; open ports and missing headers are not automatically classified as vulnerabilities.
