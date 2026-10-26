# Packet Vault

Native macOS viewer for local PCAP/PCAPNG files, protocol summaries, frame details, Wi-Fi target inventories and chosen WPA/WPA2-Personal wordlist checks.

Build from the repository root with `zsh scripts/build-native.sh`, then open `dist/Packet Vault.app`. Install TShark and Aircrack-ng separately. Select your own capture and wordlist; none are bundled. The optional dictionary browser uses `~/Library/Application Support/macOS-tools/wordlists/`.

Packet lists and protocol summaries inspect the first 10,000 input frames. Target inventory and selected frame details read the full capture. Handshake candidates are observations, not guarantees of crackability. WPA3-SAE, Enterprise and arbitrary encrypted traffic are not supported by the wordlist checker.


`test_fixtures.py` creates synthetic captures and a known test password in a temporary directory; it does not use real captures or wireless hardware.
