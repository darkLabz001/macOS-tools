# macOS-tools

Four macOS security and investigation tools, distributed as clean source copies.

| Tool | Purpose |
| --- | --- |
| [Outside In](outside-in/) | Domain/IP reconnaissance, DNS, RDAP, certificate discovery, HTTPS/TLS observations, bounded TCP checks and an evidence graph. |
| [Network Mapper](network-mapper/) | Native Nmap front end with manual scan controls, saved snapshots and comparisons. |
| [Packet Vault](packet-vault/) | Local packet-capture inspection, Wi-Fi inventory and selected WPA/WPA2 wordlist checks. |
| [Wifit3](wifit3/) | Customized upstream wireless-auditing TUI with manual start/stop controls. |

Use these tools only on systems and captures you own or are authorized to assess.

## Build

Requires macOS 14+, Apple Command Line Tools, and Python 3.11+. Install Nmap, TShark/Wireshark, Aircrack-ng or a supported USB wireless adapter as needed by the individual tools. No dependencies or wordlists are bundled.

```sh
zsh scripts/build-native.sh
open "dist/Outside In.app"
open "dist/Network Mapper.app"
open "dist/Packet Vault.app"
```

Apps are built locally and ad hoc signed; they are not notarized. The build writes only into this checkout. It does not replace installed apps or change Dock settings.

Run Wifit3 with [uv](https://docs.astral.sh/uv/):

```sh
python3 scripts/fetch-firmware.py
zsh wifit3/launch.command
```

## Privacy of this source distribution

This is a new source tree with no imported Git history. It excludes API credentials, environment files, local server details, account information, real scan/capture results, recovered passwords, wordlists, logs, databases, caches, installed application bundles and Finder metadata backups. Examples use reserved documentation names and addresses. Tests generate their own synthetic data locally.

Generated artwork has had PNG text/EXIF metadata removed. Firmware blobs are excluded; a checksum-verified download helper fetches the original upstream assets when requested. Vendor license notices are preserved. Windows driver-installation executables are excluded from this macOS collection.

## Checks

```sh
zsh scripts/check.sh
python3 scripts/audit-source.py
```

The audit rejects sensitive runtime files, machine-specific home paths, private/overlay IPv4 endpoints, common credential formats and image text metadata. It is a defense against accidental inclusion, not a guarantee that every possible secret format can be recognized. Never commit a real configuration or runtime data.

## Attribution

Wifit3 is derived from [derv82/wifit3](https://github.com/derv82/wifit3), v0.6.0, licensed GPL-2.0-only. Original copyright and firmware license notices remain in the source. See [THIRD_PARTY_NOTICES.md](docs/THIRD_PARTY_NOTICES.md). Other components in this collection are also provided under GPL-2.0-only.
