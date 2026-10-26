# macOS-tools

Clean source copies of **Outside In**, **Network Mapper**, **Packet Vault**, and **Wifit3**, with their shared optional Vault relay.

Download [macOS-tools-source.zip](macOS-tools-source.zip), extract it, and follow the included README. The package contains all four source directories, artwork, build scripts, tests, licenses, an inert configuration template and a privacy-audit script. It contains no Git metadata or original history.

```sh
unzip macOS-tools-source.zip
cd macOS-tools
zsh scripts/build-native.sh
```

The audited source package is distributed as a ZIP because command-line Git access was unavailable in the publishing environment. SHA-256 verification is provided in [SHA256SUMS.txt](SHA256SUMS.txt).

Server sync is **disabled by default**. Supply your own HTTPS endpoint and credentials outside the checkout if you choose to enable it. No real credentials, personal paths, private server details, captures, logs, scan results, databases, wordlists or recovered passwords are included. Tests use synthetic fixtures. Firmware is downloaded separately with checksum verification.

See [SANITIZATION.md](SANITIZATION.md) for the performed checks and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for upstream attribution. GPL-2.0-only, with separately licensed firmware notices retained in the source.
