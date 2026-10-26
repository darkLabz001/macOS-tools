# Wifit3 for macOS

Source copy of [Wifit3 v0.6.0](https://github.com/derv82/wifit3) with manual scanning controls and optional structured Vault export. Original GPL-2.0-only and firmware notices are preserved.

```sh
python3 ../scripts/fetch-firmware.py
zsh launch.command
```

The launcher uses uv and Python 3.12 to install the project's declared dependencies. A supported USB wireless adapter and any applicable OS USB authorization are required for radio operation.

- Connecting an adapter leaves scanning idle.
- **Start scan** starts scanning; **Stop scan** stops it and retains displayed results.
- Target actions are selected manually. Automatic WPS PBC and automatic cracking are disabled in this customized copy.
- **Stop attack** cancels a running campaign and waits for cleanup.

The repository includes no captures, recovered keys, device-specific configuration, account data, locally extracted runtime, packaged upstream executable or Windows driver installers. Firmware is excluded and can be fetched with the checksum-verified helper above. Vendor notices are original upstream distribution assets.

Vault export sends allowlisted access-point metadata every ten seconds while the scanner screen is mounted. It does not start scanning or attacks, and it does not export keys, PINs, handshakes or capture contents. It is disabled until a user opts in with their own external configuration. The launcher makes the sibling relay module importable.

`test_manual_controls.py` uses mocked hardware and headless UI checks. Real device behavior depends on chipset/OS support and must be assessed separately.
