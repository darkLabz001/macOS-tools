# Source-distribution checks

This distribution was assembled from an explicit source-file allowlist in a new repository. No original Git history, installed app bundles, runtime folders or system configuration were imported.

Checks performed:

- Source scan for personal home-directory paths, overlay-network addresses, common credential formats, private keys and blocked runtime files: passed.
- Exact-match comparison against the local integration credential, destination and known personal identifiers, without exporting those comparison values: zero matches.
- PNG text/EXIF metadata removed; icon PNG representations cleaned.
- Firmware blobs and Windows executables excluded. Original upstream firmware checksums and vendor license notices retained.
- Server addresses and credentials replaced by an inert example configuration. Sync requires explicit enablement and user-supplied HTTPS credentials stored outside the checkout.
- Runtime paths isolated from the existing installed tools. No private case, scan or capture data is migrated.
- Original licenses and public upstream attribution preserved.

Validation: native app builds, 18 Outside In core checks, nine relay tests, eleven mocked Wifit3 control/export checks, Nmap worker fixtures, native self-tests and synthetic packet-capture checks passed. Tests do not use real targets, captures or radio hardware.

The source package contains synthetic test names, documentation addresses and deliberately known test passwords. These are test fixtures, not credentials from an installation. Generated output, populated configurations and caches are excluded by the repository ignore rules.

Run `python3 scripts/audit-source.py` before committing future changes. Keep real credentials and runtime data outside version control.
