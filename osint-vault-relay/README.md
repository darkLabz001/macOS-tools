# Optional OSINT Vault relay

Shared, dependency-free Python sender for Network Mapper, Packet Vault and Wifit3. Outside In uses its own Swift sender with the same external configuration format.

No endpoint or key is built in. Sync is opt-in. Copy `config/vault-config.example.json` to `~/Library/Application Support/macOS-tools/vault-config.json`, outside this checkout. Set your own HTTPS `/api/v1/ingest` URL, API key and `enabled: true`. Set file permissions to owner-only. Never commit the populated file.

Each record includes `source`, `type`, `value`, tags, an observation timestamp and allowlisted metadata. Requests use `X-API-Key` and an Idempotency-Key. Redirects are refused. Native apps package the relay as a resource and find Python through standard executable paths.

Queued metadata is stored in an owner-only SQLite database under `~/Library/Application Support/macOS-tools/OSINTVaultRelay/`. The native apps retry while open every minute; Wifit3 uses its ten-second metadata timer. Unchanged payloads are deduplicated. Errors remain visible and failed records remain queued. A lost acknowledgement can still produce a repeat if the server does not implement idempotency.

Capture bodies, recovered passwords/PINs/keys, raw handshakes, dictionaries and raw NSE output are excluded. The source distribution contains no queue or prior delivery state. Tests use reserved addresses, synthetic records and a mocked sender; they perform no server uploads.
