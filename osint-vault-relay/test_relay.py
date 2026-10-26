import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
import urllib.error

import vault_relay as relay


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps({"enabled": True, "endpoint": "https://vault.example/api/v1/ingest", "apiKey": "test-only"}))
        self.record = relay.record("network-mapper", "ip", "192.0.2.1", {"ports": []}, ["test"])

    def tearDown(self):
        self.directory.cleanup()

    def test_retry_survives_failure_and_deduplicates(self):
        self.assertEqual(relay.enqueue([self.record], self.root), 1)
        self.assertEqual(relay.enqueue([self.record], self.root), 0)
        failed = Mock(side_effect=TimeoutError())
        self.assertEqual(relay.flush(self.root, self.config, failed)["pending"], 1)
        delivered = Mock()
        self.assertEqual(relay.flush(self.root, self.config, delivered)["sent"], 1)
        self.assertEqual(relay.enqueue([self.record], self.root), 0)
        self.assertEqual(relay.flush(self.root, self.config, delivered)["pending"], 0)
        self.assertEqual(delivered.call_count, 1)
        body = json.loads(delivered.call_args.args[0])
        self.assertIn("observed_at", body["metadata"])
        self.assertNotIn("apiKey", body)

    def test_bad_record_does_not_block_other_records(self):
        second = dict(self.record, value="192.0.2.2")
        relay.enqueue([self.record, second], self.root)
        failure = urllib.error.HTTPError("https://vault.example/api/v1/ingest", 422, "bad record", {}, None)
        result = relay.flush(self.root, self.config, Mock(side_effect=[failure, None]))
        self.assertEqual(result["pending"], 1)
        self.assertEqual(result["sent"], 1)

    def test_missing_configuration_preserves_queue(self):
        relay.enqueue([self.record], self.root)
        result = relay.flush(self.root, self.root / "missing.json", Mock())
        self.assertEqual(result["pending"], 1)
        self.assertIn("unavailable", result["error"])

    def test_payload_change_is_new_observation(self):
        relay.enqueue([self.record], self.root)
        changed = dict(self.record, metadata={"ports": [443]})
        relay.enqueue([changed], self.root)
        self.assertEqual(relay.status(self.root)["pending"], 2)

    def test_mapper_allowlist_preserves_services(self):
        rows = relay.mapper_records({"hosts": [{"address": "192.0.2.1", "name": "test.example", "scripts": ["password: secret"], "ports": [{"number": "443", "proto": "tcp", "state": "open", "service": "https", "version": "Test", "scripts": ["secret"]}]}]})
        self.assertEqual(rows[0]["source"], "network-mapper")
        self.assertEqual(rows[0]["metadata"]["ports"][0]["service"], "https")
        self.assertNotIn("secret", json.dumps(rows))

    def test_packet_endpoint_port_direction(self):
        rows = relay.packet_endpoint_records({"capture": "/private/capture.pcap", "rows": "192.0.2.1\t192.0.2.2\t\t\t54321\t443\t\t\tTLS\n"})
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["metadata"]["observed_transport_ports_in_frames"], ["54321/tcp"])
        self.assertEqual(rows[1]["metadata"]["observed_transport_ports_in_frames"], ["443/tcp"])
        self.assertEqual(rows[0]["metadata"]["capture_name"], "capture.pcap")

    def test_wifi_excludes_recovered_material(self):
        ap = {"bssid": "02:11:22:33:44:55", "ssid": "Fixture", "channel": 6, "wps_pin": "12345678", "wps_pin_psk": "secret", "wep_key": "secret", "handshakes": {"secret": "secret"}}
        wifi = relay.wifi_records([ap])
        packet = relay.packet_wifi_records({"targets": [dict(ap, handshakeCandidate=True, readiness="Candidate")]})
        self.assertEqual(wifi[0]["source"], "wifit3")
        self.assertEqual(packet[0]["source"], "packet-vault")
        self.assertNotIn("secret", json.dumps(wifi + packet))
        self.assertEqual(wifi[0]["type"], "access_point")

    def test_redirect_is_not_followed(self):
        self.assertIsNone(relay.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.example"))

    def test_config_and_source_validation(self):
        with self.assertRaises(ValueError):
            relay.enqueue([dict(self.record, source="unknown")], self.root)
        with self.assertRaises(ValueError):
            relay.send("{}", "id", {"endpoint": "http://other.example", "apiKey": "test-only"})


if __name__ == "__main__":
    unittest.main()
