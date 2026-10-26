import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from wifit3.ui.screens.scanner import ScannerView
from wifit3.ui.screens.focus_v2.screen import FocusViewV2
from wifit3.wlan.array import WlanArray


class ManualControlsTests(unittest.IsolatedAsyncioTestCase):
    def scanner(self):
        array = SimpleNamespace(members=[object()], capture_enabled=False,
                                start_hopping=AsyncMock(), stop_hopping=AsyncMock())
        screen = SimpleNamespace(app=SimpleNamespace(array=array), _scan_running=False,
                                 _channel_filter=None, _sync_scan_controls=Mock(),
                                 _log_auto_crack_status_when_changed=Mock())
        return screen, array

    async def test_resume_stays_idle_until_explicit_start(self):
        screen, array = self.scanner()
        await ScannerView.on_screen_resume(screen)
        array.start_hopping.assert_not_awaited()
        self.assertFalse(array.capture_enabled)
        await ScannerView.action_start_scan(screen)
        self.assertTrue(screen._scan_running)
        self.assertTrue(array.capture_enabled)
        array.start_hopping.assert_awaited_once()

    async def test_stop_disables_capture_and_does_not_resume(self):
        screen, array = self.scanner()
        await ScannerView.action_start_scan(screen)
        await ScannerView.action_stop_scan(screen)
        await ScannerView.on_screen_resume(screen)
        self.assertFalse(screen._scan_running)
        self.assertFalse(array.capture_enabled)
        self.assertEqual(array.start_hopping.await_count, 1)

    async def test_repeated_start_does_not_create_duplicate_hoppers(self):
        screen, array = self.scanner()
        await ScannerView.action_start_scan(screen)
        await ScannerView.action_start_scan(screen)
        array.start_hopping.assert_awaited_once()

    async def test_failed_start_restores_idle_capture_state(self):
        screen, array = self.scanner()
        array.start_hopping.side_effect = RuntimeError("disconnected")
        with self.assertRaises(RuntimeError):
            await ScannerView.action_start_scan(screen)
        self.assertFalse(screen._scan_running)
        self.assertFalse(array.capture_enabled)
        array.stop_hopping.assert_awaited_once()

    async def test_no_adapter_does_not_start(self):
        screen, array = self.scanner()
        array.members = []
        await ScannerView.action_start_scan(screen)
        array.start_hopping.assert_not_awaited()
        self.assertFalse(array.capture_enabled)

    async def test_paused_capture_drops_packets_before_state_updates(self):
        array = WlanArray(capture_enabled=False)
        array._sink = Mock()
        array._dedupe = Mock()
        array._ingest(object(), object())
        array._sink.update.assert_not_called()
        array._dedupe.submit_detailed.assert_not_called()

    async def test_stop_attack_awaits_campaign_cleanup(self):
        campaign = SimpleNamespace(stop=AsyncMock())
        screen = SimpleNamespace(_controls=SimpleNamespace(current=campaign, stop=Mock()),
                                 _stop_probe=Mock(), workers=SimpleNamespace(cancel_all=Mock()),
                                 refresh_buttons=Mock(), _log=Mock())
        await FocusViewV2.action_stop_attack(screen)
        screen._controls.stop.assert_called_once()
        campaign.stop.assert_awaited_once()
        self.assertTrue(screen._pbc_user_stopped)

    async def test_scanner_ui_mounts_idle_with_visible_controls(self):
        from wifit3.ui.app import WifiteApp
        from textual.widgets import Button
        app = WifiteApp(cli_log_level="unset")
        app.device_watch.poll = lambda: None
        async with app.run_test(size=(120, 40)) as pilot:
            app.array = WlanArray(capture_enabled=False)
            await app.push_screen("scanner")
            await pilot.pause()
            self.assertFalse(app.screen._scan_running)
            self.assertFalse(app.screen.query_one("#start-scan", Button).disabled)
            self.assertTrue(app.screen.query_one("#stop-scan", Button).disabled)
            self.assertFalse(app.array.capture_enabled)

    async def test_target_controls_mount_without_starting_a_campaign(self):
        from wifit3.ui.app import WifiteApp
        from wifit3.models import AccessPoint
        from textual.widgets import Button
        app = WifiteApp(cli_log_level="unset")
        app.device_watch.poll = lambda: None
        async with app.run_test(size=(120, 40)) as pilot:
            app.array = WlanArray(capture_enabled=False)
            app.target_ap = AccessPoint(bssid="02:00:00:00:00:01", ssid="Test fixture",
                                        channel=1, encryption="WPA2")
            await app.push_screen("focus")
            await pilot.pause()
            self.assertIsNotNone(app.screen.query_one("#stop-attack", Button))
            self.assertIsNone(app.screen._controls.current)
            self.assertFalse(app.pbc_enabled)
            await pilot.click("#stop-attack")
            await pilot.pause()
            self.assertIsNone(app.screen._controls.current)


if __name__ == "__main__":
    unittest.main()
