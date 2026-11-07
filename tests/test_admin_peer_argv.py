"""Check peer grammar against the shipped launchd artifact, without a broker."""
from __future__ import annotations

import plistlib
import unittest
from pathlib import Path
from unittest import mock

from tw.admin import verify_broker_peer


class BrokerPeerArgvTests(unittest.TestCase):
    def setUp(self):
        plist = Path(__file__).resolve().parents[1] / "launchd/org.frontierinfra.titanwarden.plist"
        self.shipped = plistlib.loads(plist.read_bytes())["ProgramArguments"]
        self.home = Path(self.shipped[self.shipped.index("--home") + 1]).resolve()
        self.console = ["--console-config", str(self.home / "console/config.json"),
                        "--console-rp-id", "broker.fixture.ts.net",
                        "--console-user", "human@example.test"]

    def verify(self, argv, *, pid=123, launchd_pid=123):
        with mock.patch("tw.admin.peer_pid", return_value=pid), \
                mock.patch("tw.admin.service_broker_pid", return_value=launchd_pid), \
                mock.patch("tw.admin.broker_argv", return_value=argv):
            return verify_broker_peer(mock.Mock(), self.home)

    def test_exact_shipped_production_plist_argv_is_accepted(self):
        self.assertTrue(self.verify(self.shipped))

    def test_exact_shipped_plist_with_console_suffix_is_accepted(self):
        self.assertTrue(self.verify(self.shipped + self.console))

    def test_desk_values_are_configuration_not_fixed_master_identity(self):
        argv = self.shipped.copy()
        argv[argv.index("--desk-identity") + 1] = "lead-titanwarden"
        argv[argv.index("--desk-project") + 1] = "titanwarden"
        self.assertTrue(self.verify(argv + self.console))

    def test_existing_bare_and_console_only_forms_are_preserved(self):
        self.assertTrue(self.verify(self.shipped[:5]))
        self.assertTrue(self.verify(self.shipped[:5] + self.console))

    def test_reordered_shipped_flags_are_accepted(self):
        self.assertTrue(self.verify(self.shipped[:3] + self.shipped[5:] + self.shipped[3:5]))
        self.assertTrue(self.verify(self.shipped[:3] + self.console + self.shipped[5:] + self.shipped[3:5]))

    def test_missing_duplicate_and_unknown_desk_flags_are_rejected(self):
        base = self.shipped[:5]
        for suffix in (["--desk-identity", "master"], ["--desk-project", "master"],
                       self.shipped[5:] * 2, ["--desk-identity", "--desk-project", "master"],
                       ["--desk-identity", "master", "--unknown", "master"]):
            self.assertFalse(self.verify(base + suffix), repr(suffix))

    def test_squatter_wrong_home_and_trailing_arguments_are_rejected(self):
        for argv in ([self.shipped[0], "squatter.py"] + self.shipped[1:],
                     self.shipped[:4] + ["/agent/chosen-home"] + self.shipped[5:],
                     self.shipped + ["--extra"], self.shipped + self.console + ["--extra"]):
            self.assertFalse(self.verify(argv), repr(argv))

    def test_arbitrary_config_is_rejected_and_reordered_console_flags_are_accepted(self):
        bad_path = self.console.copy()
        bad_path[1] = "/agent/chosen.json"
        self.assertFalse(self.verify(self.shipped + bad_path))
        self.assertTrue(self.verify(self.shipped + self.console[2:] + self.console[:2]))

    def test_duplicate_home_module_console_and_desk_flags_are_rejected(self):
        for extra in (["--home", str(self.home)], ["-m", "tw.broker"],
                      ["--console-user", "other@example.test"],
                      ["--desk-project", "master"]):
            self.assertFalse(self.verify(self.shipped + self.console + extra), repr(extra))

    def test_partial_console_flag_sets_are_rejected(self):
        self.assertFalse(self.verify(self.shipped + self.console[:2]))
        self.assertFalse(self.verify(self.shipped + self.console[2:]))

    def test_non_tailnet_and_malformed_rp_ids_are_rejected(self):
        for rp in ("example.com", "localhost", "broker.ts.net", "broker.fixture.ts.net/evil",
                   "Broker.fixture.ts.net", "broker.fixture.ts.net:8443"):
            suffix = self.console.copy()
            suffix[3] = rp
            self.assertFalse(self.verify(self.shipped + suffix), rp)

    def test_out_of_range_and_control_character_user_strings_are_rejected(self):
        for user in ("", "x" * 255, "human name", "human\n@example.test", "hum\u00e1n@example.test"):
            suffix = self.console.copy()
            suffix[5] = user
            self.assertFalse(self.verify(self.shipped + suffix), repr(user))

    def test_missing_or_wrong_launchd_pid_and_missing_argv_still_fail_closed(self):
        self.assertFalse(self.verify(self.shipped, pid=124))
        self.assertFalse(self.verify(self.shipped, launchd_pid=None))
        self.assertFalse(self.verify(self.shipped, pid=None))
        self.assertFalse(self.verify(None))


if __name__ == "__main__":
    unittest.main()
