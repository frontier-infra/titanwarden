from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tw import backup as backup_module
from tw.backup import backup, file_sha256

from support import initialized_store


class BackupTests(unittest.TestCase):
    def test_online_backup_and_external_checksum(self) -> None:
        temporary, store, _master, _recovery = initialized_store()
        self.addCleanup(temporary.cleanup)
        store.close()
        external_temp = tempfile.TemporaryDirectory(prefix="tw-external", dir="/tmp")
        self.addCleanup(external_temp.cleanup)
        internal, external = backup(store.home, Path(external_temp.name))
        self.assertTrue(internal.exists())
        self.assertIsNotNone(external)
        assert external is not None
        self.assertEqual(file_sha256(internal), file_sha256(external))
        self.assertTrue(internal.with_suffix(".manifest.json").exists())
        self.assertTrue((Path(external_temp.name) / internal.with_suffix(".manifest.json").name).exists())
        self.assertEqual([], list(Path(external_temp.name).glob(".*.tmp")))

    def test_external_timeout_keeps_internal_copy_and_fails(self) -> None:
        temporary, store, _master, _recovery = initialized_store()
        self.addCleanup(temporary.cleanup)
        store.close()
        external_temp = tempfile.TemporaryDirectory(prefix="tw-external", dir="/tmp")
        self.addCleanup(external_temp.cleanup)
        with mock.patch.object(backup_module, "EXTERNAL_TIMEOUT", 0.001):
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                backup(store.home, Path(external_temp.name))
            with mock.patch.object(backup_module, "alert") as alert:
                code = backup_module.main(["--home", str(store.home), "--external", external_temp.name, "--alert"])
        self.assertEqual(1, code)
        alert.assert_called_once()
        self.assertTrue(list((store.home / "backups").glob("tw-*.db")))
        self.assertEqual([], list(Path(external_temp.name).glob("tw-*.db")))

    def test_alert_posts_once_then_notes_the_open_item(self) -> None:
        calls: list[list[str]] = []
        listed: list[dict[str, object]] = []

        def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, json.dumps(listed) if "list" in command else "", "")

        with mock.patch.object(backup_module.subprocess, "run", fake_run):
            listed[:] = [{"id": 1, "title": "something else"}]
            backup_module.alert("first")
            listed[:] = [{"id": 7, "title": backup_module.ALERT_TITLE}]
            backup_module.alert("second")
        self.assertEqual("action", calls[1][3])
        self.assertEqual(["update", "7", "--note", "second"], calls[3][3:])


if __name__ == "__main__":
    unittest.main()
