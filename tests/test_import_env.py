import hashlib
import json
import os
import secrets
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from tw.importers.envfile import EnvImportError, EnvImporter, parse_manifest


class MemorySink:
    def __init__(self):
        self.by_fingerprint = {}
        self.stored = []
        self.quarantines = []

    def store(self, path, value, source):
        fingerprint = hashlib.sha256(value).digest()
        existing = self.by_fingerprint.get(fingerprint)
        if existing is not None:
            return {"path": path, "version_no": existing[1], "linked_to": existing[0]}
        version = len(self.stored) + 1
        self.by_fingerprint[fingerprint] = (path, version)
        self.stored.append((path, value, source))
        return {"path": path, "version_no": version}

    def quarantine(self, project, original_path, payload):
        self.quarantines.append((project, original_path, payload))
        return "qua_test"

    def matches(self, value):
        return hashlib.sha256(value).digest() in self.by_fingerprint


class EnvImporterTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(dir="/tmp", prefix="twenv")
        self.root = Path(self.tempdir.name)
        self.sink = MemorySink()
        policy_path = self.root / "policies.json"
        policy_path.write_text(
            json.dumps(
                {
                    "client": {
                        "change_policy": "client_approval_required",
                        "force_class": "restricted",
                        "import_env": "refuse",
                        "repo_patterns": ["example-org/client-app"],
                        "path_roots": [str(self.root / "client-root")],
                    }
                }
            )
        )
        self.importer = EnvImporter(
            policy_path,
            store_value=self.sink.store,
            store_quarantine=self.sink.quarantine,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_imports_values_skips_placeholders_links_duplicates_and_writes_manifest(self):
        first = secrets.token_urlsafe(32)
        second = secrets.token_urlsafe(32)
        source = self.root / ".env"
        source.write_text(
            f"API_TOKEN={first}\nSECOND_TOKEN='{second}'\nDUPLICATE={first}\n"
            "EMPTY=\nPLACEHOLDER=changeme\nANGLE=<required>\n"
        )
        os.chmod(source, 0o644)
        result = self.importer.import_file(source, "alpha")
        self.assertEqual(result["quarantine_id"], "qua_test")
        self.assertEqual([item["name"] for item in result["stored"]], [
            "api-token", "second-token", "duplicate"
        ])
        self.assertEqual(set(result["skipped"]), {"EMPTY", "PLACEHOLDER", "ANGLE"})
        self.assertEqual(len(self.sink.stored), 2)
        self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o600)
        manifest = self.root / ".env.tw"
        self.assertEqual(
            manifest.read_text().splitlines(),
            [
                "API_TOKEN=tw://alpha/api-token",
                "SECOND_TOKEN=tw://alpha/second-token",
                "DUPLICATE=tw://alpha/api-token",
            ],
        )
        self.assertEqual(self.sink.quarantines[0][2], source.read_bytes())

    def test_fo_project_refusal_leaves_file_untouched(self):
        self._assert_refusal(project="client", location=self.root / "project.env")

    def test_fo_path_root_refusal_leaves_file_untouched(self):
        self._assert_refusal(project="alpha", location=self.root / "client-root" / ".env")

    def test_fo_git_origin_refusal_leaves_file_untouched(self):
        repo = self.root / "repo"
        repo.mkdir()
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "remote",
                "add",
                "origin",
                "git@example.invalid:example-org/client-app.git",
            ],
            check=True,
        )
        self._assert_refusal(project="alpha", location=repo / ".env")

    def test_fo_git_origin_match_is_case_insensitive(self):
        repo = self.root / "lowercase-repo"
        repo.mkdir()
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "remote",
                "add",
                "origin",
                "git@example.invalid:EXAMPLE-ORG/CLIENT-APP.git",
            ],
            check=True,
        )
        self._assert_refusal(project="alpha", location=repo / ".env")

    def test_symlink_source_is_refused_before_read(self):
        real = self.root / "real.env"
        real.write_text("TOKEN=fake-test-value-only\n")
        link = self.root / "linked.env"
        link.symlink_to(real)
        with self.assertRaises(EnvImportError) as caught:
            self.importer.import_file(link, "alpha")
        self.assertEqual(caught.exception.code, "E_POLICY")
        self.assertFalse(link.with_name(".env.tw").exists())

    def test_symlinked_parent_directory_is_refused_before_read(self):
        real_repo = self.root / "real-repo"
        real_repo.mkdir()
        source = real_repo / ".env"
        source.write_text("TOKEN=fake-test-value-only\n")
        linked_repo = self.root / "linked-repo"
        linked_repo.symlink_to(real_repo, target_is_directory=True)
        with self.assertRaises(EnvImportError) as caught:
            self.importer.import_file(linked_repo / ".env", "alpha")
        self.assertEqual(caught.exception.code, "E_POLICY")
        self.assertFalse(real_repo.joinpath(".env.tw").exists())

    def _assert_refusal(self, project, location):
        location.parent.mkdir(parents=True, exist_ok=True)
        payload = secrets.token_urlsafe(32).encode()
        location.write_bytes(b"TOKEN=" + payload + b"\n")
        os.chmod(location, 0o640)
        before = (location.read_bytes(), location.stat().st_mode, location.stat().st_mtime_ns)
        with self.assertRaises(EnvImportError) as caught:
            self.importer.import_file(location, project)
        self.assertEqual(caught.exception.code, "E_POLICY")
        after = (location.read_bytes(), location.stat().st_mode, location.stat().st_mtime_ns)
        self.assertEqual(after, before)
        self.assertFalse(location.with_name(".env.tw").exists())
        self.assertEqual(self.sink.stored, [])
        self.assertEqual(self.sink.quarantines, [])

    def test_manifest_refuses_literal_matching_stored_value(self):
        value = secrets.token_urlsafe(32).encode()
        self.sink.store("alpha/key", value, "put")
        manifest = self.root / ".env.tw"
        manifest.write_bytes(b"SAFE=tw://alpha/key\nBAD=" + value + b"\n")
        with self.assertRaises(EnvImportError) as caught:
            parse_manifest(manifest, self.sink.matches)
        self.assertEqual(caught.exception.code, "E_POLICY")
        self.assertIn("line 2", str(caught.exception))
        self.assertNotIn(value.decode(), str(caught.exception))


if __name__ == "__main__":
    unittest.main()
