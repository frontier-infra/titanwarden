from __future__ import annotations

import ipaddress
import plistlib
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]


class RepositoryTests(unittest.TestCase):
    def test_no_unicode_dashes(self) -> None:
        tracked = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
        ).stdout.split(b"\0")
        for relative in tracked:
            if not relative:
                continue
            path = ROOT / relative.decode("utf-8", "surrogateescape")
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            self.assertNotIn("\N{EM DASH}", text, str(path))
            self.assertNotIn("\N{EN DASH}", text, str(path))

    def test_workflow_uses_hosted_runners(self) -> None:
        workflow = (ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")
        self.assertNotIn("self-hosted", workflow)
        self.assertIn("ubuntu-latest", workflow)
        self.assertIn("macos-latest", workflow)

    def test_public_docs_have_no_private_infrastructure(self) -> None:
        for path in (ROOT / "docs/support").glob("*"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(".ts.net", text)
            self.assertNotIn("run_", text)
            for token in text.replace("/", " ").split():
                try:
                    address = ipaddress.ip_address(token.strip("`.,:()[]"))
                except ValueError:
                    continue
                self.assertNotIn(address, ipaddress.ip_network("100.64.0.0/10"))

    def test_plist_paths_are_absolute(self) -> None:
        for path in (ROOT / "launchd").glob("*.plist"):
            data = plistlib.loads(path.read_bytes())
            arguments = data["ProgramArguments"]
            self.assertTrue(arguments[0].startswith("/"), str(path))
            for key in ("StandardOutPath", "StandardErrorPath"):
                self.assertTrue(data[key].startswith("/"), str(path))

    def test_gitleaks_token_rule_exists(self) -> None:
        self.assertIn("twt_", (ROOT / ".gitleaks.toml").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
