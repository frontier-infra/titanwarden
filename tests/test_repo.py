from __future__ import annotations

import ipaddress
import plistlib
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/test.yml"


def tracked_texts():
    """Yield (path, text) for every git-tracked file that decodes as UTF-8."""
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
        yield path, text


class RepositoryTests(unittest.TestCase):
    def test_no_unicode_dashes(self) -> None:
        for path, text in tracked_texts():
            self.assertNotIn("\N{EM DASH}", text, str(path))
            self.assertNotIn("\N{EN DASH}", text, str(path))

    def test_no_private_contact_domains(self) -> None:
        # Assembled at runtime so this file never contains the strings it forbids.
        forbidden = ("myagents" + ".email", "titaniumcomputing" + ".com")
        for path, text in tracked_texts():
            for needle in forbidden:
                self.assertNotIn(needle, text, str(path))

    def test_workflow_uses_blacksmith_runners(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("self-hosted", workflow)
        hosted = re.findall(r"(?<![a-z0-9-])(?:ubuntu|macos|windows)-(?:latest|[0-9][0-9.]*)\b", workflow)
        self.assertEqual(hosted, [], workflow)
        self.assertIn("blacksmith-4vcpu-ubuntu-2404", workflow)
        self.assertIn("blacksmith-6vcpu-macos-15", workflow)

    def test_workflow_pins_actions_to_commits(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        actions = re.findall(r"^\s*-?\s*uses:\s*(\S+)", workflow, re.M)
        self.assertTrue(actions)
        for action in actions:
            self.assertRegex(action, r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")

    def test_workflow_uses_no_secrets(self) -> None:
        self.assertNotIn("secrets.", WORKFLOW.read_text(encoding="utf-8"))

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
