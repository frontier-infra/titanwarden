"""Names-only Desk integration.

Captured 2026-10-09 fixture shape: a list of items. Item fields include id,
status, options, done_by, requested_by, resolution, resolution_kind, and thread.
Thread entries include id, item_id, kind, text, author, author_kind, owner,
created_at, delivered_at, and status_changed. Decisions use only ``kind``,
``author``, ``author_kind``, and ``text``. Item or thread text must never carry a
secret value.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# The Desk display name whose direct, signed answers count as decisions.
OPERATOR_NAME = os.environ.get("TW_DESK_OPERATOR", "Operator")


class DeskError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DeskDecision:
    decision: str | None
    accepted: bool
    reason: str
    author: str | None = None


class DeskClient:
    def __init__(
        self,
        *,
        identity: str = "lead-titanwarden",
        project: str = "titanwarden",
        executable: str = "desk",
    ) -> None:
        self.identity = identity
        self.project = project
        self.executable = executable

    def _run(self, *arguments: str, json_output: bool = False) -> Any:
        command = [self.executable, "--as", self.identity, *arguments]
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
        )
        if completed.returncode != 0:
            raise DeskError(f"desk command failed: {' '.join(arguments[:2])}")
        if not json_output:
            return completed.stdout.strip()
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise DeskError("desk returned invalid JSON") from exc

    def blocker(self, title: str, body: str, *, urgent: bool = False) -> str:
        args = ["blocker", self.project, title, "--body", body]
        if urgent:
            args.append("--urgent")
        return str(self._run(*args))

    def ask(
        self,
        title: str,
        body: str,
        *,
        options: tuple[str, ...] = ("Approve", "Deny"),
        recommend: int | None = 1,
    ) -> str:
        args = ["ask", self.project, title, "--body", body]
        for option in options:
            args.extend(("--option", option))
        if recommend is not None:
            args.extend(("--recommend", str(recommend)))
        return str(self._run(*args))

    def action(self, title: str, body: str) -> str:
        return str(self._run("action", self.project, title, "--body", body))

    def info(self, title: str, body: str) -> str:
        return str(self._run("info", self.project, title, "--body", body))

    def outcome(self, text: str) -> str:
        return str(self._run("outcome", self.project, text))

    def default(self, item_id: str | int, decision: str) -> str:
        return str(self._run("default", str(item_id), "--took", decision))

    def done(self, item_id: str | int, note: str | None = None) -> str:
        args = ["done", str(item_id)]
        if note:
            args.extend(("--note", note))
        return str(self._run(*args))

    def items(self) -> list[dict[str, Any]]:
        result = self._run("list", "--all", "--json", "--project", self.project, json_output=True)
        if not isinstance(result, list):
            raise DeskError("desk item list has unexpected shape")
        return [item for item in result if isinstance(item, dict)]


def classify_answer(
    item: dict[str, Any],
    *,
    signed_answers: bool = False,
    signature_valid: bool = False,
) -> DeskDecision:
    """Classify the newest actual answer, rejecting relay and agent entries."""

    thread = item.get("thread")
    if not isinstance(thread, list):
        return DeskDecision(None, False, "missing_thread")
    entries = [
        entry
        for entry in thread
        if isinstance(entry, dict) and entry.get("kind") in {"answer", "approve"}
    ]
    if not entries:
        return DeskDecision(None, False, "no_answer")
    entry = entries[-1]
    author = str(entry.get("author", ""))
    author_kind = entry.get("author_kind")
    if author_kind != "person":
        return DeskDecision(None, False, "agent_answer", author)
    if author != OPERATOR_NAME:
        return DeskDecision(None, False, "not_direct_operator", author)
    text = str(entry.get("text", "")).strip().lower()
    if text.startswith("deny") or text.startswith("reject"):
        return DeskDecision("deny", True, "direct_operator_denial", author)
    if not text.startswith("approve"):
        return DeskDecision(None, False, "unknown_answer", author)
    if not signed_answers:
        return DeskDecision("approve", False, "unsigned_approval_advisory", author)
    if not signature_valid:
        return DeskDecision("approve", False, "invalid_signature", author)
    return DeskDecision("approve", True, "signed_direct_operator_approval", author)

