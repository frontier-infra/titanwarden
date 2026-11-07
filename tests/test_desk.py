from __future__ import annotations

import json
import unittest
from pathlib import Path

from tw.desk import classify_answer


class DeskFixtureTests(unittest.TestCase):
    def fixture(self, name: str) -> dict:
        path = Path(__file__).with_name("fixtures") / name
        return json.loads(path.read_text(encoding="utf-8"))[0]

    def test_unsigned_operator_approval_is_advisory(self) -> None:
        decision = classify_answer(self.fixture("desk_answered.json"))
        self.assertEqual(decision.decision, "approve")
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.reason, "unsigned_approval_advisory")

    def test_signed_operator_approval_is_accepted(self) -> None:
        decision = classify_answer(
            self.fixture("desk_answered.json"), signed_answers=True, signature_valid=True
        )
        self.assertTrue(decision.accepted)

    def test_agent_default_is_not_answer(self) -> None:
        decision = classify_answer(self.fixture("desk_defaulted.json"))
        self.assertIsNone(decision.decision)
        self.assertFalse(decision.accepted)

    def test_relayed_operator_is_rejected(self) -> None:
        item = self.fixture("desk_answered.json")
        item["thread"][0]["author"] = "Operator (via Claude)"
        decision = classify_answer(item, signed_answers=True, signature_valid=True)
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.reason, "not_direct_operator")


if __name__ == "__main__":
    unittest.main()
