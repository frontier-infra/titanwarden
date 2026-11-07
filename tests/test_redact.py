import base64
import json
import os
import secrets
import re
import time
import unittest
from urllib.parse import quote_from_bytes, quote_plus

from tw.redact import Redactor, build_patterns, scrub_text


class RedactorTests(unittest.TestCase):
    def setUp(self):
        self.value = secrets.token_urlsafe(40).encode()
        self.other = secrets.token_urlsafe(40).encode()
        self.redactor = Redactor(
            build_patterns(
                {
                    "alpha/allowed": self.value,
                    "beta/hidden": self.other,
                },
                visible_paths={"alpha/allowed"},
            )
        )

    def test_supported_encodings_and_scoped_markers(self):
        variants = [
            self.value,
            base64.b64encode(self.value),
            base64.b64encode(self.value).rstrip(b"="),
            base64.urlsafe_b64encode(self.value),
            base64.urlsafe_b64encode(self.value).rstrip(b"="),
            self.value.hex().encode(),
            self.value.hex().upper().encode(),
            quote_from_bytes(self.value).encode(),
            re.sub(
                rb"%[0-9A-F]{2}",
                lambda match: match.group(0).lower(),
                quote_from_bytes(self.value).encode(),
            ),
            json.dumps(self.value.decode("latin1"))[1:-1].encode(),
        ]
        for variant in variants:
            with self.subTest(length=len(variant)):
                output = self.redactor.redact(b"before:" + variant + b":after")
                self.assertEqual(output, b"before:[tw:alpha/allowed]:after")

        output = self.redactor.redact(b"before:" + self.other + b":after")
        self.assertEqual(output, b"before:[tw:redacted]:after")
        self.assertNotIn(b"beta/hidden", output)

    def test_strict_percent_plus_and_json_slash_encodings(self):
        value = b"long secret/with spaces+slash"
        redactor = Redactor(build_patterns({"alpha/key": value}, {"alpha/key"}))
        variants = (
            quote_from_bytes(value, safe="").encode(),
            quote_plus(value, safe="").encode(),
            json.dumps(value.decode())[1:-1].encode().replace(b"/", b"\\/"),
        )
        for variant in variants:
            with self.subTest(variant=variant):
                self.assertEqual(redactor.redact(variant), b"[tw:alpha/key]")

    def test_streaming_matches_across_one_byte_writes(self):
        stream = self.redactor.stream()
        output = b"".join(stream.feed(bytes((byte,))) for byte in self.value)
        output += stream.finish()
        self.assertEqual(output, b"[tw:alpha/allowed]")
        self.assertEqual(stream.count, 1)

    def test_embedded_base64_is_caught_at_each_alignment(self):
        for prefix_length in range(3):
            encoded = base64.b64encode(b"x" * prefix_length + self.value + b"tail")
            with self.subTest(prefix_length=prefix_length):
                output = self.redactor.redact(encoded)
                self.assertIn(b"[tw:alpha/allowed]", output)
                self.assertNotIn(self.value, output)

    def test_short_values_are_excluded_and_non_secret_output_is_identical(self):
        patterns = build_patterns({"alpha/short": b"1234567"}, {"alpha/short"})
        redactor = Redactor(patterns)
        payload = b"plain output and 1234567 stay unchanged"
        self.assertEqual(redactor.redact(payload), payload)

    def test_scrubber_marks_and_replaces_matches(self):
        text = "reason:" + self.value.decode()
        scrubbed, changed = scrub_text(text, self.redactor)
        self.assertTrue(changed)
        self.assertNotIn(self.value.decode(), scrubbed)
        self.assertIn("[tw:alpha/allowed]", scrubbed)

    def test_throughput_with_one_thousand_values(self):
        values = {f"test/value-{index}": os.urandom(32) for index in range(1000)}
        redactor = Redactor(build_patterns(values, set(values)))
        selected = values["test/value-500"]
        payload = (b"ordinary output " * 65536) + selected
        started = time.perf_counter()
        output = redactor.redact(payload)
        elapsed = time.perf_counter() - started
        throughput = len(payload) / max(elapsed, 1e-9)
        # Throughput is reported only. A wall-clock gate measured the install, not the
        # redactor: the one failure seen (1,627,057 bytes/s) was the compiled-trie regex
        # fallback on a venv without pyahocorasick, and no single threshold fits both
        # backends (the automaton runs this fixture about 15x faster than the fallback).
        print(
            f"\nredact throughput {throughput / (1024 * 1024):.1f} MiB/s over "
            f"{len(payload)} bytes ({elapsed * 1000:.1f} ms); reported, not gated"
        )
        self.assertNotIn(selected, output)

    def test_the_fast_backend_is_the_one_in_use(self):
        # pyahocorasick is a declared dependency, so the compiled-trie regex fallback
        # must never run. The fallback is about 15x slower on this fixture (1.6 MiB/s
        # against 25 MiB/s), which would silently slow every redaction in a credential
        # vault. A venv without the package is a broken install, not a slow machine,
        # so this replaces what the old wall-clock throughput gate was accidentally
        # checking.
        import ahocorasick

        values = {f"test/value-{index}": os.urandom(32) for index in range(10)}
        redactor = Redactor(build_patterns(values, set(values)))
        self.assertIsNotNone(
            redactor._automaton,
            "Redactor built the regex fallback: pyahocorasick is missing",
        )
        self.assertIsInstance(redactor._automaton, ahocorasick.Automaton)
        self.assertIsNone(redactor._regex)


if __name__ == "__main__":
    unittest.main()
