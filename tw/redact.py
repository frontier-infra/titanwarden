"""Streaming, whole-store output redaction.

The redactor intentionally works on bytes. Child output is not guaranteed to be
UTF-8, while secret values and their encoded forms are byte sequences.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Iterable, Mapping
from urllib.parse import quote_from_bytes, quote_plus

try:
    import ahocorasick
except ImportError:  # pragma: no cover - exercised only in minimal bootstrap environments
    ahocorasick = None


@dataclass(frozen=True)
class Pattern:
    encoded: bytes
    marker: bytes


def _json_escape(value: bytes) -> bytes:
    text = value.decode("latin1")
    return json.dumps(text, ensure_ascii=True)[1:-1].encode("ascii")


def _base64_cores(value: bytes, encoder) -> Iterable[bytes]:
    for alignment in range(3):
        prefix = b"\x00" * alignment
        encoded = encoder(prefix + value + b"\x00\x00")
        start = ((alignment + 2) // 3) * 4
        end = ((alignment + len(value)) // 3) * 4
        core = encoded[start:end]
        if len(core) >= 8:
            yield core


def _encodings(value: bytes) -> set[bytes]:
    standard = base64.b64encode(value)
    urlsafe = base64.urlsafe_b64encode(value)
    percent = quote_from_bytes(value, safe="").encode("ascii")
    plus = quote_plus(value, safe="").encode("ascii")
    json_escaped = _json_escape(value)
    variants = {
        value,
        standard,
        standard.rstrip(b"="),
        urlsafe,
        urlsafe.rstrip(b"="),
        value.hex().encode("ascii"),
        value.hex().upper().encode("ascii"),
        percent,
        plus,
        re.sub(rb"%[0-9A-F]{2}", lambda match: match.group(0).lower(), percent),
        json_escaped,
        json_escaped.replace(b"/", b"\\/"),
    }
    variants.update(_base64_cores(value, base64.b64encode))
    variants.update(_base64_cores(value, base64.urlsafe_b64encode))
    return {item for item in variants if item}


def build_patterns(
    values: Mapping[str, bytes | Iterable[bytes]], visible_paths: set[str] | frozenset[str]
) -> list[Pattern]:
    """Build encoded match patterns with scope-sensitive replacement markers."""

    by_encoding: dict[bytes, bytes] = {}
    for path in sorted(values):
        marker = f"[tw:{path}]".encode() if path in visible_paths else b"[tw:redacted]"
        item = values[path]
        path_values = [bytes(item)] if isinstance(item, (bytes, bytearray)) else item
        for raw_value in path_values:
            value = bytes(raw_value)
            if len(value) < 8:
                continue
            for encoded in _encodings(value):
                current = by_encoding.get(encoded)
                if current is None or (current == b"[tw:redacted]" and path in visible_paths):
                    by_encoding[encoded] = marker
    return [Pattern(encoded, marker) for encoded, marker in by_encoding.items()]


def _trie_regex(words: Iterable[bytes]) -> bytes:
    terminal = None
    root: dict[int | None, dict] = {}
    for word in words:
        node = root
        for byte in word:
            node = node.setdefault(byte, {})
        node[terminal] = {}

    def compile_node(node: dict[int | None, dict]) -> bytes:
        alternatives: list[bytes] = []
        for byte, child in sorted(
            ((key, value) for key, value in node.items() if key is not terminal),
            key=lambda item: item[0],
        ):
            alternatives.append(re.escape(bytes((byte,))) + compile_node(child))
        if terminal in node:
            alternatives.append(b"")
        if not alternatives:
            return b""
        if len(alternatives) == 1:
            return alternatives[0]
        return b"(?:" + b"|".join(alternatives) + b")"

    return compile_node(root)


class Redactor:
    def __init__(self, patterns: Iterable[Pattern]):
        pattern_list = list(patterns)
        self._markers = {pattern.encoded: pattern.marker for pattern in pattern_list}
        self.max_pattern_length = max((len(value) for value in self._markers), default=1)
        self._automaton = None
        self._regex = None
        if self._markers and ahocorasick is not None:
            automaton = ahocorasick.Automaton(ahocorasick.STORE_ANY, ahocorasick.KEY_SEQUENCE)
            for encoded, marker in self._markers.items():
                automaton.add_word(tuple(encoded), (len(encoded), marker))
            automaton.make_automaton()
            self._automaton = automaton
        else:
            expression = _trie_regex(self._markers)
            self._regex = re.compile(expression) if expression else None

    def _replace(self, match: re.Match[bytes]) -> bytes:
        return self._markers[match.group(0)]

    def redact(self, payload: bytes) -> bytes:
        matches = self.matches(payload)
        if not matches:
            return payload
        pieces: list[bytes] = []
        position = 0
        for start, end, marker in matches:
            pieces.append(payload[position:start])
            pieces.append(marker)
            position = end
        pieces.append(payload[position:])
        return b"".join(pieces)

    def matches(self, payload: bytes) -> list[tuple[int, int, bytes]]:
        candidates: list[tuple[int, int, bytes]] = []
        if self._automaton is not None:
            for end, (length, marker) in self._automaton.iter(tuple(payload)):
                candidates.append((end - length + 1, end + 1, marker))
        elif self._regex is not None:
            candidates.extend(
                (match.start(), match.end(), self._markers[match.group(0)])
                for match in self._regex.finditer(payload)
            )
        if not candidates:
            return []
        candidates.sort(key=lambda item: (item[0], -(item[1] - item[0])))
        selected: list[tuple[int, int, bytes]] = []
        position = 0
        for candidate in candidates:
            if candidate[0] < position:
                continue
            selected.append(candidate)
            position = candidate[1]
        return selected

    def stream(self) -> "RedactionStream":
        return RedactionStream(self)


class RedactionStream:
    def __init__(self, redactor: Redactor):
        self.redactor = redactor
        self.buffer = b""
        self.count = 0

    def _redact_counted(self, payload: bytes) -> bytes:
        matches = self.redactor.matches(payload)
        if not matches:
            return payload
        self.count += len(matches)
        pieces: list[bytes] = []
        position = 0
        for start, end, marker in matches:
            pieces.extend((payload[position:start], marker))
            position = end
        pieces.append(payload[position:])
        return b"".join(pieces)

    def feed(self, chunk: bytes) -> bytes:
        if not chunk:
            return b""
        self.buffer += chunk
        keep = self.redactor.max_pattern_length - 1
        if len(self.buffer) <= keep:
            return b""
        safe = len(self.buffer) - keep
        for start, end, _marker in self.redactor.matches(self.buffer):
            if start < safe < end:
                safe = start
                break
        if safe == 0:
            return b""
        ready, self.buffer = self.buffer[:safe], self.buffer[safe:]
        return self._redact_counted(ready)

    def finish(self) -> bytes:
        ready, self.buffer = self.buffer, b""
        return self._redact_counted(ready)


def scrub_text(text: str, redactor: Redactor) -> tuple[str, bool]:
    payload = text.encode("utf-8", "surrogatepass")
    scrubbed = redactor.redact(payload)
    return scrubbed.decode("utf-8", "replace"), scrubbed != payload
