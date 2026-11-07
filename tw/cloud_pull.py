"""One bounded pull, with disk-backed page storage and an absolute deadline."""
import json
import tempfile
from collections.abc import Sequence

from . import crypto
from .cloud_sync import PullRetry

MAX_PULL_BYTES = 8 * 1024 * 1024
MAX_PULL_PAGES = 64
MAX_PULL_RECORDS = 8192
MAX_PULL_SECONDS = 20
DECODE_ERRORS = (crypto.CryptoError, ValueError, TypeError, KeyError, StopIteration, IndexError,
                 AttributeError, OverflowError, RecursionError)


class PullBudget:
    def __init__(self, monotonic):
        self.monotonic = monotonic
        self.deadline = monotonic() + MAX_PULL_SECONDS
        self.bytes = self.pages = self.records = 0

    def check(self):
        if self.monotonic() >= self.deadline:
            raise PullRetry('cloud pull elapsed budget exceeded')

    def response(self, size):
        self.check()
        self.bytes += size
        self.pages += 1
        if self.bytes > MAX_PULL_BYTES or self.pages > MAX_PULL_PAGES:
            raise PullRetry('cloud pull byte or page budget exceeded')

    def count(self, value):
        # Count all array elements, including nested evidence and key material.
        if isinstance(value, dict):
            for item in value.values():self.count(item)
        elif isinstance(value, list):
            self.records += len(value)
            if self.records > MAX_PULL_RECORDS:
                raise PullRetry('cloud pull record budget exceeded')
            for item in value:self.count(item)
        self.check()


class PageSpool(Sequence):
    """Retain encoded pages on a private anonymous file, decode one at a time."""
    def __init__(self):
        self.file = tempfile.TemporaryFile(mode='w+b')
        self.offsets = []

    def append(self, page):
        self.file.seek(0, 2)
        self.offsets.append(self.file.tell())
        self.file.write(crypto.canonical_json(page) + b'\n')

    def __len__(self):return len(self.offsets)

    def __getitem__(self, index):
        if isinstance(index, slice):return [self[i] for i in range(*index.indices(len(self)))]
        self.file.seek(self.offsets[index])
        return json.loads(self.file.readline())

    def close(self):self.file.close()

    def __del__(self):self.close()
