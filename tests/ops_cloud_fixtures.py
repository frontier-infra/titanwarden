"""Cloud-generated production operational inputs, pinned before JSON parsing."""
from pathlib import Path

from tw.cloud_wire import load_pinned_json

REVISION = 'ae272bbf497e34e24561bd44498d6184223cb1e0'
ROOT = Path(__file__).parent / 'fixtures/cloud' / REVISION / 'core/vectors'
MANIFEST = 'paired-broker-manifest-ops-v1.json'
MANIFEST_SHA256 = '38c7e78e1329f60d9855d908fe6c8891f4abbab70e338d3fe6577924cda177fe'


def documents():
    manifest = load_pinned_json(ROOT / MANIFEST, MANIFEST_SHA256)
    return [(item, load_pinned_json(ROOT / item['file'], item['sha256'])) for item in manifest['files']]
