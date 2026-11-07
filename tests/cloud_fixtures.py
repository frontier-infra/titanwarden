"""Immutable upstream fixture inventory. Hash checks precede JSON parsing."""
from pathlib import Path

from tw.cloud_wire import load_pinned_json

CLOUD_REVISION = "177766e1de71acbff0a188fa4d4b487db6c28391"
ROOT = Path(__file__).parent / "fixtures" / "cloud" / CLOUD_REVISION
FIXTURES = {
    "core/vectors/protocol-v2.json": "ee8eb086d1248a7e12989d6e57dfd9406700081f9cae4d50281e8e094f239c04",
    "control/vectors/authority-v1.json": "114388ad3b6abd96c449a0d57031472812e10b849e2e75b10cecf1157ef870be",
    "control/src/genesis/vectors.json": "336c7f9b0f6a9b6c4c54cdc8de169cc8211a524b181949d7c986cb0bc3faa6c8",
    "control/test/recovery/vectors.json": "136688a51b3c7ac8b31660a741648997e9ac98d03272c53f4fe413b62b82231e",
}
PAIRED_MANIFEST = "core/vectors/paired-broker-manifest-v1.json"
PAIRED_MANIFEST_SHA256 = "434e44d34c383184546cf1504e7a0906a04cf522cf1313a98ef0f033b754422f"


def paired_manifest():
    return load_pinned_json(ROOT / PAIRED_MANIFEST, PAIRED_MANIFEST_SHA256)


def paired_traces():
    for item in paired_manifest()["files"]:
        name = "core/vectors/" + item["file"]
        yield name, load_pinned_json(ROOT / name, item["sha256"])


def production_manifest():
    return load_pinned_json(ROOT / "core/vectors/paired-broker-manifest-v2.json", "342b0e961fc64f3eb65a77758e578d2e5e3f9556ca60a54700119ce46a1450c6")


def production_traces():
    for item in production_manifest()["files"]:
        name = "core/vectors/" + item["file"]
        document = load_pinned_json(ROOT / name, item["sha256"])
        if item["file"].endswith("-v2.json"):
            yield name, document


def fixture(name):
    return load_pinned_json(ROOT / name, FIXTURES[name])
