"""Immutable cloud P8 fixture, SHA checked before parsing."""
from pathlib import Path
from tw.cloud_wire import load_pinned_json
from admin_cloud_fixtures import document as bootstrap

REVISION = 'accfe20f32355bdf88a871a65c10df9f9c660acb'
ROOT = Path(__file__).parent/'fixtures/cloud'/REVISION/'core/vectors'
SHA256 = 'f743fafa337dd044d1bf2bc2f6d1cb6b0ed71a322e5582ac192cd6882e6e1839'
MANIFEST_SHA256 = '90e9c8aec3887f6d3aa557ae0650e5b2d61d7aada09197e1e5d783ea179fc623'


def document():
    manifest = load_pinned_json(ROOT/'paired-broker-manifest-version-state-v1.json', MANIFEST_SHA256)
    data = load_pinned_json(ROOT/'broker-version-state-v1.json', SHA256)
    if manifest != dict(revision=1, files=[dict(file='broker-version-state-v1.json', sha256=SHA256, records=14, cases=18)]):
        raise ValueError('version activation manifest differs')
    base = bootstrap()
    if data['bootstrap'] != dict(file='broker-admin-policy-v1.json', sha256='380a5d0a6893129de6ed7fbb7f2facde7c5ac23797ee23ff700fcdfe63bd7987'):
        raise ValueError('version activation bootstrap differs')
    if data['profile'] != 'production' or data['production_acceptable'] is not True:
        raise ValueError('production activation fixture required')
    return base, data
