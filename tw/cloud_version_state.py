"""Signed pending-to-active cutover, using only predecessor commitments."""
from .cloud_epochs import _writer
from .cloud_policy import AuthorityView
from .cloud_epochs import fail
from . import cloud_wire as wire


def require(condition, message):
    if not condition:
        fail(message)


def activate(state, entry, snapshot):
    b = entry['body']
    require(isinstance(b, dict) and set(b) >= {'secret_id', 'version_id', 'from_state', 'to_state', 'supersedes_version_id'}
        and set(b) <= {'secret_id', 'version_id', 'from_state', 'to_state', 'supersedes_version_id', 'authz', 'assertion'},
        'Invalid version_state fields')
    for key in ('secret_id', 'version_id', 'supersedes_version_id'):
        require(isinstance(b[key], str) and 0 < len(b[key]) <= 2048, 'Invalid version identity')
    require(b['from_state'] == 'pending' and b['to_state'] == 'active', 'Only pending to active is permitted')
    require(('authz' in b) == ('assertion' in b), 'Incomplete activation authorization')
    secret = state['secrets'].get(b['secret_id'])
    require(secret is not None and secret.get('state', 'active') == 'active'
        and secret['class'] in ('standard', 'sensitive', 'restricted'), 'Unknown or inactive activation secret')
    protected = secret['class'] == 'restricted'
    require(bool(b.get('authz')) if protected else 'authz' not in b,
        'Activation authorization does not match secret class')
    target = next((v for v in state['versions'] if v['version_id'] == b['version_id']), None)
    prior = next((v for v in state['versions'] if v['version_id'] == b['supersedes_version_id']), None)
    require(target is not None and prior is not None and all(v['secret_id'] == b['secret_id']
        and v['project'] == secret['project'] for v in (target, prior)), 'Unknown or cross-secret activation version')
    require(target['version_id'] != prior['version_id'] and target['state'] == 'pending'
        and prior['state'] == 'active', 'Activation requires pending target and active predecessor')
    active = [v for v in state['versions'] if v['secret_id'] == b['secret_id'] and v['state'] == 'active']
    require(len(active) == 1 and active[0]['version_id'] == prior['version_id'], 'Activation requires exactly one active predecessor')
    require(type(target['version_no']) is int and type(prior['version_no']) is int
        and 1 <= prior['version_no'] < target['version_no'] <= 9007199254740991, 'Backward activation forbidden')
    require(secret['project'] in state['active_kek'] and target['kek_id'] == state['active_kek'][secret['project']],
        'Activation requires current project KEK')
    _writer(entry['signer'], secret['project'], snapshot)
    if protected:
        require(entry['signer']['kind'] == 'member', 'Restricted activation requires key-holder member')
    prior['state'], target['state'] = 'retired', 'active'


def authorize(entry, authority, runtime):
    """Bind restricted proof to the activation and spend it across all kinds."""
    if 'authz' not in entry['body']:
        return
    signer = entry['signer']
    cert = AuthorityView(authority).certificate_at(signer.get('key'), authority['head']['seq'])
    require(signer['kind'] == 'member' and cert and cert['member_id'] == signer['id']
        and cert['state'] == 'active' and cert['key_holder'], 'Restricted activation requires active key-holder')
    b = entry['body']
    authority['used_challenges'].append(wire.verify_version_authorization(entry, cert,
        dict(secret_id=b['secret_id'], version_id=b['version_id']), authority['used_challenges'], runtime))
