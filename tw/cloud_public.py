"""Broker public history: signed authority and commitments, own ciphertext only.

Other members' private slot and wrap availability is a recovery liveness
property checked by the full verifier and their browsers, not by this surface.
"""
from copy import deepcopy
import json

from . import crypto, cloud_wire as wire
from .cloud_epochs import (PublicStage, EpochReplay, checked_key, keyring_digest,
    _box, _writer, exact, text, integer, digest, binary)
from .cloud_policy import AuthorityView, require
from .cloud_recovery import RecoveryEvidence, RecoveryVerifier, recovery_state
from .cloud_sync_verifier import SyncVerifier
from .cloud_sync import guard as retry_guard
from .policy_log import PolicyError


TABLES = frozenset(('enrollment_records', 'enrollment_binding_evidence',
    'initial_member_slot_commitments', 'genesis_acceptances', 'recovery_pending_resets',
    'recovery_reset_proposals', 'recovery_reset_activations', 'recovery_epoch_commitments',
    'enrollment_adoption_proofs', 'genesis_adoptions'))
TABLE_FIELDS = {
    'enrollment_records': ('broker_id','ticket_id','transcript_json','transcript_digest','proof','created_at'),
    'enrollment_binding_evidence': ('blob_id','broker_id','wrap_digest','cert_seq'),
    'initial_member_slot_commitments': ('certificate','reference'),
    'genesis_acceptances': ('invite_id','member_id','member_key_id','workos_user_id','transcript_json','proof','accepted_at','confirmed_seq'),
    'recovery_pending_resets': ('reset_id','member_id','old_cert_seq','created_at','expires_at','request_json'),
    'recovery_reset_proposals': ('proposal_hash','proposal_seq','entry_json','reset_id','member_id','old_cert_seq','candidate_json','sas_evidence_json','accepted_at','candidate_created_at','expires_at'),
    'recovery_reset_activations': ('activation_seq','proposal_hash','reset_id','entry_json','sas_evidence_json','accepted_at'),
    'recovery_epoch_commitments': ('epoch_seq','commit_seq','generation','recipients_json'),
    'enrollment_adoption_proofs': ('broker_id','candidate_root','proof'),
    'genesis_adoptions': ('singleton','org_root','broker_id','metadata_json','accepted_at'),
}


def commitment_stage(public, own, entry, *, broker, scope, recipients=None, custody_required=True):
    wire.exact(public, ('schema','policy_seq','plan_id','fence','created_at','keyring',
        'keyring_metadata','recipients','scoped_seals'))
    wire.exact(own, ('policy_seq','plan_id','fence','keyring','wraps','scoped_seals'))
    require(public['schema'] == 'tw-epoch-public-v1' and public['policy_seq'] == own['policy_seq'] == entry['seq'], 'public stage position differs')
    body = entry['body']
    require(public['plan_id'] == own['plan_id'] == body.get('plan_id', '__epoch_init__')
        and public['fence'] == own['fence'] == body.get('fence', 0), 'public stage identity differs')
    require(public['keyring'] == body['keyring'] and public['scoped_seals'] == body['scoped_seals']
        and public['recipients'] == (body.get('recipients', []) if recipients is None else recipients), 'public stage commitment mismatch')
    require(all(isinstance(public[k],list) for k in ('keyring','keyring_metadata','recipients','scoped_seals'))
        and all(isinstance(own[k],list) for k in ('keyring','wraps','scoped_seals')), 'public stage arrays required')
    commitments = {r['key_id']: r for r in public['keyring']}
    require(len(commitments) == len(public['keyring']), 'duplicate public key commitment')
    metadata = {}
    for row in public['keyring_metadata']:
        wire.exact(row, ('key_id','purpose','project','version','mk_generation','aad_v'))
        wire.integer(row['version'],1); wire.integer(row['mk_generation'],1)
        commitment = commitments.get(row['key_id'])
        require(row['key_id'] not in metadata and commitment is not None and row['aad_v'] == 2
            and row['purpose'] in ('kek','fingerprint') and commitment['purpose'] == row['purpose']
            and (row['purpose']=='fingerprint' and row['project'] is None or row['purpose']=='kek' and isinstance(row['project'],str) and bool(row['project']))
            and commitment['scope'] == (row['project'] or '*'), 'public key metadata differs')
        metadata[row['key_id']] = dict(row, commitment_digest=wire.digest(commitment['digest']))
    retry_guard(set(metadata) == set(commitments), 'incomplete public key metadata','E_SYNC_RETRY')
    keys = {}
    for row in own['keyring']:
        require(scope == 'full', 'scoped broker received encrypted keyring')
        checked_key(row)
        expected = metadata.get(row['key_id'])
        require(row['key_id'] not in keys and expected is not None
            and all(row[k] == expected[k] for k in ('purpose','project','version','mk_generation','aad_v'))
            and keyring_digest(row) == expected['commitment_digest'], 'own keyring digest mismatch')
        keys[row['key_id']] = row
    retry_guard(not custody_required or scope != 'full' or set(keys) == set(metadata), 'missing own encrypted keyring','E_SYNC_RETRY')
    generation = body.get('generation', body.get('to_generation', body.get('omk_generation')))
    wraps = { (r['kind'],r['id']): dict(recipient_kind=r['kind'],recipient_id=r['id'],
        omk_generation=generation,wrap_digest=r['wrap_digest']) for r in public['recipients'] }
    seals = {}
    for row in public['scoped_seals']:
        key = metadata.get(row['key_id'])
        require(key is not None, 'seal key metadata missing')
        seals[(row['broker_id'],row['key_id'])] = dict(broker_id=row['broker_id'],key_id=row['key_id'],
            purpose=key['purpose'], project=row['project'],wrap_digest=row['wrap_digest'])
    seen = set()
    for row in own['wraps']:
        wire.exact(row, ('recipient_kind','recipient_id','omk_generation','eph_pub','nonce','wrapped_omk','wrap_digest'))
        require(scope == 'full' and row['recipient_kind'] == 'broker' and row['recipient_id'] == broker, 'another recipient wrap present')
        identity = ('broker',broker)
        expected = wraps.get(identity)
        require(identity not in seen and expected is not None and all(row[k] == expected[k] for k in expected), 'own wrap commitment mismatch')
        _box(row,'wrapped_omk')
        seen.add(identity); wraps[identity] = row
    if custody_required and scope == 'full' and ('broker',broker) in wraps:
        retry_guard(('broker',broker) in seen, 'missing own committed wrap','E_SYNC_RETRY')
    seen = set()
    for row in own['scoped_seals']:
        wire.exact(row, ('broker_id','key_id','purpose','project','eph_pub','nonce','wrapped_key','wrap_digest'))
        require(scope != 'full' and row['broker_id'] == broker
            and (row['purpose'] == 'fingerprint' or row['project'] in scope), 'another recipient seal present')
        identity = (broker,row['key_id']); expected = seals.get(identity)
        require(identity not in seen and expected is not None and all(row[k] == expected[k] for k in expected), 'own seal commitment mismatch')
        _box(row,'wrapped_key')
        seen.add(identity); seals[identity] = row
    if custody_required and scope != 'full':
        retry_guard(all(identity in seen for identity,row in seals.items()
            if row['broker_id'] == broker and row['project'] in scope), 'missing own committed seal','E_SYNC_RETRY')
    return PublicStage(keyring=[keys.get(k,metadata[k]) for k in metadata],
        wraps=list(wraps.values()), scoped_seals=list(seals.values()))


class PublicEvidence(RecoveryEvidence):
    """Retained public commitments, not private-slot availability evidence."""
    def __init__(self, tables, blobs=None, **kwargs):
        tables = deepcopy(tables)
        tables['enrollment_wrap_digests'] = tables.get('enrollment_binding_evidence', [])
        super().__init__(tables, blobs, **kwargs)

    def verify_member_confirmation_wrap(self, entry, certificate, state, committed_generation):
        prior = AuthorityView(state).current(certificate['member_id'])
        pending = self._one('genesis_acceptances', lambda r:r.get('member_id') == certificate['member_id'])
        if not pending or prior:
            return super().verify_member_confirmation_wrap(entry,certificate,state,committed_generation)
        accepted = wire.verify_member_accept(dict(self._json(pending['transcript_json']),proof=pending['proof']),state['org_id'])
        require(entry['kind'] == 'member_cert' and accepted['member_key'] == certificate, 'confirmation differs from accepted keys')
        slot = deepcopy(accepted['slot']); commitment = slot.pop('commitment_sha256')
        self._initial.append((deepcopy(certificate),commitment,'slot_blob',slot))
        if certificate['key_holder']:
            wrap = wire.exact(entry['body'].get('wrap'),('omk_generation','wrap_digest'))
            require(committed_generation(state['head']) == dict(kind='committed',generation=wrap['omk_generation']), 'confirmation wrap generation differs')
            wire.digest(wrap['wrap_digest'])
        else:
            require('wrap' not in entry['body'],'nonholder carries wrap')

    def claim_wrap(self, ref, *, proposal_hash=None, required=True):
        # The signed claim binds this digest. No private member wrap is served.
        wire.digest(ref['recipient']['wrap_digest'])
        return None


class PublicEpochReplay(EpochReplay):
    def _first_project(self,state,entry,snapshot,project,change):
        if change['from_kek_id'] is not None:
            return False
        trigger = next((t for t in snapshot.get('rekey_triggers',[]) if t['seq']==entry['body'].get('trigger_seq')),None)
        require(trigger is not None and trigger['kind']=='projects' and trigger['reason']=='project_created'
            and trigger['projects']==sorted(entry['body']['projects']) and snapshot.get('project_creations',{}).get(project)==trigger['seq']
            and project not in state['active_kek'] and not any(k['project']==project for k in state['keyring'])
            and not any(project in e['projects'] or project in e['active_kek'] for e in state['epochs']), 'first project KEK predecessor mismatch')
        return True

    def _trigger(self,state,entry,snapshot,projects,budget=True):
        trigger = next((t for t in snapshot.get('rekey_triggers',[]) if t['seq']==entry['body'].get('trigger_seq')),None)
        if trigger is not None and trigger['reason']=='project_created':
            require(entry['kind']=='epoch_rotate_projects' and trigger['seq'] not in state['used_triggers']
                and all(self._first_project(state,entry,snapshot,p,entry['body']['projects'][p]) for p in projects), 'invalid first project KEK trigger')
            return 'project_created'
        return super()._trigger(state,entry,snapshot,projects,budget)

    def _ciphertext(self, state, entry, snapshot, blob, mode):
        if entry['kind'] == 'secret_create' or blob is not None:
            return super()._ciphertext(state,entry,snapshot,blob,mode)
        b = entry['body']
        exact(b, ('version_id','secret_id','version_no','state','kek_id','fingerprint','length','source','value_digest','envelope_digest'))
        secret = state['secrets'].get(text(b['secret_id']))
        require(secret is not None and b['state'] in ('pending','active'), 'invalid public version')
        _writer(entry['signer'],secret['project'],snapshot)
        require(state['active_kek'].get(secret['project']) == text(b['kek_id']), 'public version uses stale KEK')
        versions = [v for v in state['versions'] if v['secret_id'] == b['secret_id']]
        require(not any(v['version_id'] == b['version_id'] for v in state['versions'])
            and integer(b['version_no'],1) == max((v['version_no'] for v in versions),default=0)+1
            and not (b['state'] == 'active' and any(v['state'] == 'active' for v in versions)), 'public version identity differs')
        text(b['version_id']); text(b['source']); binary(b['fingerprint'],32)
        require(16 <= integer(b['length'],16) <= 1048576, 'public ciphertext length differs')
        digest(b['value_digest']); digest(b['envelope_digest'])
        state['versions'].append(dict(deepcopy(b),project=secret['project']))


class PublicHistoryVerifier(SyncVerifier):
    """Full signed authority, opaque unrelated private blobs, exact own custody."""
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self._epochs = PublicEpochReplay()
        self._requests = PublicRequestReplay()

    def _authorize(self,entry,state):
        from . import cloud_admin_policy
        # PolicyVerifier calls this hook only after the signature and prefix verify.
        # Activation spends a proof in policy history, matching cloud admission's
        # complete policy_log scan without changing the authority core projection.
        spent = {e['body']['authz']['challenge'] for e in self._records
            if isinstance(e['body'].get('authz'),dict) and isinstance(e['body']['authz'].get('challenge'),str)}
        if entry['kind'] == 'epoch_init' and not self._projects:
            self._projects = tuple(sorted(entry['body']['active_kek']))
        if entry['kind'] in cloud_admin_policy.KINDS:
            result = cloud_admin_policy.apply(entry,state,self._candidate_epochs._state,
                projects=self._projects,runtime=self._active_runtime,used_challenges=list(spent | set(self._candidate_requests.used_challenges)))
            self._projects = tuple(sorted(set(self._projects) | set(result['admin_policy']['projects'])))
            return result
        self._candidate_requests.targets = deepcopy(self._candidate_epochs._state['secrets'])
        extra=spent | set(state.get('admin_policy',{}).get('used_challenges',[])) | set(self._candidate_requests.used_challenges)
        previous=set(state['used_challenges'])
        state['used_challenges']=list(dict.fromkeys(state['used_challenges']+sorted(extra)))
        result=super()._authorize(entry,state)
        if entry['kind'] == 'version_state' and 'authz' in entry['body']:
            extra.add(entry['body']['authz']['challenge'])
        result['used_challenges']=[challenge for challenge in result['used_challenges'] if challenge in previous or challenge not in extra]
        return result

    def _resolve_key(self,entry,state):
        from . import cloud_admin_policy
        if entry['kind'] in cloud_admin_policy.KINDS:
            from .cloud_policy import _actor
            return crypto.unb64url(_actor(entry,state)['sign_pub'])
        return super()._resolve_key(entry,state)

    def _snapshot(self,state,epochs):
        snapshot = super()._snapshot(state,epochs)
        if 'admin_policy' in state:
            snapshot['projects'] = sorted(set(snapshot['projects']) | set(state['admin_policy']['projects']))
        snapshot['project_creations'] = {p:t['seq'] for t in state['triggers'].values()
            if t['reason']=='project_created' for p in t['projects']}
        snapshot['staged_project_keys'] = {}
        return snapshot

    def _derive(self,entry,state,received_at):
        self._candidate_requests.targets = deepcopy(self._candidate_epochs._state['secrets'])
        return super()._derive(entry,state,received_at)

    def finish_history(self, blobs, *, evidence=None, broker_id=None):
        with self._lock:
            require(not self.conflict and isinstance(evidence,PublicEvidence), 'public history evidence required')
            certificate = AuthorityView(self.state).broker_certificate_at(broker_id,self.head)
            require(certificate is not None,'certified public history broker required')
            require(getattr(evidence,'expected_scope',certificate['scope']) == certificate['scope'], 'public evidence scope differs from certificate')
            self._epochs.verify_current_ciphertexts(blobs,projects=None if certificate['scope'] == 'full' else certificate['scope'])
            # Every initial reference originated in a verified signed founder or
            # invite acceptance, never in a cloud row. The row may only restate it.
            for cert,commitment,kind,metadata in self._initial_references:
                refs = [row for row in evidence._rows.get('initial_member_slot_commitments',())
                    if row['certificate'] == cert and row['reference']['commitment_sha256'] == commitment
                    and row['reference']['commitment_kind'] == kind]
                require(len(refs) == 1, 'initial slot commitment mismatch')
                ref = refs[0]['reference']
                source = next(v for v in self.state['certificates'] if v['certificate'] == cert)
                require(ref['member_key_id'] == cert['member_key_id'] and ref['policy_seq'] == source['seq']
                    and (metadata is None or ref['slot_id'] == metadata['slot_id']), 'initial slot reference position differs')
            self._finalized_head = self.head
            self._ciphertext_scope = certificate['scope']


from .cloud_requests import RequestReplay, parse_request, operations, timestamp, request_grant_id


class PublicRequestReplay(RequestReplay):
    """Only signed grants can authorize this broker; inbox rows confer nothing."""
    def _apply(self, entry, state, facts, runtime):
        if entry['kind'] == 'policy_rules':
            return super()._apply(entry,state,{},runtime)
        require(entry['seq'] == state['head']['seq']+1 and entry['prev_hash'] == state['head']['hash'], 'public request predecessor differs')
        b, signer = entry['body'], entry['signer']
        if entry['kind'] == 'request_open':
            wire.exact(b,('request','default_at'))
            request = parse_request(b['request'])
            require(request['request_id'] not in self.requests,'duplicate public request')
            cert = AuthorityView(state).current(signer.get('id')) if signer['kind'] == 'member' else None
            broker = AuthorityView(state).broker_certificate_at(signer.get('id'),state['head']) if signer['kind'] == 'broker' else None
            require(cert and cert['certificate']['state'] == 'active' and cert['certificate']['key_holder']
                or broker and (broker['scope'] == 'full' or request['target'].split('/')[0] in broker['scope']), 'public request signer outside scope')
            if b['default_at'] is not None:
                require(timestamp(b['default_at']) >= timestamp(entry['ts']), 'public request deadline differs')
            self.requests[request['request_id']] = dict(request=request,state='open',origin=signer['kind'],
                opened_by=deepcopy(signer),opened_at=entry['ts'],default_at=b['default_at'])
            return
        if entry['kind'] == 'request_default':
            wire.exact(b,('request_id',))
            opened = self.requests.get(b['request_id'])
            require(signer['kind'] == 'derived' and opened and opened['state'] == 'open'
                and opened['default_at'] is not None and timestamp(entry['ts']) > timestamp(opened['default_at']), 'public default deadline differs')
            # Historical admission facts are not independently available. Keep
            # this transition visible but never derive a delivery grant from it.
            opened['state'] = 'defaulted'
            return
        wire.exact(b,('request_id','decision','reason','grant','request','client_approval_ref'),('authz','assertion'))
        require(entry['kind'] == 'request_decide' and b['decision'] in ('approve','deny'), 'invalid public decision')
        prior = self.requests.get(b['request_id'])
        require(prior is None or prior['state'] == 'open','public request already terminal')
        request = parse_request(b['request']) if prior is None else prior['request']
        require(request['request_id'] == b['request_id'] and (prior is None or b['request'] is None), 'public request restatement differs')
        version = AuthorityView(state).current(signer.get('id')) if signer['kind'] == 'member' else None
        require(version is not None and version['certificate']['state'] == 'active'
            and version['certificate']['member_key_id'] == signer.get('key')
            and wire.rank(version['certificate']['role']) >= 2, 'public grant requires admin role')
        cert = version['certificate']
        require(cert['member_id'] != request['principal_id'] and (prior is None
            or prior['opened_by'].get('id') != cert['member_id']), 'public self approval forbidden')
        target = next((s for s in self.targets.values() if s['path'] == request['target']),None)
        require(target is not None or request['kind'] == 'create','unknown public grant target')
        secret_class = target['class'] if target else b['grant']['max_class'] if b['grant'] else 'restricted'
        project=request['target'].split('/')[0]
        client=state.get('admin_policy',{}).get('projects',{}).get(project,{}).get('change_policy')=='client_approval_required'
        if secret_class == 'restricted' or client or 'authz' in b or 'assertion' in b:
            challenge = wire.verify_authorization(entry,cert,dict(request_id=b['request_id']),
                list(dict.fromkeys(state['used_challenges']+self.used_challenges)),runtime)
            self.used_challenges.append(challenge)
        if client and b['decision']=='approve':
            wire.text(b['client_approval_ref'])
        else:
            require(b['client_approval_ref'] is None,'unexpected public client approval reference')
        if b['decision'] == 'deny':
            require(b['grant'] is None,'public denial contains grant')
        else:
            g = wire.exact(b['grant'],('principal_id','pattern','ops','max_class','expires_at'))
            require(g['principal_id'] == request['principal_id'] and g['pattern'] == request['target']
                and g['max_class'] == secret_class and set(operations(g['ops'])) <= set(request['ops'])
                and (request['kind'] != 'create' or g['ops'] == ['put'])
                and timestamp(entry['ts']) < timestamp(g['expires_at']) <= timestamp(entry['ts'])+request['ttl_seconds']*1000,
                'public grant exceeds signed request')
            ident = request_grant_id(request['request_id'])
            require(ident not in self.grants,'duplicate public grant')
            self.grants[ident] = deepcopy(g)
        self.requests[request['request_id']] = dict(request=request,state='approved' if b['decision']=='approve' else 'denied')


def decode_evidence(pages, policy, *, org, broker):
    """Decode only the agreed versioned transport, binding every page to a head."""
    retry_guard(bool(pages) and bool(policy), 'complete policy and evidence required','E_SYNC_RETRY')
    head, scope = pages[0]['head'], pages[0]['scope']
    wire.parse_head(head)
    require(scope == 'full' or isinstance(scope,list) and scope == sorted(set(scope)) and bool(scope), 'invalid evidence scope')
    records = {}
    for row in policy:
        wire.exact(row,('seq','prev_hash','hash','kind','entry_json','signer_kind','signer_id','sig'))
        entry = crypto.parse_canonical(row['entry_json'].encode())
        require(entry['seq'] == row['seq'] and entry['prev_hash'] == row['prev_hash'] and entry['kind'] == row['kind']
            and entry['signer']['kind'] == row['signer_kind'] and entry['signer'].get('id') == row['signer_id']
            and wire.hash_object(entry) == row['hash'] and row['seq'] not in records, 'policy row commitment mismatch')
        records[row['seq']] = (entry,row['sig'])
    retry_guard(sorted(records) == list(range(1,head['seq']+1)) and wire.hash_object(records[head['seq']][0]) == head['hash'], 'incomplete policy evidence prefix','E_SYNC_RETRY')
    tables = {name:[] for name in TABLES}
    stages, own, expected = {}, {}, 1
    for index,page in enumerate(pages):
        wire.exact(page,('schema','org_id','broker_id','scope','head','from_seq','through_seq','next_from_seq',
            'control_head','public_staging','own_payloads','tables'))
        require(page['schema'] == 'tw-policy-evidence-v1' and page['org_id'] == org and page['broker_id'] == broker
            and page['head'] == head and page['scope'] == scope and page['from_seq'] == expected,
            'evidence page binding differs')
        wire.parse_head(page['control_head'])
        through = wire.integer(page['through_seq'],expected)
        require(through <= head['seq'] and page['next_from_seq'] == (None if through == head['seq'] else through+1)
            and (page['next_from_seq'] is None) == (index == len(pages)-1), 'evidence pagination incomplete')
        require(set(page['tables']) == TABLES and all(isinstance(r,list) for r in page['tables'].values()), 'evidence table allowlist differs')
        for name,rows in page['tables'].items():
            for row in rows:
                wire.exact(row,TABLE_FIELDS[name])
                if name == 'initial_member_slot_commitments':
                    wire.exact(row['reference'],('member_key_id','policy_seq','slot_id','commitment_sha256','commitment_kind'))
                if row not in tables[name]:
                    tables[name].append(row)
        for field,target in (('public_staging',stages),('own_payloads',own)):
            require(isinstance(page[field],list),'evidence stage array required')
            for row in page[field]:
                seq = wire.integer(row['policy_seq'],expected)
                require(seq <= through and seq not in target,'evidence stage position differs')
                target[seq] = row
        expected = through+1
    retry_guard(expected == head['seq']+1 and set(stages) == set(own),'evidence suffix or own payload missing','E_SYNC_RETRY')
    decoded = {}
    for seq,public in stages.items():
        entry = records[seq][0]
        require(entry['kind'] in ('epoch_init','epoch_rotate','epoch_rotate_projects','epoch_commit'),'unrelated public stage')
        if entry['kind'] == 'epoch_commit':
            intent = records[entry['body']['epoch_seq']][0]
            stage_entry = dict(intent,seq=seq)
        else:
            intent = entry
            stage_entry = entry
        recipients = deepcopy(intent['body'].get('recipients',[]))
        if 'recipients_count' in intent['body']:
            for position in range(intent['seq']+1,head['seq']+1):
                later = records[position][0]
                if later['kind'] == 'epoch_recipients' and later['body']['epoch_seq'] == intent['seq']:
                    recipients.extend(later['body']['items'])
            complete=public['recipients']
            require(isinstance(complete,list) and len(complete) == intent['body']['recipients_count']
                and wire.hash_object(complete) == intent['body']['recipients_sha256']
                and complete[:len(recipients)]==recipients,'public recipient commitment mismatch')
            recipients=complete
        committed=not ('recipients_count' in intent['body']) or any(e['kind']=='epoch_commit' and e['body']['epoch_seq']==intent['seq'] for e,sig in records.values())
        decoded[seq] = commitment_stage(public,own[seq],stage_entry,broker=broker,scope=scope,recipients=recipients,custody_required=committed)
        if entry['kind']=='epoch_commit':
            decoded[intent['seq']] = deepcopy(decoded[seq])
    for seq,(entry,signature) in records.items():
        if entry['kind'] in ('epoch_init','epoch_rotate','epoch_rotate_projects','epoch_commit') and seq not in decoded:
            raise PolicyError('E_SYNC_RETRY','epoch awaits complete public commitment evidence')
    evidence = PublicEvidence(tables,request_facts={})
    evidence.expected_scope = scope
    return dict(head=head,scope=scope,records=records,stages=decoded,evidence=evidence)
