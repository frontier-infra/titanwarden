"""Opt-in daemon cloud service. Private keys and values stay inside the broker."""
from contextlib import ExitStack
from copy import deepcopy
import json
import threading
import time
from urllib.parse import urlencode

from . import crypto, cloud_wire as wire
from .cloud_enroll import EnrollmentSession, save_reservation, load_reservation, ticket_id
from .cloud_http import HTTPSTransport, SignedClient, public_origin, CloudResponseError
from .cloud_pull import PullBudget, PageSpool, DECODE_ERRORS, MAX_PULL_PAGES
from .cloud_policy import AuthorityView
from .cloud_public import PublicHistoryVerifier, decode_evidence
from .cloud_sync import CloudSync, guard, PullRetry
from .policy_log import PolicyError, policy_record
from .store import StoreError, utc_now


CONFIG = 'cloud_connection'


def remote_refusal(error):
    # Remote free text and arbitrary error-code strings never reach a pane.
    if error.code in ('E_AUTH','E_ROLE','E_DENIED','E_NOT_FOUND'):
        return PolicyError('E_DENIED','cloud request refused')
    return PullRetry('cloud request refused; synchronization will retry')


class CloudRuntime:
    def __init__(self, store, seal, *, transport_factory=HTTPSTransport, clock=utc_now, monotonic=time.monotonic):
        self.store, self.seal = store, seal
        self.transport_factory, self.clock, self.monotonic = transport_factory, clock, monotonic
        self.lock = threading.RLock()
        self.fetch_lock = threading.Lock()
        self.failures, self.next_attempt, self.last_code = 0, 0, None
        self.redaction_sink = lambda: None

    @property
    def enabled(self):
        return self.store.meta(CONFIG) is not None

    def config(self):
        raw = self.store.meta(CONFIG)
        guard(raw is not None,'store has not joined','E_SYNC_RETRY')
        return json.loads(raw)

    def blk(self):
        guard(self.seal.state == 'unsealed' and self.seal.keys is not None,'broker is sealed','E_SEALED')
        return bytes(self.seal.keys.master)

    def session(self):
        cfg = self.config()
        try:
            return load_reservation(self.store,self.blk(),cfg['org'],cfg['ticket'])
        except crypto.CryptoError as exc:
            raise StoreError('local enrollment custody failed verification') from exc

    def sync(self, *, store=None):
        cfg = self.config()
        return CloudSync(store or self.store,cfg['org'],cfg['broker'],verifier_type=PublicHistoryVerifier)

    def client(self):
        cfg,session = self.config(),self.session()
        client=SignedClient(cfg['org'],cfg['broker'],session.signing_key,clock=self.clock,
            transport=self.transport_factory(cfg['origin']))
        client.spools=[]
        client.budget=PullBudget(self.monotonic)
        if isinstance(client._transport,HTTPSTransport):client._transport.budget=client.budget
        return client

    def call(self, client, method, path, body=None, query=None):
        cfg = self.config()
        url = cfg['origin']+f"/v1/orgs/{cfg['org']}/"+path
        if query:
            url += '?' + urlencode(query)
        try:
            return client.send_http(client.prepare(method,url,body))
        except CloudResponseError as exc:
            raise remote_refusal(exc) from None

    def join(self, *, origin, org, name, code):
        with self.lock:
            blk = self.blk(); origin = public_origin(origin); wire.org_id(org)
            guard(self.store.meta('cloud_broker') == '1','use an empty cloud broker store for enrollment','E_POLICY')
            guard(self.store.connection.execute('SELECT 1 FROM secrets LIMIT 1').fetchone() is None,
                'populated local stores require the adoption ceremony','E_POLICY')
            if self.enabled:
                cfg = self.config()
                guard((cfg['origin'],cfg['org']) == (origin,org),'store already joined another organization')
                session = self.session()
            else:
                ticket = ticket_id(code)
                pending = self.store.meta('cloud_pending_join')
                if pending:
                    pending = json.loads(pending)
                    guard((pending['origin'],pending['org'],pending['ticket']) == (origin,org,ticket),'pending enrollment identity differs')
                    keys = []
                    for purpose in ('sign','kx'):
                        row = pending[purpose]
                        scalar = crypto.unwrap_key(blk,crypto.unb64url(row['wrapped']),crypto.unb64url(row['nonce']),
                            crypto.local_key_aad(org,ticket,purpose,'pending','*',1))
                        point = crypto.unb64url(pending['transcript']['sign_pub' if purpose=='sign' else 'kx_pub'])
                        keys.append(crypto.import_private(dict(kty='EC',crv='P-256',d=crypto.b64url(scalar),
                            x=crypto.b64url(point[1:33]),y=crypto.b64url(point[33:]))))
                    session = EnrollmentSession(org,pending['transcript'],*keys)
                else:
                    session = EnrollmentSession.create(org,name,'0.1.0')
                    pending = dict(origin=origin,org=org,ticket=ticket,transcript=session.transcript)
                    for purpose,key in (('sign',session.signing_key),('kx',session.exchange_key)):
                        scalar = key.private_numbers().private_value.to_bytes(32,'big')
                        wrapped,nonce = crypto.wrap_key(blk,scalar,crypto.local_key_aad(org,ticket,purpose,'pending','*',1))
                        pending[purpose] = dict(wrapped=crypto.b64url(wrapped),nonce=crypto.b64url(nonce))
                    self.store.set_meta('cloud_pending_join',crypto.canonical_json(pending).decode())
                reservation = session.reservation(code)
                try:
                    response = self.transport_factory(origin).enroll(reservation)
                except CloudResponseError as exc:
                    raise remote_refusal(exc) from None
                session.accept_reservation(response)
                genesis = response['genesis']
                guard(isinstance(genesis,dict),'join requires existing organization genesis')
                entry = wire.parse_signed_entry(genesis)['entry']
                guard(entry['kind'] == 'genesis' and entry['org_id'] == org,'enrollment genesis identity differs')
                save_reservation(session,self.store,blk,ticket,reservation['proof'])
                cfg = dict(origin=origin,org=org,ticket=ticket,broker=session.broker_id,genesis=genesis)
                self.store.set_meta(CONFIG,crypto.canonical_json(cfg).decode())
            root = wire.hash_object(cfg['genesis']['entry'])
            words = crypto.sas_words(crypto.sas_context(org,root,'broker',session.broker_id,
                session.transcript['sign_pub'],session.transcript['kx_pub']))
            return dict(broker_id=session.broker_id,words=words,state='pending')

    def pair(self, words):
        with self.lock:
            cfg,session = self.config(),self.session()
            session.pin(self.store,crypto.canonical_json(cfg['genesis']['entry']),typed_words=words)
            return dict(paired=True,broker_id=cfg['broker'])

    def _spool(self, client):
        spool = PageSpool()
        client.spools.append(spool)
        return spool

    def policy_evidence(self, client, head):
        """Validate binding and progress before retaining each evidence page."""
        pages,position,scope = self._spool(client),1,None
        cfg = self.config()
        while position is not None:
            guard(len(pages) < MAX_PULL_PAGES,'evidence page limit exceeded','E_SYNC_RETRY')
            page = self.call(client,'GET','policy/evidence',query=dict(from_seq=position,limit=50,
                head_seq=head['seq'],head_hash=head['hash']))
            wire.exact(page,('schema','org_id','broker_id','scope','head','from_seq','through_seq',
                'next_from_seq','control_head','public_staging','own_payloads','tables'))
            guard(page['schema']=='tw-policy-evidence-v1' and page['org_id']==cfg['org']
                and page['broker_id']==cfg['broker'] and page['head']==head
                and type(page['from_seq']) is int and page['from_seq']==position
                and (scope is None or page['scope']==scope),'evidence page binding differs')
            through=wire.integer(page['through_seq'],position)
            continuation=page['next_from_seq']
            guard(through<=head['seq'] and (continuation is None if through==head['seq'] else
                type(continuation) is int and continuation==through+1),'evidence continuation does not progress')
            scope=page['scope']
            pages.append(page);position=continuation
        return pages

    def fetch(self, client):
        records,head,after = self._spool(client),None,0
        while head is None or after < head['seq']:
            guard(len(records)<8192,'policy prefix limit exceeded','E_SYNC_RETRY')
            page = self.call(client,'GET','policy',query=dict(after=after,limit=500))
            wire.exact(page,('entries','head','control_head'))
            wire.parse_head(page['head']);wire.parse_head(page['control_head'])
            if head is not None and page['head'] != head:
                raise PullRetry('policy head changed during pagination')
            head = page['head']
            guard(isinstance(page['entries'],list) and 0<len(page['entries'])<=500,'policy page missing')
            for row in page['entries']:
                guard(type(row['seq']) is int and row['seq']==after+1 and row['seq']<=head['seq'],
                    'policy continuation does not progress')
                records.append(row);after=row['seq']
        cfg = self.config()
        bundle = decode_evidence(self.policy_evidence(client,head),records,org=cfg['org'],broker=cfg['broker'])
        guard(bundle['head'] == head,'policy evidence head differs')
        pages,cursor,offsets = self._spool(client),None,dict(secrets=0,versions=0)
        blobs=[]
        while True:
            guard(len(pages)<MAX_PULL_PAGES,'ciphertext page limit exceeded','E_SYNC_RETRY')
            page = self.call(client,'GET','sync/secrets',query=None if cursor is None else dict(after=cursor))
            wire.exact(page,('secrets','versions','cursor'))
            guard(all(isinstance(page[k],list) and len(page[k])<=100 for k in offsets),'ciphertext page rows exceeded')
            following={k:offsets[k]+len(page[k]) for k in offsets}
            cursor=page['cursor']
            if cursor is not None:
                view=crypto.parse_canonical(crypto.unb64url(cursor))
                guard(view==dict(org_id=cfg['org'],broker_id=cfg['broker'],seq=head['seq'],
                    scope=['*'] if bundle['scope']=='full' else bundle['scope'],offsets=following)
                    and type(view['seq']) is int and all(type(view['offsets'][k]) is int for k in offsets),
                    'ciphertext cursor binding differs')
                guard(sum(following.values())>sum(offsets.values()),'ciphertext continuation does not progress')
            # Raw pages stay on disk; replay retains only bounded current blobs.
            pages.append(page);offsets=following
            blobs.extend({k:row[k] for k in ('version_id','secret_id','kek_id','ciphertext','nonce','wrapped_dek','dek_nonce')}
                for row in page['versions'])
            if cursor is None:break
        def frames():
            by_id={blob['version_id']:blob for blob in blobs}
            for position,(entry,sig) in sorted(bundle['records'].items()):
                client.budget.check()
                blob=by_id.get(entry['body'].get('version_id')) if entry['kind']=='version_add' else None
                yield (policy_record(entry,None if sig is None else crypto.unb64url(sig),entry['ts']),
                    bundle['stages'].get(position),blob,bundle['evidence'])
        # Initial projects enter the verifier only in its post-signature hook.
        return bundle,frames,blobs,pages,[]

    def pull(self):
        try:
            return self._pull_once()
        except PolicyError as exc:
            self.last_code=exc.code
            if exc.code=='E_POLICY_CONFLICT':
                self._protocol_diagnostic()
            raise
        except (OSError,CloudResponseError) as exc:
            self.last_code='E_SYNC_RETRY'
            raise PullRetry('cloud transport unavailable') from None
        except DECODE_ERRORS:
            self.last_code='E_POLICY_CONFLICT'
            self._protocol_diagnostic()
            raise PolicyError('E_POLICY_CONFLICT','cloud response failed verification') from None

    def _protocol_diagnostic(self):
        with self.lock,self.store._transaction_lock:
            cfg=self.config()
            if self.store.cloud_pin(cfg['org']) is not None and self.store.load_cloud_replay(cfg['org']) is not None:
                sync=self.sync()
                if not sync.conflicts():
                    sync.refuse('protocol_violation',self.clock())

    def _pull_once(self):
        # A stalled background pull never queues another pull ahead of delivery.
        guard(self.fetch_lock.acquire(blocking=False),'cloud pull already in progress','E_SYNC_RETRY')
        client=None
        try:
            with self.lock, self.store._transaction_lock:
                cfg,session,client = self.config(),self.session(),self.client()
                guard(session.pinned_root is not None,'typed SAS pairing required','E_SYNC_RETRY')
                blk=self.blk()
                prior=self.store.load_cloud_replay(cfg['org'])
                branch=self.store.cloud_branch(cfg['org'])
            client.spools=[]
            client.budget=PullBudget(self.monotonic)
            if isinstance(client._transport,HTTPSTransport):client._transport.budget=client.budget
            poll = self.call(client,'GET','broker/enrollment')
            if poll.get('state') == 'pending':return dict(state='pending')
            guard(poll.get('state') == 'active','broker is not active','E_SYNC_RETRY')
            bundle,frames,blobs,pages,projects = self.fetch(client)
            keys_response=self.call(client,'GET','keys')
            poll=self.call(client,'GET','broker/enrollment')
            guard(poll.get('state')=='active','enrollment changed during pull','E_SYNC_RETRY')
            final_policy=self.call(client,'GET','policy',query=dict(after=bundle['head']['seq'],limit=1))
            wire.exact(final_policy,('entries','head','control_head'))
            guard(final_policy['head']==bundle['head'],'cloud head changed during material reads','E_SYNC_RETRY')
            bundle['evidence']._blobs.update(org_key_wraps=deepcopy(poll['wraps']),broker_key_wraps=deepcopy(poll['scoped_seals']))
            now=self.clock()
            verifier=self.sync().pull(frames,blobs,projects=projects,evidence=bundle['evidence'],observed_at=now,commit=False)
            client.budget.check()
            with self.lock, self.store._transaction_lock:
                guard(self.config()==cfg and self.seal.state=='unsealed' and self.blk()==blk,
                    'local enrollment changed during pull','E_SYNC_RETRY')
                guard(self.store.cloud_branch(cfg['org'])==branch and self.store.load_cloud_replay(cfg['org'])==prior,
                    'local head changed during pull','E_SYNC_RETRY')
                sync = self.sync()
                now = self.clock()
                # Decode and open remote custody before installing any part of
                # this pull. The durable pickup repeats the exact-head checks.
                sync.pickup_keys(keys_response,blk,session.exchange_key,
                    checkpoint=verifier.export_checkpoint(),commit=False)
                head = sync.accept_pull(verifier,blobs,observed_at=now)
                guard(sync.certificate()['scope'] == bundle['scope'],'evidence scope differs from verified certificate')
                sync.sync_pages(pages,now=now)
                row = self.store.connection.execute('SELECT state FROM cloud_enrollments WHERE org_id=? AND broker_id=?',(cfg['org'],cfg['broker'])).fetchone()
                sync.pickup_keys(keys_response,self.blk(),session.exchange_key)
                if row['state'] != 'complete':
                    certificate=sync.certificate()
                    guard(certificate.get('source')=='certificate' and all(certificate[key]==session.transcript[key] for key in ('sign_pub','kx_pub')),
                        'enrollment requires a logged certificate for the paired keys')
                    # A later committed rekey can replace the initial certificate
                    # wraps before first pickup. Current custody is independently
                    # opened above; an active server flag never grants it.
                    with self.store.transaction(immediate=True) as db:
                        session._paired_row(self.store,db)
                        guard(sync.checkpoint()['head']==head,'enrollment head changed before completion','E_SYNC_RETRY')
                        db.execute("UPDATE cloud_enrollments SET state='complete',certificate_json=?,head_json=?,custody_json=? WHERE org_id=? AND broker_id=? AND state='pinned'",
                            (crypto.canonical_json(certificate).decode(),crypto.canonical_json(head).decode(),
                             crypto.canonical_json(dict(generation=sync.checkpoint()['epochs']['generation'],head=head,source='verified-current-epoch')).decode(),cfg['org'],cfg['broker']))
                completion=sync.completion()
                self.redaction_sink()
            self.call(client,'POST','sync/head',completion)
            return dict(state='active',head=head)
        finally:
            if client is not None:
                for spool in getattr(client,'spools',[]):spool.close()
            self.fetch_lock.release()

    def tick(self):
        if not self.enabled or self.seal.state != 'unsealed' or self.monotonic() < self.next_attempt:
            return
        try:
            self.pull()
        except (OSError,CloudResponseError,PullRetry) as exc:
            self.last_code = getattr(exc,'code','E_SYNC_RETRY')
            self.failures = min(self.failures+1,10)
            self.next_attempt = self.monotonic()+min(300,2**self.failures)
        except PolicyError as exc:
            self.last_code = exc.code
            if exc.code=='E_SYNC_RETRY':
                self.failures=min(self.failures+1,10)
                self.next_attempt=self.monotonic()+min(300,2**self.failures)
            else:
                self.next_attempt = self.monotonic()+30
        except DECODE_ERRORS as exc:
            self.last_code = 'E_POLICY_CONFLICT'
            self._protocol_diagnostic()
            self.next_attempt = self.monotonic()+30
        else:
            self.failures,self.last_code = 0,None
            self.next_attempt = self.monotonic()+10

    def status(self):
        if not self.enabled:
            return dict(mode='local')
        cfg = self.config()
        pin = self.store.cloud_pin(cfg['org'])
        state = self.store.load_cloud_replay(cfg['org']) if pin is not None else None
        enrollment = self.store.connection.execute('SELECT state FROM cloud_enrollments WHERE org_id=? AND broker_id=?',(cfg['org'],cfg['broker'])).fetchone()
        observations = [] if state is None else self.store.cloud_observations(cfg['org'])['heads']
        return dict(mode='cloud',org_id=cfg['org'],broker_id=cfg['broker'],paired=pin is not None,
            head=None if state is None else state['head'],last_code=self.last_code,
            enrollment_state=enrollment['state'],scope=None if state is None else self.sync().certificate()['scope'],
            observed_at=None if not observations else observations[-1]['observed_at'],
            conflicts=[] if state is None else [dict(conflict_id=r['conflict_id'],reason=r['reason']) for r in self.sync().conflicts()])

    def secret_row(self,path):
        sync = self.sync()
        secret = next((s for s in sync.agent_metadata() if s['path'] == path),None)
        if secret is None:
            return None
        version = next((v for v in sync.checkpoint()['epochs']['versions'] if v['secret_id']==secret['secret_id'] and v['state']=='active'),None)
        project = self.store.connection.execute('SELECT no_shell FROM projects WHERE slug=?',(secret['project'],)).fetchone()
        return dict(secret,short=version is None or version['length']-16 < 8,allow_short_delivery=0,
            no_shell=sync.checkpoint()['epochs']['secrets'][secret['secret_id']].get('no_shell',False),
            project_no_shell=sync.checkpoint()['authority'].get('admin_policy',{}).get('projects',{}).get(secret['project'],{}).get('no_shell',False)
                or (0 if project is None else project[0]))

    def read(self,path):
        sync = self.sync(); state = sync.checkpoint()
        secret = next((s for s in state['epochs']['secrets'].values() if s['path'] == path),None)
        guard(secret is not None,'secret unavailable','E_DENIED')
        version = next((v for v in state['epochs']['versions'] if v['secret_id']==secret['secret_id'] and v['state']=='active'),None)
        guard(version is not None,'active version unavailable','E_DENIED')
        return sync.read_value(version['version_id'],self.blk(),now=self.clock())

    def values(self):
        cfg = self.config()
        state = self.store.load_cloud_replay(cfg['org']) if self.store.cloud_pin(cfg['org']) is not None else None
        if state is None or self.seal.state != 'unsealed':
            return {}
        sync = self.sync()
        visible = {s['secret_id']:s['path'] for s in sync.agent_metadata()}
        result = {}
        for version in state['epochs']['versions']:
            if version['secret_id'] in visible and version['state']=='active':
                value = sync._read_value(version['version_id'],self.blk(),now=self.clock(),delivery=False)
                result.setdefault(visible[version['secret_id']],[]).append(value)
        return result

    def permission_grants(self, principal):
        sync = self.sync(); head = sync.checkpoint()['head']
        state = self.store.cloud_request_state(sync.org,head)
        guard('grants' in state,'verified grants unavailable')
        policy = sync.checkpoint()['authority'].get('admin_policy',{})
        subject = policy.get('principals',{}).get(principal)
        if subject is not None and (subject['state']!='active' or subject['broker_id'] not in (None,sync.broker)):
            raise PolicyError('E_DENIED','signed principal is disabled or belongs to another broker')
        return [g for g in list(state['grants'].values())+list(policy.get('grants',{}).values())
            if g['principal_id']==principal and not g.get('revoked',False)]

    def put(self,path,value,*,secret_class='sensitive',kind='opaque',source='put',authorize=None,principal_id='human:operator',**_kwargs):
        self.pull()
        resume = None
        with self.lock, self.store._transaction_lock:
            sync = self.sync()
            state = sync.checkpoint()
            secret = next((s for s in state['epochs']['secrets'].values() if s['path'] == path), None)
            if secret is not None:
                guard(secret['class'] == secret_class, 'secret class differs', 'E_POLICY')
                guard(secret_class in ('standard','sensitive'),
                    'A person must activate restricted secrets in the console.', 'E_ROTATION_UNAVAILABLE')
                sync.require_delivery(secret['project'], secret_class, self.clock())
                generation = state['epochs']['generation']
                fk = next(k['key_id'] for k in state['epochs']['keyring'] if k['purpose'] == 'fingerprint')
                fingerprint = crypto.cloud_fingerprint(self.store.cloud_local_key(self.blk(), org=sync.org,
                    broker=sync.broker, key_id=fk, purpose='fingerprint', scope='*', generation=generation), value).hex()
                for version in state['epochs']['versions']:
                    receipt = self.store.meta('cloud_write_'+version['version_id'])
                    if (version['secret_id'] == secret['secret_id'] and version['state'] == 'pending'
                            and self.store.meta('cloud_rotation_'+version['version_id']) == '1' and receipt is not None):
                        receipt = json.loads(receipt)
                        guard(receipt['principal_id'] == principal_id, 'activation belongs to another principal', 'E_DENIED')
                        guard(receipt == dict(principal_id=principal_id,path=path,fingerprint=fingerprint)
                            and version['fingerprint'] == fingerprint, 'another activation is pending', 'E_SYNC_RETRY')
                        resume = dict(path=path, version_no=version['version_no'], fingerprint_prefix=fingerprint[:12],
                            activation_version_id=version['version_id'])
                        break
        result = resume or self._publish_version(path,value,secret_class=secret_class,kind=kind,source=source,
            authorize=authorize,principal_id=principal_id)
        vid = result.pop('activation_version_id', None)
        if vid is not None:
            self._activate_version(vid, secret_class=secret_class, authorize=authorize)
        return result

    def _activate_version(self, version_id, *, secret_class, authorize):
        import uuid
        from .cloud_epochs import EpochReplay
        with self.lock, self.store._transaction_lock:
            if authorize is not None:
                authorize()
            sync, session, now = self.sync(), self.session(), self.clock()
            state = sync.checkpoint()
            version = next((v for v in state['epochs']['versions'] if v['version_id'] == version_id), None)
            guard(version is not None and version['state'] == 'pending', 'activation target is no longer pending', 'E_SYNC_RETRY')
            secret = state['epochs']['secrets'][version['secret_id']]
            guard(secret['class'] in ('standard','sensitive'),
                'A person must activate restricted secrets in the console.', 'E_ROTATION_UNAVAILABLE')
            guard(secret['class'] == secret_class, 'secret class changed before activation', 'E_POLICY')
            sync.require_delivery(secret['project'], secret['class'], now)
            active = [v for v in state['epochs']['versions'] if v['secret_id'] == secret['secret_id'] and v['state'] == 'active']
            guard(len(active) == 1, 'activation requires one active predecessor')
            key = 'cloud_activation_'+version_id
            retained = self.store.meta(key)
            retained = None if retained is None else json.loads(retained)
            if retained is None or retained['head'] != state['head']:
                entry = dict(v=2,org_id=sync.org,seq=state['head']['seq']+1,prev_hash=state['head']['hash'],ts=now,
                    kind='version_state',signer=dict(kind='broker',id=sync.broker),
                    body=dict(secret_id=secret['secret_id'],version_id=version_id,from_state='pending',to_state='active',
                        supersedes_version_id=active[0]['version_id']))
                retained = dict(head=state['head'],logical_id=str(uuid.uuid4()),payload=dict(entry=entry,
                    sig=crypto.b64url(crypto.p256_sign(session.signing_key,crypto.policy_context(sync.org,wire.hash_object(entry))))))
                self.store.set_meta(key, crypto.canonical_json(retained).decode())
            checker = EpochReplay()
            checker._state = deepcopy(state['epochs'])
            checker.apply(retained['payload']['entry'], AuthorityView(state['authority']).epoch_snapshot(state['head'],
                sorted(state['epochs']['active_kek'])), received_at=now)
            client = self.client()
            request = client.prepare('POST',self.config()['origin']+f'/v1/orgs/{sync.org}/policy',
                retained['payload'],logical_id=retained['logical_id'])
        try:
            client.send_http(request)
        except CloudResponseError as exc:
            raise remote_refusal(exc) from None
        self.pull()
        with self.lock, self.store._transaction_lock:
            current = next((v for v in sync.checkpoint()['epochs']['versions'] if v['version_id'] == version_id), None)
            guard(current is not None and current['state'] == 'active', 'activation awaiting verified pull', 'E_SYNC_RETRY')

    def _publish_version(self,path,value,*,secret_class='sensitive',kind='opaque',source='put',authorize=None,principal_id='human:operator',**_kwargs):
        import uuid
        with self.lock, self.store._transaction_lock:
            if authorize is not None:
                authorize()
            sync,session = self.sync(),self.session()
            state,now = sync.checkpoint(),self.clock()
            project = path.split('/')[0]
            from .cloud_requests import target_path
            target_path(path)
            sync.require_delivery(project,secret_class,now)
            secret = next((s for s in state['epochs']['secrets'].values() if s['path']==path),None)
            guard(secret is None or secret['class']==secret_class,'secret class differs','E_POLICY')
            generation = state['epochs']['generation']
            kid = state['epochs']['active_kek'].get(project)
            guard(kid is not None,'unknown cloud project','E_SCOPE')
            def key(key_id,purpose,scope):
                return self.store.cloud_local_key(self.blk(),org=sync.org,broker=sync.broker,
                    key_id=key_id,purpose=purpose,scope=scope,generation=generation)
            kek = key(kid,'kek',project)
            fk_id = next(r['key_id'] for r in state['epochs']['keyring'] if r['purpose']=='fingerprint')
            fingerprint = crypto.cloud_fingerprint(key(fk_id,'fingerprint','*'),value).hex()
            for version in state['epochs']['versions']:
                receipt=self.store.meta('cloud_write_'+version['version_id'])
                if receipt is None:continue
                receipt=json.loads(receipt)
                if (secret is not None and version['secret_id']==secret['secret_id'] and version['state']=='active'
                        and receipt==dict(principal_id=principal_id,path=path,fingerprint=fingerprint)
                        and crypto.compare_digest(version['fingerprint'],fingerprint)):
                    return dict(path=path,version_no=version['version_no'],fingerprint_prefix=fingerprint[:12])
            guard(secret is None or secret_class in ('standard','sensitive'),
                'A person must activate restricted secrets in the console.', 'E_ROTATION_UNAVAILABLE')
            guard(secret is None or sum(v['secret_id'] == secret['secret_id'] and v['state'] == 'active' for v in state['epochs']['versions']) == 1,
                'An existing secret requires a single active predecessor.', 'E_ROTATION_UNAVAILABLE')
            pending = self.store.connection.execute('SELECT * FROM cloud_unpublished WHERE org_id=?',(sync.org,)).fetchall()
            payload = None
            for row in pending:
                old = json.loads(row['payload_json'])
                prior_secret = state['epochs']['secrets'].get(old['version']['secret_id'],old.get('secret'))
                if prior_secret and prior_secret['path']==path:
                    receipt=self.store.meta('cloud_write_'+row['version_id'])
                    guard(receipt is not None and json.loads(receipt)['principal_id']==principal_id,
                        'publication belongs to another principal','E_DENIED')
                    guard(old['entries'][-1]['entry']['body']['fingerprint']==fingerprint,'another publication is pending','E_SYNC_RETRY')
                    payload = old
                    if json.loads(row['head_json'])!=state['head']:
                        saved=self.store.connection.execute("SELECT generation FROM cloud_local_keys WHERE org_id=? AND broker_id=? AND key_id=? AND purpose='kek' AND scope=? ORDER BY generation DESC LIMIT 1",
                            (sync.org,sync.broker,row['kek_id'],project)).fetchone()
                        guard(saved is not None,'retained publication key unavailable','E_SYNC_RETRY')
                        old_key=self.store.cloud_local_key(self.blk(),org=sync.org,broker=sync.broker,key_id=row['kek_id'],purpose='kek',scope=project,generation=saved['generation'])
                        self.store.set_meta('cloud_publish_'+row['version_id'],str(uuid.uuid4()))
                        payload=sync.rebuild_unpublished(row['version_id'],old_key,kek,session.signing_key,now=now)
                        sync.stage_version(payload,now=now)
            if payload is None:
                sid = self.store.new_id('sec_') if secret is None else secret['secret_id']
                vid = self.store.new_id('ver_')
                versions = [v for v in state['epochs']['versions'] if v['secret_id']==sid]
                number = max((v['version_no'] for v in versions),default=0)+1
                dek = crypto.random_key()
                ciphertext,nonce = crypto.aes_encrypt(dek,value,crypto.value_aad(sync.org,sid,number))
                wrapped,dek_nonce = crypto.wrap_key(kek,dek,crypto.dek_aad(sync.org,vid,kid))
                blob = dict(version_id=vid,secret_id=sid,kek_id=kid,ciphertext=ciphertext.hex(),
                    nonce=nonce.hex(),wrapped_dek=wrapped.hex(),dek_nonce=dek_nonce.hex())
                body = dict(version_id=vid,secret_id=sid,version_no=number,state='pending' if secret is not None else 'active',
                    kek_id=kid,fingerprint=fingerprint,length=len(ciphertext),source=source,
                    value_digest=crypto.value_digest(ciphertext,nonce),envelope_digest=crypto.envelope_digest(kid,wrapped,dek_nonce))
                bodies = []
                if secret is None:
                    secret = dict(secret_id=sid,path=path,project=project,**{'class':secret_class},kind=kind)
                    bodies.append(('secret_create',secret))
                bodies.append(('version_add',body))
                seq,prev = state['head']['seq']+1,state['head']['hash']
                entries=[]
                for entry_kind,entry_body in bodies:
                    entry = dict(v=2,org_id=sync.org,seq=seq,prev_hash=prev,ts=now,
                        kind=entry_kind,body=entry_body,signer=dict(kind='broker',id=sync.broker))
                    prev,seq = wire.hash_object(entry),seq+1
                    entries.append(dict(entry=entry,sig=crypto.b64url(crypto.p256_sign(session.signing_key,crypto.policy_context(sync.org,prev)))))
                payload = dict(version=blob,entries=entries)
                if len(entries)==2:
                    payload['secret']=secret
                self.store.set_meta('cloud_publish_'+vid,str(uuid.uuid4()))
                self.store.set_meta('cloud_write_'+vid,crypto.canonical_json(dict(principal_id=principal_id,path=path,fingerprint=fingerprint)).decode())
                if body['state'] == 'pending':
                    self.store.set_meta('cloud_rotation_'+vid, '1')
                sync.stage_version(payload,now=now)
            vid = payload['version']['version_id']
            logical = self.store.meta('cloud_publish_'+vid)
            guard(logical is not None,'publication request identity missing','E_SYNC_RETRY')
            client = self.client()
            url = self.config()['origin']+f'/v1/orgs/{sync.org}/sync/versions'
        try:
            client.send_http(client.prepare('POST',url,payload,logical_id=logical))
        except CloudResponseError as exc:
            raise remote_refusal(exc) from None
        self.pull()
        with self.lock, self.store._transaction_lock:
            guard(self.store.connection.execute('SELECT 1 FROM cloud_unpublished WHERE org_id=? AND version_id=?',(sync.org,vid)).fetchone() is None,
                'publication awaiting verified pull','E_SYNC_RETRY')
            published=next((v for v in sync.checkpoint()['epochs']['versions'] if v['version_id']==vid),None)
            if published is not None and published['state'] == 'pending' and payload['entries'][-1]['entry']['body']['state'] == 'pending':
                return dict(path=path,version_no=published['version_no'],fingerprint_prefix=fingerprint[:12],activation_version_id=vid)
            guard(published is not None and published['state']=='active','Published cloud version is not active; signed activation is unavailable','E_ROTATION_UNAVAILABLE')
            return dict(path=path,version_no=payload['entries'][-1]['entry']['body']['version_no'],fingerprint_prefix=fingerprint[:12])

    def resolve(self, admin_session, *, expected_head, through_conflict, typed_root):
        """Select one fully replayed history using the existing admin connection."""
        import tempfile
        from .admin_server import AdminSession
        from .store import Store
        with ExitStack() as resources:
            with self.lock,self.store._transaction_lock:
                guard(isinstance(admin_session,AdminSession) and admin_session.is_authenticated(),
                    'resolution requires authenticated admin session','E_AUTH')
                blk = self.blk()
                sync,cfg = self.sync(),self.config()
                wire.parse_head(expected_head)
                guard(typed_root == self.store.cloud_pin(sync.org),'independent resolution root differs')
                conflicts = sync.conflicts()
                guard(bool(conflicts) and type(through_conflict) is int and conflicts[-1]['conflict_id']==through_conflict,
                    'resolution must cover exactly current conflicts')
                old_head = sync.checkpoint()['head']
                client,session = self.client(),self.session()
            client.spools=[]
            client.budget=PullBudget(self.monotonic)
            if isinstance(client._transport,HTTPSTransport):client._transport.budget=client.budget
            resources.callback(lambda: [spool.close() for spool in client.spools])
            bundle,frames,blobs,pages,projects = self.fetch(client)
            guard(bundle['head'] == expected_head,'selected resolution head differs')
            keys_response = self.call(client,'GET','keys')
            now = self.clock()
            with tempfile.TemporaryDirectory(prefix='tw-resolution-') as temporary:
                with Store(temporary).open(create=True) as candidate:
                    candidate.initialize_cloud_replay(sync.org,typed_root)
                    checked = self.sync(store=candidate)
                    checked.pull(frames,blobs,projects=projects,evidence=bundle['evidence'],observed_at=now)
                    guard(checked.certificate()['scope'] == bundle['scope'],'resolution certificate scope differs')
                    checked.sync_pages(pages,now=now)
                    checked.pickup_keys(keys_response,blk,session.exchange_key)
                    snapshot = checked.checkpoint()
                    requests = candidate.cloud_request_state(sync.org,snapshot['head'])
                    keys = [tuple(row) for row in candidate.connection.execute('SELECT * FROM cloud_local_keys WHERE org_id=? AND broker_id=?',(sync.org,sync.broker))]
                    client.budget.check()
                    with self.lock,self.store._transaction_lock:
                        guard(admin_session.is_authenticated() and self.seal.state=='unsealed' and self.blk()==blk,
                            'admin session expired during history selection','E_AUTH')
                        with self.store.transaction(immediate=True) as db:
                            guard(sync.checkpoint()['head']==old_head and sync.conflicts()==conflicts,
                                'local state changed during history selection','E_SYNC_RETRY')
                            cursor = db.execute('INSERT INTO cloud_verified_branches(org_id,through_conflict,selected_head_json,root_hash,authenticated_by,selected_at) VALUES (?,?,?,?,?,?)',
                                (sync.org,through_conflict,crypto.canonical_json(expected_head).decode(),typed_root,'existing-admin-session',now))
                            branch = cursor.lastrowid
                            db.execute('INSERT INTO cloud_branch_replay VALUES (?,?,?,?,?,?)',(branch,expected_head['seq'],expected_head['hash'],
                                crypto.canonical_json(snapshot['authority']).decode(),crypto.canonical_json(snapshot['epochs']).decode(),crypto.canonical_json(requests).decode()))
                            db.execute('INSERT INTO cloud_branch_observations VALUES (?,?,?,?)',(branch,expected_head['seq'],expected_head['hash'],now))
                            db.execute('INSERT INTO cloud_active_branch VALUES (?,?) ON CONFLICT(org_id) DO UPDATE SET branch_id=excluded.branch_id',(sync.org,branch))
                            db.execute('DELETE FROM cloud_sync_blobs WHERE org_id=?',(sync.org,))
                            for blob in blobs:
                                db.execute('INSERT INTO cloud_sync_blobs VALUES (?,?,?,?)',(sync.org,blob['version_id'],expected_head['seq'],crypto.canonical_json(blob).decode()))
                            # Old branch snapshots and conflicts remain immutable.
                            # Current independently opened custody replaces only the
                            # same key identities, retaining prior exposure evidence.
                            for row in keys:
                                db.execute('INSERT INTO cloud_local_keys VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(org_id,broker_id,key_id,generation) DO UPDATE SET purpose=excluded.purpose,scope=excluded.scope,wrapped_key=excluded.wrapped_key,nonce=excluded.nonce',row)
                            self.store.prune_cloud_custody(db,sync.org,sync.broker,snapshot['authority'],snapshot['epochs'])
            self.redaction_sink()
            return dict(resolved=True,head=expected_head,through_conflict=through_conflict)
