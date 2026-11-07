import { describe, expect, it } from 'vitest';
import { aesEncrypt, hex, sha256, utf8, valueDigest, valueAad } from '../../core/src/index';
import { eligibility, authoritySnapshot, type AuthorityView } from '../src/epochs/authority';
import { ciphertextToSignedDigest, signedToCiphertextDigest } from '../src/epochs/digests';
import { keyringDigest } from '../src/epochs/validation';
import { planForTrigger } from '../src/epochs/plans';
import { emptyEpochState } from '../src/epochs/types';
import { constantTimeHash } from '../src/epochs/control';
import { recipientHints, verifyRecipientHints } from '../src/epochs/recipients';
import {continuousKeeperSince} from '../src/epochs/continuity';
import { pendingRemovedProjects, EpochView } from '../src/epochs/view';
import { initialized, allow, keys, entry, NOW } from './epoch-fixtures';
describe('epoch core and authority ports', () => {
  it('pins a domain-separated keyring digest vector that binds id and version', async () => {
    const row = { key_id: 'key-a', purpose: 'kek' as const, project: 'a', version: 2, nonce: '00'.repeat(12), wrapped_key: '11'.repeat(48), mk_generation: 2, aad_v: 2 as const };
    expect(await keyringDigest(row)).toBe('5e97acbf89ba93d9b8bdb661533f998359f7ba49157f506c10bdd722db9d9d3a');
    expect(await keyringDigest({ ...row, key_id: 'key-b' })).not.toBe(await keyringDigest(row));
    expect(await keyringDigest({ ...row, version: 3 })).not.toBe(await keyringDigest(row));
  });
  it('historical value_digest is ciphertext-only and the SQL/API translation round-trips', async () => {
    const plaintext = utf8('low entropy fixture'), box = await aesEncrypt(new Uint8Array(32), plaintext, valueAad('a'.repeat(32), 's', 1));
    const digest = await valueDigest(box.ciphertext, box.nonce);
    expect(digest).not.toBe(hex(await sha256(plaintext)));
    const joined = new Uint8Array(box.ciphertext.length + box.nonce.length);
    joined.set(box.ciphertext);
    joined.set(box.nonce, box.ciphertext.length);
    expect(digest).toBe(hex(await sha256(joined)));
    expect(ciphertextToSignedDigest(signedToCiphertextDigest({ value_digest: digest }))).toEqual({ value_digest: digest });
  });
  it('certification adapter uses W1 member rank one plus the certified key_holder flag', async () => {
    const calls: unknown[] = [];
    const cert = { member_key_id: 'k', member_id: 'm', kx_pub: 'pub', sign_pub: 'pub', key_holder: true, state: 'active' as const };
    const view: AuthorityView = { isCertified: (...args) => { calls.push(args); return true; }, certificateAt: () => cert, active: () => [cert], brokerCertificateAt: () => null };
    const head = { seq: 9, hash: 'a'.repeat(64) };
    expect(await eligibility(view).isCertified('k', 'key_holder', head)).toBe(true);
    expect(calls).toEqual([['k', 1, head]]);
    cert.key_holder = false;
    expect(await eligibility(view).isCertified('k', 'key_holder', head)).toBe(false);
    expect(await eligibility(view).isCertified('b', 'keeper', head)).toBe(false);
  });
  it('unknown trigger reasons and unscoped project lists fail closed', () => {
    const state = emptyEpochState();
    state.generation = 1;
    state.active_kek = { a: 'k' };
    expect(() => planForTrigger('a'.repeat(32), 2, { kind: 'full', reason: 'made_up', projects: [] }, state, new Date().toISOString())).toThrow();
    expect(() => planForTrigger('a'.repeat(32), 2, { kind: 'projects', reason: 'scoped_broker_revoked', projects: ['foreign'] }, state, new Date().toISOString())).toThrow();
    expect(planForTrigger('a'.repeat(32), 2, { kind: 'full', reason: 'key_holder_removed', projects: [] }, state, new Date().toISOString())).toMatchObject({ table: 'rekey_plans', ifAbsent: true, values: { from_generation: 1, to_generation: 2, state: 'open' } });
  });
  it('custody views reject another head and preserve full exposure until commit', async () => {
    const f = await initialized();
    f.snapshot.brokers = [{ id: 'b', kx_pub: f.snapshot.members[0].kx_pub, scope: ['a'], keeper: false, full_custody_generation: 1 }];
    expect(new EpochView(f.state, f.snapshot).effectiveCustody('b', f.snapshot.head)).toBe('full');
    f.state.generation = 2;
    expect(new EpochView(f.state, f.snapshot).effectiveCustody('b', f.snapshot.head)).toEqual(['a']);
    expect(() => new EpochView(f.state, f.snapshot).effectiveCustody('b', { ...f.snapshot.head, seq: 8 })).toThrow();
  });
  it('keeper independently rejects substituted, extra, removed and scope-changed server hints', async () => {
    const f = await initialized();
    f.snapshot.brokers = [{ id: 'scoped', kx_pub: f.snapshot.members[0].kx_pub, scope: ['a'], keeper: false, full_custody_generation: null }];
    const hints = await recipientHints(f.snapshot, allow.authority);
    await expect(verifyRecipientHints(f.snapshot, hints, allow.authority)).resolves.toBeUndefined();
    for (const changed of [() => { hints.recipients[0].kx_pub = '04' + '00'.repeat(64); }, () => { hints.recipients.pop(); }, () => { hints.recipients.push({ ...hints.recipients[0], id: 'extra' }); }, () => { hints.scoped[0].projects.push('b'); }]) {
      const original = structuredClone(hints);
      changed();
      await expect(verifyRecipientHints(f.snapshot, hints, allow.authority)).rejects.toThrow('rekey_recipient_mismatch');
      Object.assign(hints, original);
    }
  });
  it('narrowed project exposure persists until any later committed rekey covers that project', async () => {
    const f = await initialized(), changes = [{ seq: 5, from_scope: ['a', 'b'], to_scope: ['a'] }], head = { seq: 10, hash: 'c'.repeat(64) };
    expect(pendingRemovedProjects(changes, f.state, head)).toEqual(['b']);
    f.snapshot.head = head;
    f.snapshot.brokers = [{ id: 's', kx_pub: f.snapshot.members[0].kx_pub, scope: ['a'], keeper: false, full_custody_generation: null, pending_removed_projects: ['b'] }];
    expect(new EpochView(f.state, f.snapshot).effectiveCustody('s', head)).toEqual(['a', 'b']);
    f.state.epochs.push({ seq: 7, commit_seq: 8, kind: 'full', covered_triggers: [5,6], generation: 2, active_kek: { a: 'new-a', b: 'new-b' }, projects: ['a', 'b'], trigger_seq: 6 });
    expect(pendingRemovedProjects(changes, f.state, head)).toEqual([]);
    expect(pendingRemovedProjects(changes, f.state, { ...head, seq: 6 })).toEqual(['b']);
  });
  it('custody evidence rejects unverified and mismatched pending downgrade coverage', async () => {
    const f = await initialized();
    f.snapshot.head = { seq: 6, hash: 'e'.repeat(64) };
    f.snapshot.brokers = [{ id: 's', kx_pub: f.snapshot.members[0].kx_pub, scope: ['a'], keeper: false, full_custody_generation: 1, scope_changes: [{ seq: 5, from_scope: 'full', to_scope: ['a'] }] }];
    expect(() => new EpochView(f.state, f.snapshot).custodyEvidence('s', f.snapshot.head)).toThrow('Unverified');
    f.snapshot.rekey_triggers = [{ seq: 5, kind: 'full', reason: 'full_to_scoped_downgrade', projects: [] }];
    expect(new EpochView(f.state, f.snapshot).custodyEvidence('s', f.snapshot.head)).toMatchObject({ custody: 'full', pending_downgrades: [5] });
    f.state.generation = 2;
    expect(() => new EpochView(f.state, f.snapshot).custodyEvidence('s', f.snapshot.head)).toThrow('matching committed');
    f.state.epochs.push({ seq: 6, commit_seq: 6, kind: 'full', covered_triggers: [5], generation: 2, projects: ['a', 'b'], active_kek: { a: 'x', b: 'y' } });
    expect(new EpochView(f.state, f.snapshot).custodyEvidence('s', f.snapshot.head)).toMatchObject({ custody: ['a'], pending_downgrades: [] });
  });
  it('a later committed full rekey covers both a downgrade and a further narrowing', async () => {
    const f = await initialized();
    f.snapshot.head = { seq: 6, hash: 'e'.repeat(64) };
    f.snapshot.brokers = [{ id: 's', kx_pub: f.snapshot.members[0].kx_pub, scope: ['a'], keeper: false, full_custody_generation: 1, scope_changes: [{ seq: 5, from_scope: 'full', to_scope: ['a', 'b'] }, { seq: 6, from_scope: ['a', 'b'], to_scope: ['a'] }] }];
    f.snapshot.rekey_triggers = [5, 6].map(seq => ({ seq, kind: 'full' as const, reason: 'full_to_scoped_downgrade', projects: [] }));
    const k = await keys(f.snapshot, f.state, 2), e = entry('epoch_rotate', { from_generation: 1, to_generation: 2, trigger_seq: 6, ...k.body }, f.snapshot);
    const { transitionEpoch } = await import('../src/epochs/engine');
    const out = await transitionEpoch(f.state, e, f.snapshot, NOW, k.stage, { ...allow, triggerAt: async () => ({ kind: 'full', reason: 'full_to_scoped_downgrade', projects: [] }) });
    f.snapshot.head = { seq: e.seq, hash: 'f'.repeat(64) };
    expect(out.state.epochs.at(-1).covered_triggers).toEqual([5, 6]);
    expect(new EpochView(out.state, f.snapshot).custodyEvidence('s', f.snapshot.head)).toMatchObject({ custody: ['a'], pending_downgrades: [] });
  });
  it('review M3: a project epoch credits only its named removal trigger',async()=>{
    const f=await initialized();f.snapshot.head={seq:6,hash:'c'.repeat(64)};f.snapshot.brokers=[{id:'s',kx_pub:f.snapshot.members[0].kx_pub,scope:['a'],keeper:false,full_custody_generation:null}];
    f.snapshot.rekey_triggers=[{seq:4,kind:'projects',reason:'scoped_broker_revoked',projects:['b']},{seq:5,kind:'projects',reason:'scoped_broker_narrowed',projects:['b']}];
    const k=await keys(f.snapshot,f.state,1,['b']),e=entry('epoch_rotate_projects',{trigger_seq:4,omk_generation:1,projects:{b:{from_kek_id:'kek_b_1',to_kek_id:'kek_b_2'}},keyring:k.body.keyring,scoped_seals:k.body.scoped_seals},f.snapshot),{transitionEpoch}=await import('../src/epochs/engine');
    const out=await transitionEpoch(f.state,e,f.snapshot,NOW,k.stage,{...allow,triggerAt:async()=>({kind:'projects',reason:'scoped_broker_revoked',projects:['b']})});
    const changes=[{seq:5,from_scope:['a','b'],to_scope:['a']}];
    expect({covered:out.state.epochs.at(-1)!.covered_triggers,pending:pendingRemovedProjects(changes,out.state,{seq:e.seq,hash:'d'.repeat(64)})}).toEqual({covered:[4],pending:['b']});
    f.snapshot.head={seq:e.seq,hash:'d'.repeat(64)};const full=await keys(f.snapshot,out.state,2),rotate=entry('epoch_rotate',{from_generation:1,to_generation:2,reason:'manual',...full.body},f.snapshot),committed=await transitionEpoch(out.state,rotate,f.snapshot,NOW,full.stage,allow);
    expect(pendingRemovedProjects(changes,committed.state,{seq:rotate.seq,hash:'e'.repeat(64)})).toEqual([]);
  });
  it('keeper continuity survives ordinary recertification and resets after any ineligible interval',()=>{
    expect(continuousKeeperSince([{seq:2,eligible:true},{seq:4,eligible:true}],8)).toBe(2);
    expect(continuousKeeperSince([{seq:2,eligible:true},{seq:4,eligible:false},{seq:6,eligible:true}],8)).toBe(6);
    expect(continuousKeeperSince([{seq:2,eligible:true},{seq:4,eligible:false}],8)).toBeNull();
    expect(continuousKeeperSince([],8,1)).toBe(1);expect(()=>continuousKeeperSince([{seq:9,eligible:true}],8)).toThrow();
  });
  it('fixed-size claim hash comparison checks every position and rejects lengths', () => {
    const a = new Uint8Array(32);
    expect(constantTimeHash(a, a)).toBe(true);
    for (let i = 0; i < 32; i++) {
      const b = new Uint8Array(32);
      b[i] = 1;
      expect(constantTimeHash(a, b)).toBe(false);
    }
    expect(constantTimeHash(a, new Uint8Array(31))).toBe(false);
  });
});
