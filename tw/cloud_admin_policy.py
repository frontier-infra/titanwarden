"""Signed W21 metadata and access-policy transitions for broker public replay."""
from copy import deepcopy
import re
from urllib.parse import urlsplit

from . import crypto,cloud_wire as wire
from .cloud_policy import _actor,require
from .cloud_requests import operations,target_path
from .policy_log import utc_millis


FIELDS = {
    'project_put':('slug','change_policy','no_shell','lead_principal'),
    'project_member_put':('slug','member_id','enabled'),
    'secret_update':('secret_id','class','no_shell','allowed_hosts'),
    'placement_add':('placement_id','secret_id','sink_kind','locator'),
    'placement_rm':('placement_id',),
    'principal_add':('principal_id','kind','display','project','parent_id','broker_id'),
    'principal_disable':('principal_id',),
    'grant_add':('grant_id','principal_id','pattern','ops','max_class','expires_at','reason'),
    'grant_revoke':('grant_id',),
}
KINDS=frozenset(FIELDS)


def initial(projects):
    return dict(projects={p:dict(slug=p,change_policy='auto',no_shell=False,lead_principal=None) for p in projects},
        project_members={},principals={},grants={},placements={})


def identifier(value):
    wire.text(value)
    require(len(value.encode('utf-16-le'))<=4096 and not re.search(r'[\x00-\x1f|]',value),'invalid administration identifier')
    return value


def slug(value):
    identifier(value)
    require(bool(re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}',value)),'invalid project slug')
    return value


def pattern(value):
    parts=identifier(value).split('/')
    slug(parts[0])
    require(len(parts)>=2 and all(part not in ('','.','..') and
        (bool(re.fullmatch(r'[a-zA-Z0-9_.-]+',part)) or part=='*' and index==len(parts)-2)
        for index,part in enumerate(parts[1:])),'invalid direct grant pattern')
    return parts[0]


def locator(kind,value):
    fields={'railway_var':('project','environment','service','var'),'github_secret':('repo','name'),
        'cloudflare_secret':('account_id','script','name'),'coolify_env':('application_id','key'),'manual':('url','note')}
    require(kind in fields and isinstance(value,dict),'invalid placement locator')
    wire.exact(value,fields[kind],('environment',) if kind=='github_secret' else ())
    for item in value.values():identifier(item)
    def opaque(item):
        require(bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',item)),'invalid opaque locator segment')
    def variable(item):
        require(bool(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}',item)),'invalid locator variable name')
    def credential(item):
        return re.search(r'\b(?:bearer|basic)\b|(?:password|api[_ -]?key|token|secret)\s*[:=]|\b(?:sk-|ghp_|github_pat_|xox[baprs]-)[A-Za-z0-9_-]+|[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]+|[A-Fa-f0-9]{32,}|(?=[A-Za-z0-9_-]{24,})(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{24,}',item,re.I) is not None
    if kind=='railway_var':
        require(all(re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',value[key]) for key in ('project','environment','service')),'placement requires explicit UUIDs')
        variable(value['var'])
    if kind=='github_secret':
        require(len(value['repo'].split('/'))==2,'invalid placement repository')
        for part in value['repo'].split('/'):opaque(part)
        variable(value['name'])
        if 'environment' in value:opaque(value['environment'])
    if kind=='cloudflare_secret':
        require(bool(re.fullmatch(r'[a-f0-9]{32}',value['account_id'])),'invalid cloudflare account identifier')
        opaque(value['script']);variable(value['name'])
    if kind=='coolify_env':
        opaque(value['application_id']);variable(value['key'])
    if kind=='manual':
        parsed=urlsplit(value['url'])
        try:port=parsed.port
        except ValueError:raise ValueError('invalid placement console URL') from None
        require(parsed.scheme=='https' and bool(parsed.hostname) and parsed.username is None and parsed.password is None
            and not parsed.query and not parsed.fragment and port is None
            and value['url']=='https://'+parsed.netloc.lower()+(parsed.path or '/') and not credential(parsed.hostname)
            and len(parsed.hostname)<=253 and re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?',parsed.hostname),'invalid placement console URL')
        segments=[] if parsed.path=='/' else parsed.path[1:].split('/')
        require(len(segments)<=8 and len(parsed.path)<=256 and all(re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,47}',part) for part in segments)
            and not credential(parsed.path),'invalid manual console path')
        require(bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ,()._-]{0,159}',value['note']))
            and all(len(word)<=32 for word in re.split(' +',value['note'])) and not credential(value['note']),'invalid manual console note')
    return value


def apply(entry,state,epochs,*,projects,runtime,used_challenges=()):
    actor=_actor(entry,state)
    role=actor['role']
    kind,b=entry['kind'],entry['body']
    wire.exact(b,FIELDS[kind],('authz','assertion') if kind=='grant_add' else ())
    policy=deepcopy(state.get('admin_policy',initial(projects)))
    admin=role in ('owner','admin')
    def project_scope(project,*,standard=False,placement=False):
        require(project in policy['projects'],'unknown administration project')
        require(admin or role=='member' and policy['project_members'].get(project,{}).get(actor['member_id']) is True
            or standard and role=='approver','administration role or project denied')
    def existing(table,ident):
        row=policy[table].get(identifier(ident))
        require(row is not None,'unknown administration target')
        return row
    if kind=='project_put':
        project_slug=slug(b['slug'])
        require(type(b['no_shell']) is bool
            and b['change_policy'] in ('auto','desk_approval','client_approval_required'),'invalid project policy')
        require(admin,'project policy requires admin role')
        prior=policy['projects'].get(project_slug)
        require(role=='owner' or prior is not None and prior['change_policy']==b['change_policy']
            or b['change_policy']!='client_approval_required'
            and (prior is None or prior['change_policy']!='client_approval_required'),'client project policy requires owner')
        if b['lead_principal'] is not None:
            lead=existing('principals',b['lead_principal'])
            require(lead['state']=='active' and lead['project']==project_slug,'lead project mismatch')
        policy['projects'][project_slug]=deepcopy(b)
        if prior is None:
            state['triggers'][str(entry['seq'])]=dict(seq=entry['seq'],kind='projects',reason='project_created',projects=[project_slug])
    elif kind=='project_member_put':
        require(admin and type(b['enabled']) is bool,'project membership requires admin role')
        existing('projects',b['slug'])
        from .cloud_policy import AuthorityView
        member=AuthorityView(state).current(b['member_id'])
        require(member is not None and member['certificate']['state']=='active','unknown project member')
        memberships=policy['project_members'].setdefault(b['slug'],{})
        require(b['enabled'] or memberships.get(b['member_id']) is True,'project membership absent')
        if b['enabled']:memberships[b['member_id']]=True
        else:del memberships[b['member_id']]
    elif kind=='principal_add':
        identifier(b['principal_id']);project_scope(b['project'])
        require(b['principal_id'] not in policy['principals'],'principal identity already exists')
        require(b['kind'] in ('human','agent','service','desk','coordinator','worker','master','lead','job','host'),'invalid principal kind')
        if b['display'] is not None:wire.text(b['display'])
        if b['parent_id'] is not None:
            parent=existing('principals',b['parent_id'])
            require(parent['state']=='active' and parent['project']==b['project'],'parent project mismatch')
        if b['broker_id'] is not None:
            from .cloud_policy import AuthorityView
            broker=AuthorityView(state).broker_certificate_at(b['broker_id'],state['head'])
            require(broker is not None and (broker['scope']=='full' or b['project'] in broker['scope']),'uncertified principal broker')
        policy['principals'][b['principal_id']]=dict(deepcopy(b),state='active')
    elif kind=='principal_disable':
        principal=existing('principals',b['principal_id']);project_scope(principal['project'])
        require(principal['state']=='active','principal already disabled')
        principal['state']='disabled'
    elif kind in ('grant_add','grant_revoke'):
        if kind=='grant_add':
            identifier(b['grant_id'])
            require(b['grant_id'] not in policy['grants'],'grant identity already exists')
            principal=existing('principals',b['principal_id'])
            require(principal['state']=='active','disabled grant principal')
            project=pattern(b['pattern'])
            require(b['max_class'] in ('standard','sensitive','restricted'),'invalid direct grant class')
            project_scope(project,standard=b['max_class']=='standard')
            require(policy['projects'][project]['change_policy']!='client_approval_required','client projects require request decisions')
            if role=='member':
                require(policy['project_members'].get(principal['project'],{}).get(actor['member_id']) is True
                    and b['max_class']!='restricted' and (b['max_class']!='sensitive' or project!='shared' and project==principal['project']),'member grant exceeds managed project')
            require(operations(b['ops'])==b['ops'],'direct grant operations must be sorted')
            identifier(b['reason'])
            target=next((s for s in epochs['secrets'].values() if s['path']==b['pattern']),None)
            require(target is None or ('standard','sensitive','restricted').index(target['class'])<=('standard','sensitive','restricted').index(b['max_class']),'direct grant target class mismatch')
            if b['expires_at'] is not None:
                require(utc_millis(b['expires_at'])>utc_millis(entry['ts']),'direct grant already expired')
            require(('authz' in b)==('assertion' in b),'incomplete direct grant authorization')
            if b['max_class']=='restricted' or 'authz' in b:
                spent=list(dict.fromkeys(state['used_challenges']+policy.get('used_challenges',[])+list(used_challenges)))
                challenge=wire.verify_grant_authorization(entry,actor,dict(grant_id=b['grant_id']),spent,runtime)
                policy.setdefault('used_challenges',[]).append(challenge)
            policy['grants'][b['grant_id']]=dict({k:deepcopy(b[k]) for k in FIELDS[kind]},revoked=False)
        else:
            grant=existing('grants',b['grant_id'])
            principal=existing('principals',grant['principal_id'])
            require(principal['state']=='active' and not grant['revoked']
                and (grant['expires_at'] is None or utc_millis(grant['expires_at'])>utc_millis(entry['ts'])),'direct grant is not live')
            project_scope(grant['pattern'].split('/')[0],standard=grant['max_class']=='standard')
            if role=='member':
                project=grant['pattern'].split('/')[0]
                require(policy['project_members'].get(principal['project'],{}).get(actor['member_id']) is True
                    and grant['max_class']!='restricted' and (grant['max_class']!='sensitive' or project!='shared' and project==principal['project']),'member revocation exceeds managed project')
            grant['revoked']=True
    elif kind=='secret_update':
        secret=epochs['secrets'].get(identifier(b['secret_id']))
        require(secret is not None and admin,'secret policy requires admin role')
        require(b['class'] in ('standard','sensitive','restricted') and type(b['no_shell']) is bool
            and isinstance(b['allowed_hosts'],list) and b['allowed_hosts']==sorted(set(b['allowed_hosts']))
            and all(isinstance(host,str) and len(host)<=253 and re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?',host) for host in b['allowed_hosts']),'invalid secret policy')
        secret.update({key:deepcopy(b[key]) for key in ('class','no_shell','allowed_hosts')})
    elif kind=='placement_add':
        identifier(b['placement_id'])
        secret=epochs['secrets'].get(b['secret_id'])
        require(secret is not None and b['placement_id'] not in policy['placements'],'invalid placement target')
        project_scope(secret['project'],placement=True)
        locator(b['sink_kind'],b['locator'])
        require(not any(p['secret_id']==b['secret_id'] and p['sink_kind']==b['sink_kind'] and p['locator']==b['locator'] for p in policy['placements'].values()),'duplicate placement destination')
        if not admin:
            destination=urlsplit(b['locator']['url']).hostname if b['sink_kind']=='manual' else {'railway_var':'backboard.railway.app','github_secret':'api.github.com','cloudflare_secret':'api.cloudflare.com','coolify_env':''}[b['sink_kind']]
            require(secret['class']!='restricted' and policy['projects'][secret['project']]['change_policy']!='client_approval_required'
                and destination in secret.get('allowed_hosts',[]),'member placement exceeds class or host policy')
        policy['placements'][b['placement_id']]=dict(deepcopy(b),state='active')
    else:
        placement=existing('placements',b['placement_id'])
        require(placement.get('state')=='active','placement is not active')
        secret=epochs['secrets'].get(placement['secret_id'])
        require(secret is not None,'unknown placement secret')
        project_scope(secret['project'],placement=True)
        placement['state']='removed'
    state['admin_policy']=policy
    state['head']=dict(seq=entry['seq'],hash=wire.hash_object(entry))
    return state
