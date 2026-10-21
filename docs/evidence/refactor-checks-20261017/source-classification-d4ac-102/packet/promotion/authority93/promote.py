from pathlib import Path
import collections, copy, csv, datetime, hashlib, io, json, os, secrets, stat

# Exact ledger-only promotion; frozen packets and historical receipts are inputs.
BASE = Path('/tmp')
CP = BASE/'ts-qa-refactor-completion-open-20261016.json'
PP = BASE/'ts-qa-main-union-progress-20261016.json'
PINS = {
 str(CP): 'a59581d3ecec9e292c36f86977ab4b8b94851d70379d9c42f0bea6323fd9ccd9',
 str(PP): '324c1ab4c63d2605a9863d31614ccf291d3e15c55dbb0b8f476406078d10b1b2',
 '/tmp/ts-authority-d4ac-classification-corrected-8e5nz_tg/review.json': '084e17bc2f2575099b16f730cd5100b277d5693f330a6aa7406154c2da38e2c0',
 '/tmp/ts-authority-d4ac-classification-peer-1pd2stsh/review.json': '7e021d206217d320c0a06edd87b9fac019a868243857f9381d1c2dfec8106372',
 '/tmp/ts-ociclient-d4ac-source-classification-1p515gvv/classification.json': 'a86ce342d55f0f52ce3a1a220df68a594349388bebd40a0c08163221f2476ee5',
 '/tmp/ts-qa-ociclient-d4ac-classification-artifact-tests-vhps3ufo/review.json': 'c22f1cb62fd3a5adc3be0867d51fca1b36b387b23dfc6384265d327a8d5e031f',
 '/tmp/ts-qa-ociclient9-classification-promotion-audit-c599f2cb1212.json': '897c48c1fe901898d5aa6e71b5a71cf2a761e05d52f9056c1b6fa28eae6c31bb',
 '/tmp/ts-firstparty-vendor-d4ac-accepted-9h6_8guy/firstparty-survival.tsv': '5fdf8adda8903b852d89a3d790dae9bbd46d3233349792988b15ac9806d93e73',
}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def encoded(value):
    return (json.dumps(value, indent=2)+'\n').encode()

def exclusive(path, data, mode=0o400):
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, mode)
    assert Path(path).read_bytes() == data
    return {'path': str(path), 'sha256': sha(data), 'bytes': len(data), 'mode': format(mode, '04o')}

inputs = {name: Path(name).read_bytes() for name in PINS}
assert all(sha(inputs[name]) == digest for name,digest in PINS.items()), 'Input pin changed'
original_c, original_p = (json.loads(inputs[str(path)]) for path in [CP,PP])
c,p = copy.deepcopy(original_c),copy.deepcopy(original_p)
authority_path = '/tmp/ts-authority-d4ac-classification-corrected-8e5nz_tg/review.json'
peer_path = '/tmp/ts-authority-d4ac-classification-peer-1pd2stsh/review.json'
authority,peer = (json.loads(inputs[name]) for name in [authority_path,peer_path])
oci = json.loads(inputs['/tmp/ts-ociclient-d4ac-source-classification-1p515gvv/classification.json'])
rows = list(csv.DictReader(io.StringIO(inputs['/tmp/ts-firstparty-vendor-d4ac-accepted-9h6_8guy/firstparty-survival.tsv'].decode()), delimiter='\t'))
inventory = {(r['path'],r['original_name']):r for r in rows if r['kind']=='test'}
assert len(inventory)==4319
head,tree='d4ac68882716e7cfb14afca2f88ad596a38041af','3b73a410a025bd8050ad1d42e54acc7d5eda4b82'
assert authority['canonical_head']==peer['canonical_head']==head
assert authority['canonical_tree']==peer['canonical_tree']==tree
assert peer['decision']=='ACCEPT_CORRECTED_SOURCE_CLASSIFICATION_ONLY'
assert peer['reviewed_packet']=={'path':authority_path,'sha256':PINS[authority_path]}
assert authority['counts']['integration']==72 and authority['counts']['unit']==20 and authority['counts']['mixed']==1
assert len(authority['tests'])==len(peer['roots'])==93
accepted_peer={(r['path'],r['original_name']):r for r in peer['roots']}
authority_roots={}
for root in authority['tests']:
    key=(root['test']['path'],root['original_name'])
    assert key not in authority_roots
    assert key in inventory and key in accepted_peer
    row,other=inventory[key],accepted_peer[key]
    assert row['state']==root['survival_state']=='retained_body_exact'
    for field in ['original_declaration_sha256','current_declaration_sha256','current_name']:
        assert root[field]==other[field]==row[field]
    assert root['original_declaration_sha256']==root['current_declaration_sha256']
    assert root['classification']==other['classification_independently_accepted']
    assert root['retirement_authorized'] is False and other['retirement_authorized'] is False
    authority_roots[key]=root
assert set(authority_roots)==set(accepted_peer)=={k for k in inventory if k[0].startswith('internal/authority/')}
oci_roots={}
for root in oci['originals']:
    key=(root['path'],root['original_name'])
    assert all(root[field]==inventory[key][field] for field in ['path','original_name','kind','original_declaration_sha256','current_name','current_declaration_sha256','state'])
    if root['retained_classification_counted']:
        oci_roots[key]=root
assert len(oci_roots)==9 and not set(oci_roots).intersection(authority_roots)
assert collections.Counter(r['category'] for r in oci_roots.values())=={'integration':6,'unit':3}
assert collections.Counter(r['classification'] for r in authority_roots.values())=={'integration':72,'unit':20,'mixed':1}
assert 19+102+4198==4319 and 102+4198==4300 and 78+23+1==102
old_classification=copy.deepcopy(c['source_classification_adjudication'])
assert old_classification==p['source_classification_adjudication']
assert old_classification['retained_originals_classified']==9
now=datetime.datetime.now(datetime.timezone.utc).isoformat()
authority_receipt={
    'package':'internal/authority','packet':authority_path,'classification_sha256':PINS[authority_path],
    'independent_review':peer_path,'independent_review_sha256':PINS[peer_path],
    'baseline_rows':93,'retained_originals_classified':93,'integration':72,'unit':20,'mixed':1,
    'unresolved_within_classified_package':0,'prior_retired_rows_excluded':0,
    'retirement_delta':0,'runtime_qualified_by_this_classification':0,
    'corrected_root':peer['finding_resolved'],
    'limits':peer['limits'],
}
classification={
    'state':old_classification['state'],'as_of':now,'source_commit':head,'source_tree':tree,
    'package_groups':['internal/ociclient','internal/authority'],
    'accepted_package_classifications':{'internal/ociclient':copy.deepcopy(old_classification),'internal/authority':authority_receipt},
    'prior_ociclient_promotion_audit':{'path':'/tmp/ts-qa-ociclient9-classification-promotion-audit-c599f2cb1212.json','sha256':PINS['/tmp/ts-qa-ociclient9-classification-promotion-audit-c599f2cb1212.json']},
    'baseline_rows':107,'retained_originals_classified':102,'integration':78,'unit':23,'mixed':1,
    'unresolved_within_classified_package':0,'prior_retired_rows_excluded':5,
    'retirement_delta':0,'retirements_total':19,'retained_originals_total':4300,
    'classification_unadjudicated_remaining':4198,'runtime_qualified_by_this_classification':0,
    'limits':[
        'Cumulative source classifications only; no runtime/main/global/production/native/cloud/financial qualification.',
        'Ociclient nine retained originals (6 integration/3 unit) and authority 93 retained originals (72 integration/20 unit/1 mixed) are disjoint baseline roots.',
        'The corrected HostHistory expiry/reseed root is unit; incidental broker setup receives no integration credit.',
        'All unit/mixed safety assertions and suite obligations remain; no source rewrite, replacement, deletion or retirement is authorized.',
        'Five previously retired ociclient rows are excluded. Frozen lexical scans and historical receipts are unchanged; other retained originals remain unadjudicated.'
    ],
}
limit='4319 originals reconcile as4276 body exact+23 changed+1 expanded+19 scoped retirements. Of4300 retained originals,102 source classifications are independently accepted (78integration/23unit/1mixed);4198 remain globally unadjudicated. Source classification is not runtime qualification. All five completion categories remain OPEN.'
# Explicit current mirrors only; histories and frozen lexical scan values are excluded.
link=copy.deepcopy(c['authoritative_current_test_reconciliation']['current_feature_linkage'])
link.update(firstparty_globally_unadjudicated=4198,source_classification_adjudication=copy.deepcopy(classification))
current=c['authoritative_current_test_reconciliation']
current['firstparty'].update(source_classified_integration=78,source_classified_unit=23,source_classified_mixed=1,source_classification_adjudicated_retained=102,globally_unadjudicated_remaining_original_tests=4198,classification_limit=limit)
current['current_feature_linkage']=copy.deepcopy(link)
current['source_classification_adjudication']=copy.deepcopy(classification)
current['provenance']['limit']=limit
c['first_party_inventory']['current_feature_limit']=limit
c['first_party_inventory']['current_reconciliation'].update(remaining_original_tests_globally_unadjudicated=4198,source_classification_adjudication=copy.deepcopy(classification),current_feature_linkage=copy.deepcopy(link),limits=limit)
c['open_categories'][3]['first_party_inventory']=copy.deepcopy(c['first_party_inventory'])
c['open_categories'][3]['inventory']['canonical_presence_derivation']=copy.deepcopy(link)
latest=c['audit_boundaries']['latest_read_only_verification']
c['audit_boundaries']['read_only_verification_history'].append(copy.deepcopy(latest))
latest.update(firstparty_remaining_globally_unadjudicated=4198,firstparty_source_classified_integration=78,firstparty_source_classified_unit=23,firstparty_source_classified_mixed=1,source_classification_adjudication=copy.deepcopy(classification),current_test_reconciliation_derivation=copy.deepcopy(link),limits=limit)
latest['authoritative_test_reconciliation']=copy.deepcopy(current['provenance'])
c['integration_candidate']['publication_history'].append({'source':c['integration_candidate']['source'],'publication_delta':c['integration_candidate']['publication_delta']})
c['integration_candidate']['publication_delta']='Current d4ac has19 accepted scoped retirements. Accepted source classifications cover102 retained originals in ociclient and authority (78integration/23unit/1mixed);4198 of4300 retained originals remain globally unadjudicated. Historical donor checks remain source-scoped; no current feature/runtime/native/cloud/global qualification.'
p['first_party_inventory']['current_reconciliation'].update(globally_unadjudicated=4198,classified_retained=102,source_classified_integration=78,source_classified_unit=23,source_classified_mixed=1,source_classification_adjudication=copy.deepcopy(classification),note=limit)
p['gate']='All five completion categories OPEN. Accepted d4ac:19 scoped retirements;4300 retained originals include102 independently accepted source classifications(78integration/23unit/1mixed),4198globallyunadjudicated. Vendor1449present/0retired/0centralclosure. No runtime/main/global credit.'
# Exclusive immutable snapshots precede all writes to existing ledgers.
snapshots=[]
for path in [CP,PP]:
    target=path.with_name(path.stem+'-before-authority93-classification-'+secrets.token_hex(5)+'.json')
    snapshots.append(exclusive(target,inputs[str(path)]))
for obj,snapshot in [(c,snapshots[0]),(p,snapshots[1])]:
    obj['as_of']=now
    obj['source_classification_adjudication']=copy.deepcopy(classification)
    obj['classification_work_pending']['groups']['internal/authority']='93 retained original source classifications independently accepted:72integration/20unit/1mixed;corrected packet and peer verified;no runtime credit'
    obj['classification_adjudication_history'].append({'as_of':now,'before_snapshot':snapshot,'adjudicated_retained_delta':93,'integration_delta':72,'unit_delta':20,'mixed_delta':1,'retirement_delta':0,'runtime_qualification_delta':0,'accepted_packet':{'path':authority_path,'sha256':PINS[authority_path]},'independent_peer':{'path':peer_path,'sha256':PINS[peer_path]}})

assert c['complete'] is False and len(c['open_categories'])==5 and all(x['status']=='OPEN' for x in c['open_categories'])
assert c['first_party_inventory']==c['open_categories'][3]['first_party_inventory']
# Every changed path must fall within this finite current-field allowlist.
allowed_c=[('as_of',),('source_classification_adjudication',),('classification_adjudication_history',),('classification_work_pending','groups','internal/authority'),('authoritative_current_test_reconciliation','firstparty'),('authoritative_current_test_reconciliation','current_feature_linkage'),('authoritative_current_test_reconciliation','source_classification_adjudication'),('authoritative_current_test_reconciliation','provenance','limit'),('first_party_inventory','current_feature_limit'),('first_party_inventory','current_reconciliation'),('open_categories',3,'first_party_inventory','current_feature_limit'),('open_categories',3,'first_party_inventory','current_reconciliation'),('open_categories',3,'inventory','canonical_presence_derivation'),('audit_boundaries','latest_read_only_verification'),('audit_boundaries','read_only_verification_history'),('integration_candidate','publication_delta'),('integration_candidate','publication_history')]
allowed_p=[('as_of',),('source_classification_adjudication',),('classification_adjudication_history',),('classification_work_pending','groups','internal/authority'),('first_party_inventory','current_reconciliation'),('gate',),('completion_ledger_sha256',)]
def changes(before,after,path=()):
    if type(before)!=type(after):return [path]
    if isinstance(before,dict):
        found=[]
        for key in before.keys()|after.keys():
            if key not in before or key not in after:found.append(path+(key,))
            else:found.extend(changes(before[key],after[key],path+(key,)))
        return found
    if isinstance(before,list):
        if len(before)!=len(after):return [path]
        return [item for i,(a,b) in enumerate(zip(before,after)) for item in changes(a,b,path+(i,))]
    return [] if before==after else [path]
def check_changes(before,after,allowed):
    changed=changes(before,after)
    assert all(any(q[:len(prefix)]==prefix for prefix in allowed) for q in changed),changed
    return [list(q) for q in changed]
changed_c=check_changes(original_c,c,allowed_c)
assert c['accepted_d4ac_authoritative_reconciliation']==original_c['accepted_d4ac_authoritative_reconciliation']
assert p['d4ac_promotion']==original_p['d4ac_promotion']
assert c['authoritative_test_reconciliation_history']==original_c['authoritative_test_reconciliation_history']
assert p['ledger_history']==original_p['ledger_history']
assert c['audit_boundaries']['read_only_verification_history'][:-1]==original_c['audit_boundaries']['read_only_verification_history']
assert c['audit_boundaries']['read_only_verification_history'][-1]==original_c['audit_boundaries']['latest_read_only_verification']
assert c['integration_candidate']['publication_history'][:-1]==original_c['integration_candidate']['publication_history']
for old,new in [(original_c,c),(original_p,p)]:
    assert set(old)<=set(new)
    assert new['classification_adjudication_history'][:-1]==old['classification_adjudication_history']
assert c['source_classification_adjudication']['accepted_package_classifications']['internal/ociclient']==old_classification
cbytes=encoded(c)
p['completion_ledger_sha256']=sha(cbytes)
pbytes=encoded(p)
changed_p=check_changes(original_p,p,allowed_p)
# Recheck every input immediately before the only two existing-file mutations.
assert all(sha(Path(name).read_bytes())==digest for name,digest in PINS.items())
for path,payload in [(CP,cbytes),(PP,pbytes)]:
    with path.open('wb') as stream:
        stream.write(payload);stream.flush();os.fsync(stream.fileno())
    assert path.read_bytes()==payload
receipt={
 'state':'PROMOTED_SOURCE_CLASSIFICATION_PENDING_INDEPENDENT_LEDGER_AUDIT','as_of':now,
 'source_commit':head,'source_tree':tree,
 'counts':{'baseline_originals':4319,'retired':19,'retained':4300,'classified':102,'integration':78,'unit':23,'mixed':1,'globally_unadjudicated':4198,'authority_delta':93,'runtime_delta':0,'retirement_delta':0},
 'disjoint_original_roots_verified':True,'authority93_inventory_and_peer_root_hash_matches':True,
 'prior_ociclient9_exact_receipt_preserved':True,
 'corrected_authority_counts':{'integration':72,'unit':20,'mixed':1},
 'inputs':PINS,'before_snapshots':snapshots,
 'after_ledgers':[{'path':str(CP),'sha256':sha(cbytes),'bytes':len(cbytes)},{'path':str(PP),'sha256':sha(pbytes),'bytes':len(pbytes)}],
 'promotion_script':{'path':str(Path(__file__).absolute()),'sha256':sha(Path(__file__).read_bytes())},
 'changed_paths':{'completion':changed_c,'progress':changed_p},
 'preservation':{'five_categories_OPEN':True,'complete':False,'historical_d4ac_receipts_unchanged':True,'frozen_scan_unchanged':True,'old_ledger_histories_unchanged':True,'verification_history_appended_exactly':True},
 'limits':['Only the two temporary ledgers mutated; exclusive immutable snapshots and receipt created.','No source, Git, Go, native, build, test, runtime, runner, process/listener/lock, or cloud actions.','Source classification adds zero runtime or retirement credit; all safety assertions remain.','Promotion requires a different independent ledger reviewer; this receipt is not that audit.']
}
receipt_path=BASE/('ts-qa-authority93-classification-promotion-'+secrets.token_hex(6)+'.json')
sealed=exclusive(receipt_path,encoded(receipt),0o444)
print(json.dumps({'receipt':sealed,'snapshots':snapshots,'after_ledgers':receipt['after_ledgers'],'promotion_script':receipt['promotion_script'],'counts':receipt['counts']},indent=2))
