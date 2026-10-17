import ast,collections,copy,csv,datetime,hashlib,json,os,pathlib,stat
OUT=pathlib.Path(__file__).parent
CP='/tmp/ts-qa-refactor-completion-open-20261016.json';PP='/tmp/ts-qa-main-union-progress-20261016.json'
BC='/tmp/ts-qa-refactor-completion-open-20261016-before-authority93-classification-fb8f5c3e93.json';BP='/tmp/ts-qa-main-union-progress-20261016-before-authority93-classification-f225779da8.json'
RP='/tmp/ts-qa-authority93-classification-promotion-6a4a72bb486d.json';SP='/tmp/ts-qa-promote-authority93-classification.py'
AP='/tmp/ts-authority-d4ac-classification-corrected-8e5nz_tg/review.json';PEER='/tmp/ts-authority-d4ac-classification-peer-1pd2stsh/review.json'
OCI='/tmp/ts-ociclient-d4ac-source-classification-1p515gvv/classification.json';OCIP='/tmp/ts-qa-ociclient-d4ac-classification-artifact-tests-vhps3ufo/review.json';PRIOR='/tmp/ts-qa-ociclient9-classification-promotion-audit-c599f2cb1212.json'
INV='/tmp/ts-firstparty-vendor-d4ac-accepted-9h6_8guy/firstparty-survival.tsv'
HEAD='d4ac68882716e7cfb14afca2f88ad596a38041af';TREE='3b73a410a025bd8050ad1d42e54acc7d5eda4b82'
PINS={CP:'2844cc0dd959d7511be7e1b48eebae1569ccdb5f3308e9822dad66637dba4e72',PP:'b080e4391e845404b246f857c1eb510c458834d0b15595f5d47c4c247d17c644',BC:'a59581d3ecec9e292c36f86977ab4b8b94851d70379d9c42f0bea6323fd9ccd9',BP:'324c1ab4c63d2605a9863d31614ccf291d3e15c55dbb0b8f476406078d10b1b2',RP:'96dcd5de89fe6e5c9453bac2f2b2549f1b9b2ae3b76afbe1ba08c1443b0a702c',SP:'1644e887df09d875730afc290be1fb2bf595db5187956f669efff892d3647e69',AP:'084e17bc2f2575099b16f730cd5100b277d5693f330a6aa7406154c2da38e2c0',PEER:'7e021d206217d320c0a06edd87b9fac019a868243857f9381d1c2dfec8106372',OCI:'a86ce342d55f0f52ce3a1a220df68a594349388bebd40a0c08163221f2476ee5',OCIP:'c22f1cb62fd3a5adc3be0867d51fca1b36b387b23dfc6384265d327a8d5e031f',PRIOR:'897c48c1fe901898d5aa6e71b5a71cf2a761e05d52f9056c1b6fa28eae6c31bb',INV:'5fdf8adda8903b852d89a3d790dae9bbd46d3233349792988b15ac9806d93e73'}
sha=lambda b:hashlib.sha256(b).hexdigest()
raw={p:pathlib.Path(p).read_bytes() for p in PINS}
assert all(sha(raw[p])==h for p,h in PINS.items())
objs={p:json.loads(b) for p,b in raw.items() if p.endswith('.json')}
c,p,bc,bp,r,a,peer,oci,ocip,prior=(objs[k] for k in [CP,PP,BC,BP,RP,AP,PEER,OCI,OCIP,PRIOR])
assert len(raw[CP])==1140071 and len(raw[PP])==102603 and len(raw[RP])==40573
assert stat.S_IMODE(pathlib.Path(RP).stat().st_mode)==0o444
assert all(stat.S_IMODE(pathlib.Path(k).stat().st_mode)==0o400 for k in [BC,BP])
assert r['source_commit']==HEAD and r['source_tree']==TREE
assert r['state']=='PROMOTED_SOURCE_CLASSIFICATION_PENDING_INDEPENDENT_LEDGER_AUDIT'
for rec in r['before_snapshots']+r['after_ledgers']:
 assert rec['path'] in raw and sha(raw[rec['path']])==rec['sha256'] and len(raw[rec['path']])==rec['bytes']
assert r['promotion_script']=={'path':SP,'sha256':PINS[SP]}
for name,h in r['inputs'].items():assert h==PINS[{CP:BC,PP:BP}.get(name,name)]
ast.parse(raw[SP].decode())
assert prior['verdict']=='ACCEPT_EXACT_OCICLIENT_NINE_SOURCE_CLASSIFICATION_PROMOTION_NO_RUNTIME_CREDIT'
assert prior['artifacts']['completion_ledger']['sha256']==PINS[BC] and prior['artifacts']['progress_ledger']['sha256']==PINS[BP]
assert prior['artifacts']['accepted_independent_review']=={'path':OCIP,'sha256':PINS[OCIP]}
assert a['canonical_head']==peer['canonical_head']==HEAD and a['canonical_tree']==peer['canonical_tree']==TREE
assert peer['decision']=='ACCEPT_CORRECTED_SOURCE_CLASSIFICATION_ONLY' and peer['reviewed_packet']=={'path':AP,'sha256':PINS[AP]}
# Independently validate frozen input manifests; these are read-only receipts, not executed source.
manifest_proofs=[]
for directory,manifest_sha in [(pathlib.Path(INV).parent,'2a8a34d73a5d4cdc7250d15c0ae441cc5ea34a649d9f00cba0edd668e801413e'),(pathlib.Path(OCI).parent,'9a1b860fe918a3ac4cfb305b7ee17c824a4177ae2463068179fa8f08f5fa52f5')]:
 m=(directory/'SHA256SUMS').read_bytes();assert sha(m)==manifest_sha
 checked=[]
 for line in m.decode().splitlines():
  h,n=line.split('  ',1);q=directory/n;assert sha(q.read_bytes())==h
  assert stat.S_IMODE(q.stat().st_mode)==0o400;checked.append({'name':n,'sha256':h})
 assert stat.S_IMODE(directory.stat().st_mode)==0o500
 manifest_proofs.append({'directory':str(directory),'manifest_sha256':manifest_sha,'entries':checked,'file_mode':'0400','directory_mode':'0500'})
scan=json.loads((pathlib.Path(INV).parent/'summary.json').read_bytes())
assert scan['current_commit']==HEAD and scan['current_tree']==TREE
rows=list(csv.DictReader(raw[INV].decode().splitlines(),delimiter='\t'));tests=[x for x in rows if x['kind']=='test']
inv={(x['path'],x['original_name']):x for x in tests};assert len(tests)==len(inv)==4319
survival=collections.Counter(x['state'] for x in tests)
assert survival=={'retained_body_exact':4276,'retained_body_changed':23,'renamed_expanded_integration_owner':1,'qualified_retired':19}
retired={k:v for k,v in inv.items() if v['state']=='qualified_retired'}
fields=['path','original_name','kind','original_declaration_sha256','current_name','current_declaration_sha256','state']
oci_roots={}
for x in oci['originals']:
 key=x['path'],x['original_name'];assert all(x[f]==inv[key][f] for f in fields)
 if x['retained_classification_counted']:oci_roots[key]=x
assert len(oci_roots)==9 and collections.Counter(x['category'] for x in oci_roots.values())=={'integration':6,'unit':3}
auth={(x['test']['path'],x['original_name']):x for x in a['tests']};pr={(x['path'],x['original_name']):x for x in peer['roots']}
assert len(auth)==len(a['tests'])==len(pr)==len(peer['roots'])==93
assert set(auth)==set(pr)=={k for k in inv if k[0].startswith('internal/authority/')}
for key,x in auth.items():
 row=inv[key];other=pr[key]
 for f in ['original_declaration_sha256','current_declaration_sha256','current_name']:assert x[f]==row[f]==other[f]
 assert row['state']==x['survival_state']==other['survival_state']=='retained_body_exact'
 assert x['original_declaration_sha256']==x['current_declaration_sha256']
 assert x['classification']==other['classification_independently_accepted']
 assert x['retirement_authorized'] is False and other['retirement_authorized'] is False
 assert x['runtime_qualification']==other['runtime_qualification']=='UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION'
assert collections.Counter(x['classification'] for x in auth.values())=={'integration':72,'unit':20,'mixed':1}
assert not(set(auth)&set(oci_roots)) and not((set(auth)|set(oci_roots))&set(retired))
classified=set(auth)|set(oci_roots);unadjudicated=set(inv)-set(retired)-classified
assert len(classified)==102 and len(unadjudicated)==4198 and len(retired)==19
assert 19+102+4198==4319 and 102+4198==4300 and 78+23+1==102
classification=c['source_classification_adjudication'];old=bc['source_classification_adjudication']
assert old==bp['source_classification_adjudication'] and old['retained_originals_classified']==9
assert classification==p['source_classification_adjudication']
expected_counts={'baseline_rows':107,'retained_originals_classified':102,'integration':78,'unit':23,'mixed':1,'unresolved_within_classified_package':0,'prior_retired_rows_excluded':5,'retirement_delta':0,'retirements_total':19,'retained_originals_total':4300,'classification_unadjudicated_remaining':4198,'runtime_qualified_by_this_classification':0}
assert all(classification[k]==v for k,v in expected_counts.items())
assert classification['state']==old['state']=='INDEPENDENTLY_ACCEPTED_SOURCE_CLASSIFICATIONS_NO_RUNTIME_CREDIT'
assert classification['source_commit']==HEAD and classification['source_tree']==TREE
assert classification['package_groups']==['internal/ociclient','internal/authority']
assert set(classification['accepted_package_classifications'])=={'internal/ociclient','internal/authority'}
assert classification['accepted_package_classifications']['internal/ociclient']==old
assert classification['prior_ociclient_promotion_audit']=={'path':PRIOR,'sha256':PINS[PRIOR]}
ar=classification['accepted_package_classifications']['internal/authority']
assert ar=={'package':'internal/authority','packet':AP,'classification_sha256':PINS[AP],'independent_review':PEER,'independent_review_sha256':PINS[PEER],'baseline_rows':93,'retained_originals_classified':93,'integration':72,'unit':20,'mixed':1,'unresolved_within_classified_package':0,'prior_retired_rows_excluded':0,'retirement_delta':0,'runtime_qualified_by_this_classification':0,'corrected_root':peer['finding_resolved'],'limits':peer['limits']}
assert ar['corrected_root']['accepted_classification']=='unit'
now=r['as_of'];assert now==c['as_of']==p['as_of']==classification['as_of']
# Find all current102 mirrors; require exactly the independently enumerated12 paths.
CM=[('source_classification_adjudication',),('authoritative_current_test_reconciliation','source_classification_adjudication'),('authoritative_current_test_reconciliation','current_feature_linkage','source_classification_adjudication'),('first_party_inventory','current_reconciliation','source_classification_adjudication'),('first_party_inventory','current_reconciliation','current_feature_linkage','source_classification_adjudication'),('open_categories',3,'first_party_inventory','current_reconciliation','source_classification_adjudication'),('open_categories',3,'first_party_inventory','current_reconciliation','current_feature_linkage','source_classification_adjudication'),('open_categories',3,'inventory','canonical_presence_derivation','source_classification_adjudication'),('audit_boundaries','latest_read_only_verification','source_classification_adjudication'),('audit_boundaries','latest_read_only_verification','current_test_reconciliation_derivation','source_classification_adjudication')]
PM=[('source_classification_adjudication',),('first_party_inventory','current_reconciliation','source_classification_adjudication')]
def get(obj,path):
 for key in path:obj=obj[key]
 return obj
def put(obj,path,value):
 parent=get(obj,path[:-1]);parent[path[-1]]=copy.deepcopy(value)
def walk(obj,path=()):
 if isinstance(obj,dict):
  yield path,obj
  for k,v in obj.items():yield from walk(v,path+(k,))
 elif isinstance(obj,list):
  for i,v in enumerate(obj):yield from walk(v,path+(i,))
for after,before,paths in [(c,bc,CM),(p,bp,PM)]:
 actual={q for q,v in walk(after) if v.get('retained_originals_classified')==102}
 assert actual==set(paths)
 assert all(get(after,q)==classification and get(before,q)==old for q in paths)
# Normalize only validated current receipt replacements, scalar deltas and exact appends.
# Deep equality afterward proves every other nested value remains unchanged.
normalized_c=copy.deepcopy(c);normalized_p=copy.deepcopy(p);approved=[]
for label,norm,before,paths in [('completion',normalized_c,bc,CM),('progress',normalized_p,bp,PM)]:
 for q in paths:put(norm,q,get(before,q));approved.append({'ledger':label,'path':list(q),'kind':'validated_current_classification_receipt_replacement'})
oldlimit=bc['authoritative_current_test_reconciliation']['firstparty']['classification_limit']
newlimit='4319 originals reconcile as4276 body exact+23 changed+1 expanded+19 scoped retirements. Of4300 retained originals,102 source classifications are independently accepted (78integration/23unit/1mixed);4198 remain globally unadjudicated. Source classification is not runtime qualification. All five completion categories remain OPEN.'
def scalar(label,q,oldv,newv):
 before,after,norm=(bc,c,normalized_c) if label=='completion' else (bp,p,normalized_p)
 assert get(before,q)==oldv and get(after,q)==newv,(label,q)
 put(norm,q,oldv);approved.append({'ledger':label,'path':list(q),'kind':'validated_scalar_delta','before':oldv,'after':newv})
for label,before in [('completion',bc),('progress',bp)]:
 scalar(label,('as_of',),before['as_of'],now)
 scalar(label,('classification_work_pending','groups','internal/authority'),'93-root candidate72integration/19unit/2mixed under independent review;no counts promoted','93 retained original source classifications independently accepted:72integration/20unit/1mixed;corrected packet and peer verified;no runtime credit')
for q in [('authoritative_current_test_reconciliation','current_feature_linkage','firstparty_globally_unadjudicated'),('first_party_inventory','current_reconciliation','current_feature_linkage','firstparty_globally_unadjudicated'),('open_categories',3,'first_party_inventory','current_reconciliation','current_feature_linkage','firstparty_globally_unadjudicated'),('open_categories',3,'inventory','canonical_presence_derivation','firstparty_globally_unadjudicated'),('audit_boundaries','latest_read_only_verification','current_test_reconciliation_derivation','firstparty_globally_unadjudicated'),('first_party_inventory','current_reconciliation','remaining_original_tests_globally_unadjudicated'),('open_categories',3,'first_party_inventory','current_reconciliation','remaining_original_tests_globally_unadjudicated'),('authoritative_current_test_reconciliation','firstparty','globally_unadjudicated_remaining_original_tests'),('audit_boundaries','latest_read_only_verification','firstparty_remaining_globally_unadjudicated')]:scalar('completion',q,4291,4198)
for parent,prefix in [(('authoritative_current_test_reconciliation','firstparty'),'source_classified_'),(('audit_boundaries','latest_read_only_verification'),'firstparty_source_classified_')]:
 for typ,oldv,newv in [('integration',6,78),('unit',3,23),('mixed',0,1)]:scalar('completion',parent+(prefix+typ,),oldv,newv)
scalar('completion',('authoritative_current_test_reconciliation','firstparty','source_classification_adjudicated_retained'),9,102)
for q in [('authoritative_current_test_reconciliation','firstparty','classification_limit'),('authoritative_current_test_reconciliation','provenance','limit'),('first_party_inventory','current_feature_limit'),('first_party_inventory','current_reconciliation','limits'),('open_categories',3,'first_party_inventory','current_feature_limit'),('open_categories',3,'first_party_inventory','current_reconciliation','limits'),('audit_boundaries','latest_read_only_verification','limits'),('audit_boundaries','latest_read_only_verification','authoritative_test_reconciliation','limit')]:scalar('completion',q,oldlimit,newlimit)
scalar('completion',('integration_candidate','publication_delta'),'Current d4ac has19 accepted scoped retirements. Accepted source classifications cover9 retained ociclient originals (6integration/3unit);4291 of4300 retained originals remain globally unadjudicated. Historical donor checks remain source-scoped; no current feature/runtime/native/cloud/global qualification.','Current d4ac has19 accepted scoped retirements. Accepted source classifications cover102 retained originals in ociclient and authority (78integration/23unit/1mixed);4198 of4300 retained originals remain globally unadjudicated. Historical donor checks remain source-scoped; no current feature/runtime/native/cloud/global qualification.')
for field,oldv,newv in [('classified_retained',9,102),('globally_unadjudicated',4291,4198),('source_classified_integration',6,78),('source_classified_unit',3,23),('source_classified_mixed',0,1),('note',oldlimit,newlimit)]:scalar('progress',('first_party_inventory','current_reconciliation',field),oldv,newv)
scalar('progress',('gate',),'All five completion categories OPEN. Accepted d4ac:19 scoped retirements;4300 retained originals include9 independently accepted source classifications(6integration/3unit),4291globallyunadjudicated. Vendor1449present/0retired/0centralclosure. No runtime/main/global credit.','All five completion categories OPEN. Accepted d4ac:19 scoped retirements;4300 retained originals include102 independently accepted source classifications(78integration/23unit/1mixed),4198globallyunadjudicated. Vendor1449present/0retired/0centralclosure. No runtime/main/global credit.')
scalar('progress',('completion_ledger_sha256',),PINS[BC],PINS[CP])
def append_exact(label,q,expected):
 before,after,norm=(bc,c,normalized_c) if label=='completion' else (bp,p,normalized_p)
 assert get(after,q)==get(before,q)+[expected]
 put(norm,q,get(before,q));approved.append({'ledger':label,'path':list(q),'kind':'exact_single_append_preserving_all_previous_entries','appended_value':expected})
for label,snapshot in [('completion',r['before_snapshots'][0]),('progress',r['before_snapshots'][1])]:
 append_exact(label,('classification_adjudication_history',),{'as_of':now,'before_snapshot':snapshot,'adjudicated_retained_delta':93,'integration_delta':72,'unit_delta':20,'mixed_delta':1,'retirement_delta':0,'runtime_qualification_delta':0,'accepted_packet':{'path':AP,'sha256':PINS[AP]},'independent_peer':{'path':PEER,'sha256':PINS[PEER]}})
append_exact('completion',('audit_boundaries','read_only_verification_history'),bc['audit_boundaries']['latest_read_only_verification'])
append_exact('completion',('integration_candidate','publication_history'),{'source':bc['integration_candidate']['source'],'publication_delta':bc['integration_candidate']['publication_delta']})
assert normalized_c==bc and normalized_p==bp,'Unapproved nested ledger difference'
def changed(before,after,path=()):
 if type(before)!=type(after):return [path]
 if isinstance(before,dict):
  out=[]
  for key in before.keys()|after.keys():
   out.extend([path+(key,)] if key not in before or key not in after else changed(before[key],after[key],path+(key,)))
  return out
 if isinstance(before,list):
  if len(before)!=len(after):return [path]
  return [q for i,(x,y) in enumerate(zip(before,after)) for q in changed(x,y,path+(i,))]
 return [] if before==after else [path]
actualdiff={'completion':changed(bc,c),'progress':changed(bp,p)}
assert all(set(map(tuple,r['changed_paths'][label]))==set(paths) for label,paths in actualdiff.items())
assert len(actualdiff['completion'])==190 and len(actualdiff['progress'])==43
assert c['complete'] is bc['complete'] is False
assert len(c['open_categories'])==5 and all(x['status']=='OPEN' for x in c['open_categories'])
assert [x['status'] for x in c['open_categories']]==[x['status'] for x in bc['open_categories']]
assert c['first_party_inventory']==c['open_categories'][3]['first_party_inventory']
assert c['accepted_d4ac_authoritative_reconciliation']==bc['accepted_d4ac_authoritative_reconciliation']
assert p['d4ac_promotion']==bp['d4ac_promotion']
assert c['authoritative_test_reconciliation_history']==bc['authoritative_test_reconciliation_history'] and p['ledger_history']==bp['ledger_history']
dispositions=c['authoritative_current_test_reconciliation']['nineteen_retirement_dispositions']
assert dispositions==bc['authoritative_current_test_reconciliation']['nineteen_retirement_dispositions']
assert len(dispositions)==19 and {(x['path'],x['original_name']) for x in dispositions}==set(retired)
for x in dispositions:assert all(x[f]==retired[x['path'],x['original_name']][f] for f in fields)
assert c['audit_boundaries']['latest_read_only_verification']['runtime_repeated'] is False
lex=[(q,x['lexical_scan_unadjudicated_before_classification']) for q,x in walk(c) if 'lexical_scan_unadjudicated_before_classification' in x]
# These include historical snapshots whose lexical values are also fixed by full equality proof.
assert get(c,('authoritative_current_test_reconciliation','provenance','lexical_scan_unadjudicated_before_classification'))==4300
assert get(c,('audit_boundaries','latest_read_only_verification','authoritative_test_reconciliation','lexical_scan_unadjudicated_before_classification'))==4300
for path,h in PINS.items():assert sha(pathlib.Path(path).read_bytes())==h,'Pinned input changed during audit'
report={'reviewer':'/root/qa_integrator/test_inventory','as_of':datetime.datetime.now(datetime.timezone.utc).isoformat(),'decision':'ACCEPT_EXACT_AUTHORITY93_SOURCE_CLASSIFICATION_PROMOTION_NO_RUNTIME_CREDIT','scope':'Independent actual before/current ledger promotion audit; source classifications established by separately pinned packet/peer. No existing ledger mutation or promotion-script execution.','source_commit':HEAD,'source_tree':TREE,'artifacts':{k:{'sha256':h,'bytes':len(raw[k]),'mode':format(stat.S_IMODE(pathlib.Path(k).stat().st_mode),'04o')} for k,h in PINS.items()},'counts':{'baseline_originals':4319,'retired_unchanged':19,'retained':4300,'retained_body_exact':4276,'retained_body_changed':23,'expanded_retained_owner_rename':1,'classified_retained':102,'integration':78,'unit':23,'mixed':1,'globally_unadjudicated':4198,'new_authority_classified':93,'runtime_qualification_delta':0,'retirement_delta':0,'identities':['19 + 102 + 4198 = 4319','102 + 4198 = 4300','78 + 23 + 1 = 102','9 ociclient + 93 authority = 102 disjoint retained originals']},'verified':{'all_parent_input_pins_match_and_rechecked_at_end':True,'all12_current_mirrors_deep_equal':True,'completion_mirrors':10,'progress_mirrors':2,'prior_ociclient9_receipt_deep_exact_in_each_current_mirror':True,'prior_ociclient_promotion_audit_pin_and_before_ledger_chain_verified':True,'authority93_packet_peer_inventory_name_hash_class_matches':True,'ociclient9_authority93_and_retired19_pairwise_disjoint':True,'all4319_inventory_roots_unique':True,'nineteen_retirement_dispositions_deep_unchanged_and_match_inventory':True,'all_five_categories_OPEN':True,'complete':False,'historical_d4ac_receipts_deep_unchanged':True,'historical_reconciliation_and_progress_history_deep_unchanged':True,'all_prior_classification_history_entries_unchanged':True,'all_prior_verification_history_entries_unchanged_and_previous_latest_appended_exactly':True,'all_prior_publication_history_entries_unchanged_and_previous_delta_appended_exactly':True,'frozen_lexical_scan_values_unchanged':True,'frozen_scan_all18_manifest_entries_unchanged':True,'ociclient_packet_manifest_unchanged':True,'no_other_nested_ledger_difference_after_validated_delta_normalization':True,'receipt_changed_paths_match_independently_computed_delta':True,'progress_completion_sha256_matches_current_completion_bytes':True,'source_and_runtime_qualification_records_unchanged_outside_classification_summary':True,'financial_gap_main_published_main_ci_build_native_and_union_runtime_records_unchanged':True,'promotion_script_read_and_ast_parsed_not_executed':True},'current_mirror_locations':{'completion':[list(q) for q in CM],'progress':[list(q) for q in PM]},'independently_computed_changed_paths':{k:[list(q) for q in sorted(v,key=str)] for k,v in actualdiff.items()},'validated_delta_normalization':approved,'frozen_input_manifest_proofs':manifest_proofs,'authority93_classified_roots':[{'path':key[0],'original_name':key[1],'original_declaration_sha256':auth[key]['original_declaration_sha256'],'current_declaration_sha256':auth[key]['current_declaration_sha256'],'classification':auth[key]['classification'],'runtime_qualification':'UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION'} for key in sorted(auth)],'ociclient9_classified_roots':[{'path':key[0],'original_name':key[1],'classification':oci_roots[key]['category'],'original_declaration_sha256':oci_roots[key]['original_declaration_sha256']} for key in sorted(oci_roots)],'retired19_unchanged_roots':[{'path':key[0],'original_name':key[1],'original_declaration_sha256':retired[key]['original_declaration_sha256']} for key in sorted(retired)],'findings':[],'limits':['Acceptance binds only exact pinned completion2844cc0d/progressb080e439 and immutable receipt96dcd5de; later ledger/source changes require their own audit.','Source classification adds no runtime/main/global/native/cloud/production/financial qualification. All five completion categories remain OPEN.','No Go, source, Git, runtime, process/listener/lock or cloud operation; promotion script was read/parsed only. Only this exclusive temporary report directory was created.','All original safety assertions and suite obligations remain. No retirement or ledger changes were made by this audit.','Runtime claims were not requalified; all93 authority roots remain UNKNOWN under their accepted source packet.']}
(OUT/'review.json').write_text(json.dumps(report,indent=2)+'\n')
(OUT/'SHA256SUMS').write_text(''.join(sha((OUT/n).read_bytes())+'  '+n+'\n' for n in ['review.json','verify.py']))
for n in ['review.json','verify.py','SHA256SUMS']:os.chmod(OUT/n,0o400)
os.chmod(OUT,0o500)
print(json.dumps({'path':str(OUT/'review.json'),'sha256':sha((OUT/'review.json').read_bytes()),'bytes':(OUT/'review.json').stat().st_size,'SHA256SUMS_sha256':sha((OUT/'SHA256SUMS').read_bytes()),'decision':report['decision'],'counts':report['counts'],'changed_path_counts':{k:len(v) for k,v in actualdiff.items()}},indent=2))
