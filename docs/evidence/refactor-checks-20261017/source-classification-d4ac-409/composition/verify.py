from pathlib import Path
import collections, copy, csv, hashlib, json, sys

root=Path(sys.argv[1])
sha=lambda b:hashlib.sha256(b).hexdigest()
read=lambda p:json.loads(Path(p).read_bytes())
manifest=read(root/'inputs-manifest.json')
for entry in manifest['inputs']:
    data=Path(entry['path']).read_bytes()
    assert sha(data)==entry['sha256'] and len(data)==entry['bytes']
proposal=read(manifest['delta_path'])
prior=read(manifest['prior69_path'])
summary=read(root/'proposed-classification-summary.json')
accounting=read(root/'original-root-accounting.json')
receipt=read(root/'receipt.json')
rid=lambda r:r['path']+'::'+r['original_name']
inventory={rid(r):r for r in csv.DictReader(Path(manifest['inventory_path']).read_text().splitlines(),delimiter='\t') if r['kind']=='test'}
assert len(inventory)==4319
expected={k:set() for k in ['integration','unit','mixed','reviewed_unresolved','retired','other_unadjudicated']}
for r in prior['preexisting_classified102_roots']:expected[r['classification']].add(rid(r))
for r in prior['proposed_classified_roots']:expected[r['proposed_classification']].add(r['root_id'])
expected['reviewed_unresolved'].update(r['root_id'] for r in prior['reviewed_unresolved_roots'])
expected['retired'].update(rid(r) for r in prior['prior_retired19_roots'])
for r in proposal['roots']:
    category=r['proposed_classification']
    expected['reviewed_unresolved' if category=='unresolved' else category].add(r['root_id'])
expected['other_unadjudicated']=set(inventory)-set().union(*expected.values())
assert {k:len(v) for k,v in expected.items()}=={'integration':184,'unit':160,'mixed':65,'reviewed_unresolved':72,'retired':19,'other_unadjudicated':3819}
assert sum(map(len,expected.values()))==len(set().union(*expected.values()))==4319
assert {k:sorted(v) for k,v in expected.items()}==accounting['original_root_ids_by_disposition']
assert {k for k,r in inventory.items() if r['state']=='qualified_retired'}==expected['retired']
assert summary['baseline_originals_total']==4319 and summary['baseline_rows']==486
assert summary['retained_originals_classified']==409 and summary['integration']==184 and summary['unit']==160 and summary['mixed']==65
assert summary['classification_unadjudicated_remaining']==3891 and summary['reviewed_unresolved_retained_originals']==72 and summary['remaining_other_unadjudicated']==3819
assert summary['retained_originals_total']==4300 and summary['retirements_total']==19 and summary['retirement_delta']==0 and summary['runtime_qualified_by_this_classification']==0
assert summary['unresolved_within_classified_package']==72 and summary['reviewed_unresolved_included_in_global_unadjudicated']
assert summary['source_commit']==proposal['source_commit'] and summary['source_tree']==proposal['source_tree']
def get(obj,path):
    for key in path:obj=obj[key]
    return obj
def put(obj,path,value):
    get(obj,path[:-1])[path[-1]]=value
mirrors=0
for name in ['completion','progress']:
    entry=receipt['ledgers'][name]
    before_raw=(root/entry['before_path']).read_bytes();after_raw=(root/entry['after_path']).read_bytes()
    assert sha(before_raw)==entry['before_sha256'] and sha(after_raw)==entry['after_sha256']
    before=json.loads(before_raw);after=json.loads(after_raw);restored=copy.deepcopy(after)
    paths=manifest['mirror_paths'][name]
    for path in paths:
        assert get(after,path)==summary
        put(restored,path,copy.deepcopy(get(before,path)));mirrors+=1
    assert after['classification_adjudication_history'][:-1]==before['classification_adjudication_history']
    history=after['classification_adjudication_history'][-1]
    assert history['controlling_corrections']==proposal['controlling_corrections']
    assert history['proposed_delta']==proposal['proposed_delta'] and history['proposed_after_counts']==proposal['proposed_after_counts']
    assert history['independent_delta_review']==receipt['independent_delta_review']
    assert history['before_snapshot']['sha256']==entry['before_sha256']
    restored['classification_adjudication_history']=copy.deepcopy(before['classification_adjudication_history'])
    restored['as_of']=before['as_of']
    assert restored==before,'Unrelated ledger mutation: '+name
    assert after['source_classification_adjudication']['accepted_package_classifications']==before['source_classification_adjudication']['accepted_package_classifications']
    if name=='completion':
        assert after['complete'] is False and len(after['open_categories'])==5 and all(c['status']=='OPEN' for c in after['open_categories'])
        vendor=after['authoritative_current_test_reconciliation']['vendor']
        assert vendor['current_tree_present']==1449 and vendor['current_tree_retired_originals']==0 and vendor['centrally_closed']==0
    else:
        vendor=after['vendor_canonical_presence']
        assert vendor['present']==1449 and vendor['canonical_retirements']==0 and vendor['central_closures']==0
assert mirrors==12
assert receipt['state']=='FULL_COMPOSED_PROPOSAL_NOT_APPLIED_PENDING_INDEPENDENT_COMPOSITION_REVIEW'
assert receipt['actual_shared_ledger_mutation'] is False and receipt['source_qualification_transfer'] is False
review=read(receipt['independent_delta_review']['path'])
assert receipt['independent_delta_review']['sha256']==sha(Path(receipt['independent_delta_review']['path']).read_bytes())
assert review['decision']=='ACCEPT_EXACT_SOURCE_ONLY_DELTA_PROPOSAL_NOT_COMPOSITION_OR_PROMOTION'
assert review['proposal_sha256']==sha(Path(manifest['delta_path']).read_bytes()) and not review['blocking_findings']
assert summary['next300_controlling_evidence']['exact_independent_citation_disposition']==review['nonblocking_citation_limitation']
print(json.dumps({'status':'PASS_FULL_COMPOSITION_STRUCTURE_AND_ORIGINAL_ACCOUNTING_ONLY','mirrors':mirrors,'originals':4319,'retired':19,'retained':4300,'proposed_classified':409,'integration':184,'unit':160,'mixed':65,'unadjudicated':3891,'reviewed_unresolved':72,'other_unadjudicated':3819,'unrelated_changes':0,'history_prefixes_preserved':True,'vendor_originals':1449,'vendor_retired':0,'vendor_central_closures':0,'runtime_credit':0,'shared_mutation':False},sort_keys=True))
