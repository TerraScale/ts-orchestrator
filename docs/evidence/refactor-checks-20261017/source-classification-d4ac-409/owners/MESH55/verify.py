"""Independent static packet consistency check; immutable Git-object reads only."""
import collections,hashlib,json,pathlib,re,subprocess
D=pathlib.Path('/tmp/ts-mesh55-d4ac-source-classification-pfjjhj7x')
G='/run/current-system/sw/bin/git'
def digest(b):return hashlib.sha256(b).hexdigest()
r=json.loads((D/'classification.json').read_bytes());s=json.loads((D/'summary.json').read_bytes())
a_path=pathlib.Path(r['allocation_manifest']['path']);a=json.loads(a_path.read_bytes())
assert digest(a_path.read_bytes())==r['allocation_manifest']['sha256']
batch=next(b for b in a['batches'] if b['batch_id']=='MESH55');assert json.loads((D/'allocation-slice.json').read_bytes())==batch
actual={v['root_id']:v for v in r['originals']};expected={v['root_id']:v for v in batch['roots']}
assert len(actual)==len(expected)==len(r['originals'])==55 and actual.keys()==expected.keys()
excluded={v for values in a['excluded_original_root_ids'].values() for v in values}
assert len(excluded)==200 and not excluded.intersection(actual)
assert not set(a['prior79_root_ids']).intersection(actual)
assert r['source_commit']==a['source_commit'] and r['source_tree']==a['source_tree'] and r['baseline_commit']==a['baseline_commit']
assert subprocess.check_output([G,'rev-parse',r['source_commit']+'^{tree}']).decode().strip()==r['source_tree']
blobs={};file_pin_checks=0
for path,versions in r['source_pins'].items():
 for version,pin in versions.items():
  commit=r['source_commit'] if version=='source' else r['baseline_commit']
  data=subprocess.check_output([G,'show',commit+':'+path]);blobs[commit,path]=data
  mode,kind,tail=subprocess.check_output([G,'ls-tree',commit,'--',path]).decode().strip().split(' ',2)
  oid,gotpath=tail.split('\t',1)
  assert gotpath==path and kind=='blob'
  assert pin=={'bytes':len(data),'git_mode':mode,'git_blob':oid,'sha256':digest(data)}
  assert hashlib.sha1(('blob '+str(len(data))+'\0').encode()+data).hexdigest()==oid
  file_pin_checks+=1
span_checks=0
def check_span(v):
 global span_checks
 data=blobs[v['commit'],v['path']];lines=data.splitlines()
 raw=b'\n'.join(lines[v['start_line']-1:v['end_line']]);assert raw.decode()==v['text'] and digest(raw)==v['span_sha256'] and len(raw)==v['raw_bytes']
 ver='source' if v['commit']==r['source_commit'] else 'baseline'
 assert v['git_blob']==r['source_pins'][v['path']][ver]['git_blob'];span_checks+=1
for cid,v in r['citations'].items():
 assert cid==v['path']+'::'+v['function'];check_span(v)
 assert v['text'].startswith('func ') and v['text'].endswith('}')
for rid,v in actual.items():
 for key,val in expected[rid].items():assert v[key]==val,(rid,key)
 assert v['runtime']=='UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION' and v['retirement_authorized'] is False and v['retirement_credit']==0 and v['safety_obligations_retained'] is True
 for ver,evkey,declkey in [('baseline','baseline_declaration_evidence','baseline_declaration'),('source','source_declaration_evidence','source_declaration')]:
  ev=v[evkey];check_span(ev);assert ev['text'].startswith('func '+v['current_name']+'(') and ev['text'].endswith('\n}')
  assert ev['span_sha256']==v[declkey]['sha256'] and ev['start_line']==v[declkey]['start_line'] and ev['end_line']==v[declkey]['end_line']
  assert r['source_pins'][v['path']][ver]==a['canonical_test_file_pins'][v['path']][ver]
 assert v['original_declaration_sha256']==v['current_declaration_sha256']==v['baseline_declaration_evidence']['span_sha256']==v['source_declaration_evidence']['span_sha256']
 ev=v['source_declaration_evidence'];lines=ev['text'].splitlines()
 failure_sites=[{'line':i,'text':line.strip()} for i,line in enumerate(lines,ev['start_line']) if re.search(r'\bt\.(?:Fatalf?|Errorf?)\(',line)]
 assert failure_sites==v['assertion_sites'] and failure_sites
 for block in v['core_assertion_spans']+v['local_only_assertion_spans']:
  check_span(block);assert ev['start_line']<=block['start_line']<=block['end_line']<=ev['end_line']
 for cid in v['connected_setup_helper_refs']+v['connected_production_refs']:assert cid in r['citations']
 assert v['connected_production_refs'] and v['rationale'] and v['core_assertion_spans']
 if v['category']=='mixed':assert v['local_only_assertion_spans']
for finding in r['findings']:
 for block in finding['test_spans']:check_span(block)
 for cid in finding['production_refs']:assert cid in r['citations']
counts=dict(collections.Counter(v['category'] for v in actual.values()));counts['total']=sum(counts.values())
assert counts==r['counts']==s['counts']=={'mixed':11,'integration':35,'unresolved':1,'unit':8,'total':55}
assert s['classification_json_sha256']==digest((D/'classification.json').read_bytes())
assert r['accounting_effect']['accepted_before_and_after']==a['accepted_accounting']
assert r['accounting_effect']['classified_accepted_delta']==0 and r['accounting_effect']['retirement_delta']==0 and r['accounting_effect']['ledger_mutated'] is False
integrity={'status':'PASS_STATIC_PACKET_INTEGRITY_NOT_PEER_CLASSIFICATION_REVIEW','exact_allocated_root_ids':55,'duplicate_root_ids':0,
 'unallocated_roots':0,'excluded_root_intersection':0,'excluded_original_root_count_checked':200,'baseline_and_current_declarations_reconfirmed':110,
 'canonical_file_pin_versions_checked':file_pin_checks,'canonical_cited_source_files':len(r['source_pins']),'raw_spans_reconfirmed':span_checks,
 'counts':counts,'runtime':r['runtime'],'retirement_credit':0,'accepted_ledger_changes':0,
 'classification_json_sha256':digest((D/'classification.json').read_bytes()),
 'scope':'Static independent reconstruction of artifact consistency and immutable source pins. No Go/build/runtime execution and no independent semantic peer verdict.'}
(D/'integrity.json').write_text(json.dumps(integrity,indent=2,sort_keys=True)+'\n')
print(json.dumps(integrity,sort_keys=True))
