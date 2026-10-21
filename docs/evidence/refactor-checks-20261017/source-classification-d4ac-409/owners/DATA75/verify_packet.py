import collections,hashlib,json,pathlib,re,subprocess
P=pathlib.Path(__file__).parent
D=json.loads((P/'classification.json').read_bytes())
A=json.loads(pathlib.Path(D['allocation']['path']).read_bytes())
B=next(x for x in A['batches'] if x['batch_id']=='DATA75')
sha=lambda x:hashlib.sha256(x).hexdigest()
assert sha(pathlib.Path(D['allocation']['path']).read_bytes())==D['allocation']['sha256']
assert D['literal_root_ids']==[r['root_id'] for r in B['roots']]
assert len(D['roots'])==75==len(set(D['literal_root_ids']))
assert D['source_commit']=='d4ac68882716e7cfb14afca2f88ad596a38041af'
assert D['source_tree']=='3b73a410a025bd8050ad1d42e54acc7d5eda4b82'
assert D['baseline_commit']=='bfca60368f60d2da67f9016d1d489317ae8749c8'
byfile={}
for pin in D['source_pins']:
 raw=(P/pin['packet_copy']).read_bytes()
 assert len(raw)==pin['bytes'] and sha(raw)==pin['sha256']
 assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==pin['git_blob']
 assert pin['git_mode']=='100644'
 byfile[(pin['commit'],pin['path'])]=raw.splitlines()
checked=0
def walk(obj):
 global checked
 if isinstance(obj,dict):
  if all(k in obj for k in ['path','commit','start_line','end_line','span_sha256','git_blob']):
   lines=byfile[(obj['commit'],obj['path'])];a=obj['start_line'];b=obj['end_line'];assert 1<=a<=b<=len(lines)
   span=b'\n'.join(lines[a-1:b]);assert sha(span)==obj['span_sha256']
   assert len(span)==obj['span_bytes']
   if 'text' in obj:assert span.decode()==obj['text']
   checked+=1
  for value in obj.values():walk(value)
 elif isinstance(obj,list):
  for value in obj:walk(value)
walk(D)
for r,a in zip(D['roots'],B['roots'],strict=True):
 for field in ['root_id','path','original_name','current_name','original_declaration_sha256','current_declaration_sha256','state']:
  assert r[field]==a[field]
 assert r['baseline_source']['span_sha256']==r['original_declaration_sha256']
 assert r['current_source']['span_sha256']==r['current_declaration_sha256']
 assert r['current_source']['span_sha256']==r['baseline_source']['span_sha256']
 assert sha((P/r['raw_current_declaration_packet_file']).read_bytes())==r['current_declaration_sha256']
 assert r['runtime']=='UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION'
 assert not r['retirement_authorized'] and r['retirement_delta']==0 and r['safety_obligations_retained']
 assert (r['category']=='unresolved')==bool(r['source_blocker'])
 for block in r['core_assertion_blocks']:
  assert r['source_declaration']['start_line']<=block['start_line']<=block['end_line']<=r['source_declaration']['end_line']
 for assertion in r['all_failure_assertion_lines']:
  assert byfile[(D['source_commit'],r['path'])][assertion['line']-1].decode()==assertion['text']
counts=collections.Counter(r['category'] for r in D['roots'])
for c in ['integration','unit','mixed','unresolved']:assert counts[c]==D['counts'][c]
assert sum(counts.values())==75
assert counts=={'unresolved':57,'unit':16,'integration':2}
assert sum(r['source_blocker']=='DATA75-B1' for r in D['roots'])==56
assert sum(r['source_blocker']=='DATA75-B2' for r in D['roots'])==1
names={'Publish':'Publish','admissionGet':'Get','recordPublish':'recordPublishCall','codecSign':'Sign','codecVerify':'Verify','artifactSign':'SignArtifact','artifactVerify':'VerifyArtifact','archivedVerify':'VerifyArchivedArtifact','fenceCurrent':'Current','fenceGuard':'Guard','fetch':'Fetch','ackFetch':'Fetch','ack':'Ack','standbyCurrent':'Current','standbyGuard':'Guard','planner':'Plan','writer':'ApplyDesired','testService':'testService','testServiceWithRuntime':'testServiceWithRuntime','testIntent':'testIntent','mustJSON':'mustJSON'}
for suffix,name in names.items():
 c=D['citation_catalog']['helper.'+suffix];assert c['function_or_declaration']==name,(suffix,c)
assert b'Lab' not in b'\n'.join(byfile[(D['source_commit'],'internal/natscell/runtime.go')][130:148])
assert b'Lab: true' in byfile[(D['source_commit'],'internal/delivery/service_test.go')][216]
assert b'Lab: true' in byfile[(D['source_commit'],'internal/delivery/container_consumer_integration_test.go')][28]
result={'status':'PASS_STATIC_PACKET_INTEGRITY','allocated_originals':75,'baseline_source_declaration_spans':150,'canonical_full_file_pins':len(D['source_pins']),'all_citation_spans_and_embedded_text_verified':checked,'counts':dict(counts),'runtime':'UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION','source_or_ledger_edits':0,'retirement_delta':0}
print(json.dumps(result,sort_keys=True))
