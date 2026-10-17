import json,hashlib,subprocess,collections
from pathlib import Path
OUT=Path(__file__).parent
OWNER=Path('/tmp/ts-net48-d4ac-source-classification-k9shja9e')
A=Path('/tmp/ts-d4ac-next300-allocation-proposal-raxuc07l/allocation.json')
sha=lambda b:hashlib.sha256(b).hexdigest()
p=json.loads((OWNER/'classification.json').read_bytes())
a=json.loads(A.read_bytes())
assert sha((OWNER/'classification.json').read_bytes())=='c89d6e3558298634ed2f902d0a55fa2d95496e26800be31b283dbf4da3b409e2'
assert sha((OWNER/'SHA256SUMS').read_bytes())=='300af62e0e6947a3ce4bbfca319c8fc10d0fb5fdede5cef5544cc9452991960c'
assert sha(A.read_bytes())=='032cb201e692326da7274b12d7dfd15512b1befd325cce375188ae0447ca2523'
batch=next(x for x in a['batches'] if x['batch_id']=='NET48')
allocated=[x['root_id'] for x in batch['roots']]
assert [x['root_id'] for x in p['roots']]==allocated
cache={}
def source(commit,path):
 key=(commit,path)
 if key not in cache:
  cache[key]=subprocess.check_output(['/run/current-system/sw/bin/git','show',f'{commit}:{path}'])
 return cache[key]
def blob(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def span(b,s,e):return b'\n'.join(b.split(b'\n')[s-1:e])
assert subprocess.check_output(['/run/current-system/sw/bin/git','show','--no-patch','--format=%T',p['source_commit']]).decode().strip()==p['source_tree']
for pin in p['source_pins']:
 b=source(pin['commit'],pin['path'])
 assert len(b)==pin['bytes'] and sha(b)==pin['sha256'] and blob(b)==pin['git_blob'],pin
 assert (OWNER/pin['archived_as']).read_bytes()==b,pin
pinmap={(x['commit'],x['path']):x for x in p['source_pins']}
checks=collections.Counter()
for r in p['roots']:
 for version in ['baseline','current']:
  d=r[version];commit=p['baseline_commit' if version=='baseline' else 'source_commit'];b=source(commit,r['path'])
  raw=span(b,d['start_line'],d['end_line'])
  assert sha(raw)==d['raw_declaration_sha256'],r['root_id']
  assert raw.startswith(b'func '+d['function'].encode()+b'(') and raw.endswith(b'\n}')
  assert sha(b)==d['file_sha256'] and len(b)==d['file_bytes'] and blob(b)==d['git_blob']
  assert (OWNER/d['archived_as']).read_bytes()==b
  checks['root_declarations']+=1
 b=source(p['source_commit'],r['path']);lines=b.decode().split('\n')
 assert r['exact_current_declaration_with_all_assertions']=='\n'.join(f'{i}: {lines[i-1]}' for i in range(r['current']['start_line'],r['current']['end_line']+1))
 checks['complete_numbered_declarations']+=1
 for s in r['exact_assertion_sites']:
  assert lines[s['failure_line']-1]==s['exact_failure_text']
  assert span(b,s['condition_context_start_line'],s['condition_context_end_line']).decode()==s['exact_condition_context']
  checks['assertion_sites']+=1;checks['condition_spans']+=1
 for d in r['connected_declarations']:
  b=source(p['source_commit'],d['path']);raw=span(b,d['start_line'],d['end_line'])
  assert blob(b)==d['git_blob']
  assert (p['source_commit'],d['path']) in pinmap
  if 'declaration_sha256' in d:
   assert sha(raw)==d['declaration_sha256']
   assert sha(b)==d['file_sha256'] and len(b)==d['file_bytes']
  else:assert raw.decode()==d['exact_text']
  checks['connected_spans']+=1
for d in p['allocated_bounded_scope_reads']:
 b=source(p['source_commit'],d['path'])
 assert blob(b)==d['git_blob'] and sha(span(b,d['start_line'],d['end_line']))==d['span_sha256']
 checks['bounded_scope_spans']+=1
counts=dict(collections.Counter(r['category'] for r in p['roots']))
assert counts==p['counts']['candidates_by_category']
for line in (OWNER/'SHA256SUMS').read_text().splitlines():
 digest,name=line.split('  ',1)
 assert sha((OWNER/name).read_bytes())==digest,name
 checks['owner_checksum_entries']+=1
result={'status':'PASS','source_commit':p['source_commit'],'source_tree':p['source_tree'],'baseline_commit':p['baseline_commit'],'literal_ordered_root_ids_verified':len(allocated),'source_file_pins_verified':len(p['source_pins']),'checks':dict(checks),'owner_counts':counts,'canonical_source_method':'git show COMMIT:path; independent full-file SHA256/bytes/Git-blob hash; archives checked byte-for-byte. Git modes retained from owner pins, not independently rederived.','runtime':'UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION','retirement_delta':0,'ledger_promotion_delta':0}
(OUT/'integrity-verification.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
