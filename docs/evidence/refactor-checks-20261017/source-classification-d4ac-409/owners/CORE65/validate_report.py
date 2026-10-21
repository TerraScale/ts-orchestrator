import collections,hashlib,json,pathlib,subprocess
D=pathlib.Path(__file__).parent; R=json.loads((D/'classification.json').read_bytes()); A=json.loads(pathlib.Path(R['allocation_manifest']['path']).read_bytes()); batch=next(b for b in A['batches'] if b['batch_id']=='CORE65')
sha=lambda b:hashlib.sha256(b).hexdigest()
G='/run/current-system/sw/bin/git'; C=R['source_commit']; B=R['baseline_commit']
assert sha(pathlib.Path(R['allocation_manifest']['path']).read_bytes())==R['allocation_manifest']['sha256']
assert sha(pathlib.Path(R['output_contract']['path']).read_bytes())==R['output_contract']['sha256']
assert len(R['roots'])==65 and len({r['root_id'] for r in R['roots']})==65
assert {r['root_id'] for r in R['roots']}=={r['root_id'] for r in batch['roots']}
assert len({r['path'] for r in R['roots']})==28
assert dict(collections.Counter(r['category'] for r in R['roots']))==R['counts']
assert R['counts']=={'integration':13,'unit':36,'mixed':15,'unresolved':1}
assert R['runtime']=='UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION' and R['retirement_authorized'] is False
cache={}
for p in R['source_file_pins']:
 key=p['commit']+':'+p['path']; assert key not in cache
 raw=subprocess.check_output([G,'show',key]); meta=subprocess.check_output([G,'ls-tree',p['commit'],'--',p['path']]).decode().split()
 assert sha(raw)==p['sha256'] and len(raw)==p['bytes'] and meta[0]==p['git_mode'] and meta[2]==p['git_blob']
 assert p['commit'] in {C,B}; cache[key]=raw
for cid,c in R['citation_index'].items():
 raw=cache[c['file_pin']]; lines=raw.decode().splitlines(); selected=lines[c['start_line']-1:c['end_line']]
 assert c['source_lines']==[{'line':i,'text':lines[i-1]} for i in range(c['start_line'],c['end_line']+1)]
 assert sha(('\n'.join(selected)).encode())==c['sha256']
 assert selected[0].startswith('func ') and selected[-1].rstrip().endswith('}')
for r in R['roots']:
 assert r['runtime']==R['runtime'] and r['retirement_authorized'] is False and r['safety_obligations_retained'] is True
 assert r['survival_state']=='retained_body_exact'
 for c,key in [(r['current_declaration'],C+':'+r['path']),(r['baseline_declaration_reconfirmed'],B+':'+r['path'])]:
  lines=cache[key].splitlines(); raw=b'\n'.join(lines[c['start_line']-1:c['end_line']]); assert sha(raw)==c['sha256']
 assert r['current_declaration_sha256']==r['current_raw_declaration_sha256_reconfirmed']==r['source_declaration']['sha256']
 assert r['original_declaration_sha256']==r['baseline_raw_declaration_sha256_reconfirmed']
 lines=cache[C+':'+r['path']].decode().splitlines(); c=r['current_declaration']
 assert r['assertion_source']==[{'line':i,'text':lines[i-1]} for i in range(c['start_line'],c['end_line']+1)]
 for a in r['assertion_sites']: assert a['text']==lines[a['line']-1].strip()
 assert r['connected_production_citations']
 for c in r['setup_helper_citations']+r['connected_production_citations']:
  x=R['citation_index'][c['citation_id']]
  for k,v in c.items():
   if k!='citation_id': assert x[k]==v
unresolved=[r for r in R['roots'] if r['category']=='unresolved']; assert len(unresolved)==1 and unresolved[0]['current_name']=='TestRuntimeServiceSurvivesNodeRestart'
result={'status':'STATIC_PACKET_VALIDATED_NO_RUNTIME_EXECUTION','source_commit':C,'batch':'CORE65','roots':65,'test_files':28,'counts':R['counts'],'source_files_reconfirmed':len(cache),'function_citations_validated':len(R['citation_index']),'raw_declarations_reconfirmed':130,'assertion_sites_retained':sum(len(r['assertion_sites']) for r in R['roots']),'classification_json_sha256':sha((D/'classification.json').read_bytes()),'runtime':R['runtime'],'retirement_authorized':False,'accepted_ledger_mutated':False}
(D/'validation.json').write_text(json.dumps(result,indent=2)+'\n'); print(json.dumps(result))
