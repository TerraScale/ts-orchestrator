import pathlib,json,hashlib,subprocess,re,os,csv,stat
G='/run/current-system/sw/bin/git'
REPO='/home/mariogk/Projects/TerraScale/ts-orchestrator'
C='d4ac68882716e7cfb14afca2f88ad596a38041af'
BR='7330ca87c377d2cbe5f8c269282039039df550ad'
B='bfca60368f60d2da67f9016d1d489317ae8749c8'
A=json.load(open('/tmp/ts-source-classification-batches-d4ac-0a9afk60/allocation.json'))
cache={}
def git(*args): return subprocess.check_output([G,'-C',REPO,*args])
def sha(x): return hashlib.sha256(x).hexdigest()
def blob(c,p):
 k=(c,p)
 if k not in cache: cache[k]=git('show',c+':'+p)
 return cache[k]
def span(c,p,a,b): return b'\n'.join(blob(c,p).splitlines()[a-1:b])
def meta(c,p):
 x=git('ls-tree',c,'--',p).decode().strip().split()
 return {'mode':x[0],'blob':x[2]}
def check(ok,msg):
 if not ok: errors.append(msg)
ONLY='natscell20'
checks={}
INV=list(csv.DictReader(open(A['inventory']['path']),delimiter='\t'))
IM={r['path']+'::'+r['original_name']:r for r in INV}
assert sha(pathlib.Path(A['inventory']['path']).read_bytes())==A['inventory']['sha256']
for batch,folder,expected in [('functions14','/tmp/ts-functions14-d4ac-source-classification-o5y_ymin','9510b271f01831ed0d0b8607f14d62f841a2e248bf1bcb491f2878e40154caf2'),('natscell20','/tmp/ts-natscell20-d4ac-source-classification-nzhpx105','b21ae142cb4d24e3bd64a2ba70ee920c87f765c734652ef0c3bd38a2efb54b50')]:
 if batch!=ONLY:continue
 errors=[]; folder=pathlib.Path(folder); raw=(folder/'classification.json').read_bytes(); d=json.loads(raw)
 check(sha(raw)==expected,'candidate sha')
 sumlines=(folder/'SHA256SUMS').read_text().splitlines(); sums=[]
 for l in sumlines:
  h,p=l.split(None,1); p=p.lstrip('*'); f=folder/p
  check(f.is_file() and sha(f.read_bytes())==h,'SUM '+p); sums.append(p)
 check(set(p.name for p in folder.iterdir())==set(sums)|{'SHA256SUMS'},'exact sealed file exhaustion')
 modes={str(p.relative_to(folder)):oct(stat.S_IMODE(p.stat().st_mode)) for p in folder.rglob('*')}
 check(all(v in ['0o444','0o555'] for v in modes.values()),'immutable modes')
 allocation=next(x for x in A['batches'] if x['batch_id']==batch)
 roots=d['roots']; ids=[r['root_id'] for r in roots]; ai=[r['root_id'] for r in allocation['roots']]
 check(len(ids)==len(set(ids)) and set(ids)==set(ai),'allocation exhaustion')
 check(not(set(ids)&set(A['excluded_original_root_ids'])),'excluded overlap')
 alloc={x['root_id']:x for x in allocation['roots']}
 declaration_checks=0
 for r in roots:
  q=alloc[r['root_id']]
  iv=IM[r['root_id']]
  for f in ['path','kind','original_name','current_name','original_declaration_sha256','current_declaration_sha256']: check(str(r[f])==iv[f],r['root_id']+' inventory '+f)
  check(r['survival_state']==iv['state'],r['root_id']+' inventory survival')
  for field in ['path','kind','original_name','current_name','original_declaration_sha256','current_declaration_sha256','survival_state']: check(r[field]==q[field],r['root_id']+' '+field)
  for label,c in [('original',B),('current',C)]:
   x=r[label+'_source']; p=r['path']; z=span(c,p,x['line'],x['end_line']); declaration_checks+=1
   check(sha(z)==r[label+'_declaration_sha256'],r['root_id']+' '+label+' declaration hash')
   check(z.startswith(('func '+r[label+'_name']+'(').encode()),r['root_id']+' start signature')
   check(z.endswith(b'\n}'),r['root_id']+' ending')
   check(b'}' not in z.splitlines()[1:-1],r['root_id']+' first closing boundary')
   if 'git_blob' in x:check(meta(c,p)['blob']==x['git_blob'],r['root_id']+' root blob')
  if 'complete_root_source' in r: check(span(C,r['path'],r['current_source']['line'],r['current_source']['end_line']).decode()==r['complete_root_source'],r['root_id']+' root source')
 source_checks=[]; bridge=[]
 for pin in d['source_pins']:
  c=pin.get('commit',C); p=pin['path']; raw=blob(c,p); m=meta(c,p)
  check(m['blob']==pin['git_blob'] and m['mode']==pin.get('git_mode',pin.get('mode')),p+' file mode/blob')
  check(len(raw)==pin['bytes'] and sha(raw)==pin['sha256'],p+' file bytes/sha')
  source_checks.append(c+':'+p)
  if c==C:
   bm=meta(BR,p); same=bm==m
   entry={'path':p,'d4ac':m,'bridge_commit':bm,'same_file_blob_and_mode':same}
   if not same:
    entry['selected_declarations']=[]
    btext=blob(BR,p)
    for r in roots:
     if r['path']!=p:continue
     pat=rb'^func '+re.escape(r['current_name'].encode())+rb'\('
     lines=btext.splitlines(); starts=[i for i,l in enumerate(lines) if re.match(pat,l)]
     if len(starts)==1:
      i=starts[0]; end=next(j for j in range(i+1,len(lines)) if lines[j]==b'}'); h=sha(b'\n'.join(lines[i:end+1]))
      entry['selected_declarations'].append({'root_id':r['root_id'],'sha256':h,'same_declaration':h==r['current_declaration_sha256']})
     else:entry['selected_declarations'].append({'root_id':r['root_id'],'unique_declaration_found':False})
   bridge.append(entry)
 citation_count=0; assertion_count=0; distinct=set(); cited_bridge=[]
 if batch=='functions14':
  for r in roots:
   for cit in r['boundary_setup_citations']+r['connected_production_citations']:
    p=cit['path']; a=cit['line']; b=cit['end_line']; z=span(C,p,a,b); citation_count+=1;distinct.add((p,a,b))
    check(meta(C,p)['blob']==cit['git_blob'],p+' citation blob')
    check(z.splitlines()[0].decode()==cit['function'],p+' citation signature')
    check(sha(z)==cit['declaration_sha256'],p+' citation hash')
   for x in r['assertion_evidence']:
    p=x['assertion_path']; a=x['line']; b=x['end_line']; assertion_count+=1
    check(span(C,p,a,b).decode()==x['exact_condition_and_assertion_text'],p+' assertion text')
    check(meta(C,p)['blob']==x['git_blob'],p+' assertion blob')
 else:
  for k,x in d['connected_source_evidence'].items():
   p=x['path'];a=x['start_line'];b=x['end_line'];citation_count+=1;distinct.add((p,a,b))
   check(span(C,p,a,b).decode()==x['source'],k+' citation source')
   check(meta(C,p)['blob']==x['git_blob'],k+' citation blob')
   cited_bridge.append({'citation':k,'exact_cited_source_preserved':x['source'].encode() in blob(BR,p)})
  for r in roots:
   for k in r['setup_helper_citations']+r['connected_production_citations']:check(k in d['connected_source_evidence'],r['root_id']+' missing citation')
   for x in r['assertion_blocks']:
    assertion_count+=1; p=x['path'];a=x['start_line'];b=x['end_line']
    check(span(C,p,a,b).decode()==x['exact_text'],p+' assertion text')
    check(meta(C,p)['blob']==x['git_blob'],p+' assertion blob')
 checks[batch]={'candidate_sha256':sha((folder/'classification.json').read_bytes()),'sha256sums_sha256':sha((folder/'SHA256SUMS').read_bytes()),'sum_entries':len(sums),'modes':modes,'allocation_root_count':len(ids),'declaration_checks':declaration_checks,'source_pins':len(source_checks),'citation_checks':citation_count,'distinct_citations':len(distinct),'assertion_blocks':assertion_count,'bridge_commit':BR,'bridge_tree':git('rev-parse',BR+'^{tree}').decode().strip(),'bridge_file_comparisons':bridge,'bridge_cited_declarations':cited_bridge,'frozen_inventory_roots_verified':len(roots),'errors':errors}
HERE=pathlib.Path(__file__).resolve().parent
review=json.loads((HERE/'review.json').read_text())
mechanical=json.loads((HERE/'mechanical.json').read_text())
assert checks[ONLY]==mechanical
assert not mechanical['errors']
assert len(review['original_root_ids'])==len(set(review['original_root_ids']))
assert set(review['original_root_ids'])==set(r['root_id'] for r in review['roots'])
from collections import Counter
cc=Counter(r['peer_classification'] for r in review['roots'])
for k in ['integration','unit','mixed','unresolved']:assert review['counts'][k]==cc[k]
assert review['counts']['accepted_classified_roots']==len(review['roots'])-cc['unresolved']
assert review['counts']['reviewed_unresolved_roots']==cc['unresolved']
for e in review['boundary_evidence']:
 z=span(e['commit'],e['path'],e['start_line'],e['end_line'])
 assert z.decode()==e['exact_source'] and sha(z)==e['sha256']
assert review['counts']['candidate_credit_promoted']==review['counts']['runtime_delta']==review['counts']['retirement_delta']==0
for l in (HERE/'SHA256SUMS').read_text().splitlines():
 h,p=l.split(None,1);assert sha((HERE/p).read_bytes())==h
print(json.dumps({'batch_id':ONLY,'verified':True,'counts':review['counts'],'mechanical_errors':mechanical['errors']}))
