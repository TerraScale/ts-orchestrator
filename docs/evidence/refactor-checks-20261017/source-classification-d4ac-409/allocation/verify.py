import pathlib,json,hashlib,subprocess,csv,re,sys
D=pathlib.Path(__file__).resolve().parent
M=json.loads((D/'allocation.json').read_text())
G='/run/current-system/sw/bin/git';REPO='/home/mariogk/Projects/TerraScale/ts-orchestrator'
sha=lambda b:hashlib.sha256(b).hexdigest()
for name,pin in M['inputs'].items():assert sha(pathlib.Path(pin['path']).read_bytes())==pin['sha256'],name
assert sha(pathlib.Path(M['output_contract']['path']).read_bytes())==M['output_contract']['sha256']
p=json.loads(pathlib.Path(M['inputs']['accepted69_exact_delta_proposal']['path']).read_text())
r=json.loads(pathlib.Path(M['inputs']['actual69_promotion_receipt']['path']).read_text())
assert (r['classified'],r['integration'],r['unit'],r['mixed'],r['unadjudicated'],r['retired'],r['retained'])==(171,100,43,28,4129,19,4300)
assert r['new_runtime']==False and r['new_execution']==False and r['current7330_qualification_transfer']==False
rid=lambda r:r['path']+'::'+r['original_name']
expected={'accepted102':[rid(x) for x in p['preexisting_classified102_roots']],'accepted69':[rid(x) for x in p['proposed_classified_roots']],'reviewed_unresolved10':[rid(x) for x in p['reviewed_unresolved_roots']],'retired19':[rid(x) for x in p['prior_retired19_roots']]}
assert M['excluded_original_root_ids']=={k:sorted(v) for k,v in expected.items()}
arrays=list(M['excluded_original_root_ids'].values());ex=set(sum(arrays,[]));assert len(ex)==sum(map(len,arrays))==200
assert sorted(p['allocated79_root_ids'])==M['prior79_root_ids'];assert len(set(M['prior79_root_ids']))==79
assert set(M['prior79_root_ids'])==set(expected['accepted69'])|set(expected['reviewed_unresolved10'])
assert set(M['prior79_root_ids'])<=ex
rows=[x for x in csv.DictReader(pathlib.Path(M['inputs']['inventory']['path']).open(),delimiter='\t') if x['kind']=='test']
assert len(rows)==4319;byid={rid(x):x for x in rows};assert len(byid)==4319;assert ex<=byid.keys();eligible=set(byid)-ex;assert len(eligible)==4119
cache={}
def git(*a):return subprocess.check_output([G,'--no-optional-locks',*a],cwd=REPO)
def content(c,p):
 if (c,p) not in cache:cache[c,p]=git('show',c+':'+p)
 return cache[c,p]
def filepin(c,p):
 b=content(c,p);e=git('ls-tree',c,'--',p).decode().split();return {'git_mode':e[0],'git_blob':e[2],'sha256':sha(b),'bytes':len(b)}
def decl(c,p,n):
 b=content(c,p);m=re.search(rb'^func '+re.escape(n.encode())+rb'\(',b,re.M);assert m,(p,n)
 e=re.search(rb'^}',b[m.end():],re.M);assert e;stop=m.end()+e.end()
 return {'start_line':b.count(b'\n',0,m.start())+1,'end_line':b.count(b'\n',0,stop)+1,'sha256':sha(b[m.start():stop])}
C=M['source_commit'];B=M['baseline_commit']
assert git('rev-parse',C+'^{tree}').decode().strip()==M['source_tree']
assert git('rev-parse',M['bridge_commit']+'^{tree}').decode().strip()==M['bridge_tree']
for p,pins in M['canonical_test_file_pins'].items():
 assert filepin(B,p)==pins['baseline'];assert filepin(C,p)==pins['source']
for p,pin in M['bounded_source_read_file_pins'].items():assert filepin(C,p)==pin
seen=set();owners=set();nfiles=set();hashes=0
for batch in M['batches']:
 roots=batch['roots'];ids={x['root_id'] for x in roots};assert len(ids)==len(roots)==batch['root_count'];assert 40<=len(roots)<=80
 assert batch['proposed_owner'] not in owners;owners.add(batch['proposed_owner']);assert batch['owner_status_observed']=='completed';assert batch['dispatch_state']=='HOLD_PARENT_VERIFICATION_NO_DISPATCH'
 assert not ids&seen;seen|=ids;assert ids<=eligible
 expected_ids={rid(x) for x in rows if x['path'].rsplit('/',1)[0] in batch['package_scopes'] and rid(x) not in ex};assert ids==expected_ids
 for x in roots:
  base=byid[x['root_id']];assert all(x[k]==v for k,v in base.items());assert x['root_id']==rid(x)
  a=decl(B,x['path'],x['original_name']);b=decl(C,x['path'],x['current_name']);assert a==x['baseline_declaration'];assert b==x['source_declaration']
  assert a['sha256']==x['original_declaration_sha256'];assert b['sha256']==x['current_declaration_sha256'];assert x['state']=='retained_body_exact';assert a['sha256']==b['sha256'];hashes+=2;nfiles.add(x['path'])
 assert len({x['path'] for x in roots})==batch['test_file_count']
 for s in batch['bounded_scope_reads']:
  lines=content(C,s['path']).splitlines();assert sha(b'\n'.join(lines[s['start_line']-1:s['end_line']]))==s['span_sha256']
assert len(seen)==300 and not seen&ex and len(eligible-seen)==3819 and len(owners)==5 and hashes==600 and len(nfiles)==72
assert M['allocation_counts']=={'batches':5,'proposed_owners':5,'excluded_unique_original_roots':200,'eligible_original_roots':4119,'selected_original_roots':300,'eligible_unselected_original_roots':3819,'selected_test_files':72,'baseline_and_source_declaration_hashes_verified':600,'cross_batch_overlap':0,'selected_intersection_excluded':0,'source_classification_credit':0,'runtime_delta':0,'retirement_delta':0,'ledger_mutation':False,'dispatches':0}
print(json.dumps({'result':'PASS','selected_roots':300,'excluded_unique_roots':200,'prior79_excluded':True,'eligible':4119,'eligible_unselected':3819,'test_files':72,'declaration_hashes_verified':600,'dispatches':0,'source_classification_credit':0,'runtime_delta':0,'retirement_delta':0},sort_keys=True))
