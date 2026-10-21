import pathlib,json,hashlib,csv,collections,subprocess,stat
HERE=pathlib.Path(__file__).resolve().parent
G='/run/current-system/sw/bin/git';REPO='/home/mariogk/Projects/TerraScale/ts-orchestrator'
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):return json.loads((HERE/p).read_text())
def at(x,path):
 for k in path:x=x[k]
 return x
def rid(r):return r['path']+'::'+r['original_name']
P=read('proposal.json');M=read('inputs-manifest.json');A=read('inputs/allocation.json');AUD=read('inputs/accepted102-audit.json');S=read('proposed-classification-summary.json')
for m in M['entries']:
 z=(HERE/m['snapshot']).read_bytes();assert sha(z)==m['sha256'] and len(z)==m['bytes'],m['snapshot']
actual=set(str(p.relative_to(HERE)) for p in HERE.rglob('*') if p.is_file())
summed=set()
for line in (HERE/'SHA256SUMS').read_text().splitlines():
 h,p=line.split(None,1);assert sha((HERE/p).read_bytes())==h,p;summed.add(p)
assert actual==summed|{'SHA256SUMS'}
assert all(stat.S_IMODE(p.stat().st_mode)==(0o555 if p.is_dir() else 0o444) for p in HERE.rglob('*'))
assert stat.S_IMODE(HERE.stat().st_mode)==0o555
inventory_all=list(csv.DictReader((HERE/'inputs/firstparty-survival.tsv').open(),delimiter='\t'));inv=[r for r in inventory_all if r['kind']=='test'];IM={rid(r):r for r in inv}
assert len(inv)==len(IM)==4319
old=P['preexisting_classified102_roots'];oldids={rid(r) for r in old};ret=P['prior_retired19_roots'];retids={rid(r) for r in ret}
assert len(old)==len(oldids)==102 and len(ret)==len(retids)==19
assert oldids==set(A['excluded_original_root_ids']['accepted102'])
assert retids==set(A['excluded_original_root_ids']['retired19'])
assert oldids=={rid(r) for r in AUD['authority93_classified_roots']+AUD['ociclient9_classified_roots']}
assert retids=={rid(r) for r in AUD['retired19_unchanged_roots']}
alloc=[r for b in A['batches'] for r in b['roots']];AD={r['root_id']:r for r in alloc};allocids=set(AD)
assert len(alloc)==len(AD)==79 and allocids==set(P['allocated79_root_ids'])
assert not oldids&retids and not allocids&(oldids|retids)
new=P['proposed_classified_roots'];un=P['reviewed_unresolved_roots'];newids={r['root_id'] for r in new};unids={r['root_id'] for r in un};pending=set(P['pending_allocated_not_in_this_proposal_root_ids'])
assert len(new)==len(newids)==69 and len(un)==len(unids)==10 and len(pending)==0
assert not newids&unids and not newids&pending and not unids&pending
assert newids|unids|pending==allocids
assert pending==set()
for r in old+ret+alloc+new+un:
 i=IM[rid(r)]
 for k in ['path','original_name','original_declaration_sha256']:assert r[k]==i[k],(rid(r),k)
 if r in alloc or r in new or r in un:
  for k in ['kind','current_name','current_declaration_sha256']:assert r[k]==i[k],(rid(r),k)
  assert r['survival_state']==i['state']
for r in new+un:
 for k in ['root_id','path','original_name','current_name','original_declaration_sha256','current_declaration_sha256','survival_state']:assert r[k]==AD[r['root_id']][k]
 assert r['runtime_qualification']=='UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION' and r['retirement_authorized']==False and r['safety_obligations_retained']==True
 peer=read(r['peer_report_input']);pr=next(x for x in peer['roots'] if x['root_id']==r['root_id'])
 assert r['proposed_classification']==pr.get('peer_classification',pr.get('accepted_classification',pr.get('accepted_source_classification')))
 candidate=read(r['candidate_input']);cr=next(x for x in candidate['roots'] if x['root_id']==r['root_id'])
 assert r['author_classification']==cr['classification']
 assert r['classification_credit_if_promoted']==(r['proposed_classification']!='unresolved')
cache={};declchecks=0
for r in alloc:
 for prefix in ['original','current']:
  ss=r[prefix+'_source'];c=ss['commit'];p=r['path'];key=(c,p)
  if key not in cache:cache[key]=subprocess.check_output([G,'-C',REPO,'show',c+':'+p]).splitlines()
  lines=cache[key];z=b'\n'.join(lines[ss['line']-1:ss['end_line']]);assert sha(z)==r[prefix+'_declaration_sha256']
  assert z.startswith(('func '+r[prefix+'_name']+'(').encode()) and z.endswith(b'\n}') and b'}' not in z.splitlines()[1:-1]
  declchecks+=1
bc=collections.Counter(r['classification'] for r in old);dc=collections.Counter(r['proposed_classification'] for r in new)
assert bc=={'integration':78,'unit':23,'mixed':1} and dc=={'integration':22,'unit':20,'mixed':27}
assert P['before_counts']=={'baseline_originals':4319,'retired':19,'retained':4300,'classified':102,'integration':78,'unit':23,'mixed':1,'globally_unadjudicated':4198}
assert P['proposed_after_counts']=={'baseline_originals':4319,'retired':19,'retained':4300,'classified':171,'integration':100,'unit':43,'mixed':28,'globally_unadjudicated':4129,'reviewed_unresolved_included_in_unadjudicated':10,'remaining_other_unadjudicated':4119}
assert 171+4129==4300 and 19+171+4129==4319 and 100+43+28==171 and 4129==10+4119
before=read('inputs/expected-before-completion.json');progress=read('inputs/expected-before-progress.json');bs=before['source_classification_adjudication'];mirrors=0
for label,obj in [('completion',before),('progress',progress)]:
 for path in AUD['current_mirror_locations'][label]:assert at(obj,path)==bs;mirrors+=1
assert mirrors==12 and bs['retained_originals_classified']==102 and bs['integration']==78 and bs['unit']==23 and bs['mixed']==1 and bs['classification_unadjudicated_remaining']==4198
assert before['complete']==False and all(x['status']=='OPEN' for x in before['open_categories'])
assert S['retained_originals_classified']==171 and S['integration']==100 and S['unit']==43 and S['mixed']==28 and S['classification_unadjudicated_remaining']==4129
assert S['reviewed_unresolved_retained_originals']==S['unresolved_within_classified_package']==10
assert S['baseline_rows']==171+10+5==186
for key in ['internal/authority','internal/ociclient']:assert S['accepted_package_classifications'][key]==bs['accepted_package_classifications'][key]
assert S['source_commit']==P['source_commit']==A['source_commit']=='d4ac68882716e7cfb14afca2f88ad596a38041af'
assert P['bridge_qualification']=='NOTQUALIFIED_NO_AUTOMATIC_TRANSFER'
assert P['proposed_delta']['runtime']==P['proposed_delta']['retirement']==0 and not any(P['actual_mutations'].values())
for name in ['internal/functions','internal/natscell','internal/oci','internal/region']:
 item=S['accepted_package_classifications'][name]
 assert len(item['original_root_ids'])==item['retained_originals_classified']
 assert set(item['original_root_ids'])<=newids and set(item['reviewed_unresolved_original_root_ids'])<=unids
for b in P['accepted_batch_receipts']:
 rows=[r for r in new+un if r['batch_id']==b['batch_id']];cc=collections.Counter(r['proposed_classification'] for r in rows)
 assert b['counts']=={k:cc[k] for k in ['integration','unit','mixed','unresolved']}
 assert b['classified_roots']==sum(cc[k] for k in ['integration','unit','mixed']) and b['reviewed_unresolved_roots']==cc['unresolved']
receipt=read('inputs/concurrent-evidence102/receipt.json');assert receipt['classification_delta']==0 and receipt['classification_reconciliation_objects_unchanged']==True
for name in ['completion','progress']:
 info=receipt['before'][name];snapshot=next(m for m in M['entries'] if m['snapshot']=='inputs/before-'+name+'.json')
 assert snapshot['sha256']==info['sha256']
current_before_equal={name:sha(pathlib.Path(receipt['before'][name]['original']).read_bytes())==next(m['sha256'] for m in M['entries'] if m['snapshot']=='inputs/expected-before-'+name+'.json') for name in ['completion','progress']}
for name in ['completion','progress']:
 expected=next(m for m in M['entries'] if m['snapshot']=='inputs/expected-before-'+name+'.json')
 assert expected['sha256']==receipt['outputs'][name]['sha256']
assert read('inputs/concurrent-evidence102/independent-review.json')
print(json.dumps({'verified':True,'state':P['state'],'proposed_classified_delta':len(new),'integration_delta':dc['integration'],'unit_delta':dc['unit'],'mixed_delta':dc['mixed'],'reviewed_unresolved_separate':len(un),'all_allocated_roots_verified':len(alloc),'baseline_current_declaration_checks':declchecks,'preexisting_mirrors_verified':mirrors,'current_shared_matches_expected_evidence102_before':current_before_equal,'ledger_mutation':False,'runtime_credit':0,'retirement_delta':0}))
