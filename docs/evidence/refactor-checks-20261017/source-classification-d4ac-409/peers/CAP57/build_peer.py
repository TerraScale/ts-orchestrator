import json, pathlib, hashlib, subprocess, stat, re, collections
OUT=pathlib.Path(__file__).parent
OWNER=pathlib.Path('/tmp/ts-cap57-d4ac-source-classification-r9lqashl')
GIT='/run/current-system/sw/bin/git'
SRC='d4ac68882716e7cfb14afca2f88ad596a38041af'
BASE='bfca60368f60d2da67f9016d1d489317ae8749c8'
TREE='3b73a410a025bd8050ad1d42e54acc7d5eda4b82'
RUNTIME='UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION'
def sha(b): return hashlib.sha256(b).hexdigest()
def readjson(p): return json.loads(pathlib.Path(p).read_bytes())
def check(v,m):
 if not v: raise AssertionError(m)
def git(*args): return subprocess.check_output([GIT,*args])
def checked_input(p,h):
 b=pathlib.Path(p).read_bytes();check(sha(b)==h,'input hash '+str(p));return {'path':str(p),'sha256':h,'bytes':len(b)}
ownerpin=checked_input(OWNER/'classification.json','e72f6069898051c2a1d22160d476f99583d89c60c936bca66376b1f807e685a0')
manifestpin=checked_input(OWNER/'SHA256SUMS','60c93633dfd33c489dcbe0e070d653bd523ded0f929b5135642ef21c96c86453')
check(stat.S_IMODE(OWNER.stat().st_mode)==0o555,'owner directory mode')
manifest_entries=[]
for line in (OWNER/'SHA256SUMS').read_text().splitlines():
 h,name=line.split(None,1);name=name.lstrip('*');p=OWNER/name
 check(p.parent==OWNER,'manifest path');checked_input(p,h);check(stat.S_IMODE(p.stat().st_mode)==0o444,'owner file mode');manifest_entries.append(name)
check(all(stat.S_IMODE(p.stat().st_mode)==0o444 for p in OWNER.iterdir()),'owner all sealed')
d=readjson(OWNER/'classification.json')
a=readjson(d['allocation']['path']);checked_input(d['allocation']['path'],d['allocation']['sha256']);checked_input(d['allocation']['output_contract_path'],d['allocation']['output_contract_sha256'])
inputs={k:checked_input(v['path'],v['sha256']) for k,v in d['input_pins'].items()}
check(git('rev-parse',SRC+'^{tree}').decode().strip()==TREE,'source tree')
check(d['source_commit']==SRC and d['source_tree']==TREE and d['baseline_commit']==BASE,'owner source pins')
batch=next(b for b in a['batches'] if b['batch_id']=='CAP57')
allocated={r['root_id']:r for r in batch['roots']};roots={r['root_id']:r for r in d['roots']}
check(len(allocated)==len(roots)==len(d['roots'])==57,'57 unique roots');check(allocated.keys()==roots.keys(),'exact allocation')
excluded=[i for ids in a['excluded_original_root_ids'].values() for i in ids]
check(len(excluded)==len(set(excluded))==200,'200 exclusions');check(not set(roots)&set(excluded),'excluded overlap');check(not set(roots)&set(a['prior79_root_ids']),'prior79 overlap')
cache={};pins={}
def blob(commit,path):
 key=(commit,path)
 if key not in cache:
  b=git('show',commit+':'+path);entry=git('ls-tree',commit,'--',path).decode().strip();mode,typ,oid=entry.split('\t')[0].split();check(typ=='blob','blob type')
  cache[key]=b;pins[key]={'commit':commit,'path':path,'git_blob':oid,'git_mode':mode,'sha256':sha(b),'bytes':len(b)}
 return cache[key]
def pincheck(pin,commit,path):
 blob(commit,path);expected=pins[(commit,path)]
 for k in ('git_blob','git_mode','sha256','bytes'):check(pin[k]==expected[k],f'file pin {path} {k}')
 if 'commit' in pin:check(pin['commit']==commit,'commit pin '+path)
def span(commit,path,start,end):
 lines=blob(commit,path).split(b'\n');check(1<=start<=end<=len(lines),'span range '+path);return b'\n'.join(lines[start-1:end])
def citation(path,start,end):
 b=span(SRC,path,start,end);return {'path':path,'start_line':start,'end_line':end,'git_blob':pins[(SRC,path)]['git_blob'],'sha256':sha(b),'text':b.decode()}
for path,p in d['source_files'].items():
 pincheck(p,SRC,path);check(p['source_text'].encode()==blob(SRC,path),'full source text '+path)
check(len(d['source_files'])==51,'51 source files')
for bounded in batch['bounded_scope_reads']:
 pincheck(a['bounded_source_read_file_pins'][bounded['path']],SRC,bounded['path']);check(sha(span(SRC,bounded['path'],bounded['start_line'],bounded['end_line']))==bounded['span_sha256'],'allocation bounded span')
for ref,e in d['evidence'].items():
 b=span(SRC,e['path'],e['start_line'],e['end_line']);check(e['text'].encode()==b,'evidence span '+ref);check(e['sha256']==sha(b),'evidence sha '+ref);check(e['git_blob']==pins[(SRC,e['path'])]['git_blob'],'evidence blob '+ref)
check(len(d['evidence'])==343,'343 spans')
assertions=conditions=blocks=declarations=0
for rid,r in roots.items():
 ar=allocated[rid]
 for k,v in ar.items():check(r[k]==v,'allocated root field '+rid+' '+k)
 path=r['path'];check(rid==path+'::'+r['original_name'],'literal ID')
 for commit,field,pinfield,allockey in [(BASE,'baseline_declaration','baseline_test_file_pin','baseline'),(SRC,'source_declaration','current_test_file_pin','source')]:
  pincheck(r[pinfield],commit,path);pincheck(a['canonical_test_file_pins'][path][allockey],commit,path)
  s=r[field];b=span(commit,path,s['start_line'],s['end_line']);check(sha(b)==s['sha256'],'declaration '+rid);check(b.startswith(('func '+r['current_name']+'(').encode()),'declaration start '+rid);check(b.split(b'\n')[-1]==b'}','declaration closing brace '+rid);declarations+=1
 check(span(BASE,path,r['baseline_declaration']['start_line'],r['baseline_declaration']['end_line'])==span(SRC,path,r['source_declaration']['start_line'],r['source_declaration']['end_line']),'survival '+rid)
 s=r['survival_reconfirmed'];check(s['raw_bytes_equal'] and s['state']=='retained_body_exact' and s['baseline_raw_declaration_sha256']==r['original_declaration_sha256'] and s['current_raw_declaration_sha256']==r['current_declaration_sha256'],'survival metadata '+rid)
 check(r['runtime']==RUNTIME and r['retirement_authorized'] is False and r['qualification_transfer_from_7330'] is False and r['original_safety_obligations_retained'] is True,'qualification flags '+rid)
 check(r['assertion_context_is_complete_declaration'] and r['assertion_context_ref'] in d['evidence'],'assertion context '+rid)
 e=d['evidence'][r['assertion_context_ref']];check(e['path']==path and all(e[k]==r['source_declaration'][k] for k in ['start_line','end_line','sha256']),'full assertion context '+rid)
 for field in ['assertion_sites','condition_sites']:
  for site in r[field]:
   check(span(SRC,path,site['line'],site['line']).decode()==site['text'],'site text '+rid);check(r['source_declaration']['start_line']<=site['line']<=r['source_declaration']['end_line'],'site in declaration '+rid)
  if field=='assertion_sites':assertions+=len(r[field])
  else:conditions+=len(r[field])
 declared={s['line'] for s in r['assertion_sites']}
 raw_assertions={n for n in range(r['source_declaration']['start_line'],r['source_declaration']['end_line']+1) if re.search(rb'\bt\.(?:Fatalf?|Errorf?|FailNow|Fail)\(',span(SRC,path,n,n))}
 check(raw_assertions<=declared,'missing assertion sites '+rid+' '+str(raw_assertions-declared))
 for ref in r['setup_helper_refs']+r['connected_production_refs']:check(ref in d['evidence'],'unresolved evidence reference '+ref)
 for b in r['material_assertion_blocks']:
  check(span(SRC,b['path'],b['start_line'],b['end_line']).decode()==b['text'],'material block text '+rid);check(b['git_blob']==pins[(SRC,b['path'])]['git_blob'],'block blob '+rid);blocks+=1
check(len({r['path'] for r in roots.values()})==12,'12 test files')
check(collections.Counter(r['category'] for r in roots.values())==d['counts'],'owner counts')
external=d['external_dependency_pin'];blob(SRC,external['path']);check(external['git_blob']==pins[(SRC,external['path'])]['git_blob'],'SDK module blob')
for line in external['oci_sdk_declaration_lines']:check(span(SRC,external['path'],line['line'],line['line']).decode()==line['text'],'SDK version declaration')
check(not git('ls-tree','-r','--name-only',SRC,'--','*objectstorage_client.go').strip(),'external SDK absent qualification')
# Independent semantic dispositions, written after complete source reads; owner prose is retained only as input.
reasons={
'TestAggregate':'Literal numeric slices exercise average/max/p95 and empty-input arithmetic; no producer or transport feeds the assertion.',
'TestDecideConvergesWithoutFlapping':'Alternating and sustained synthetic readings advance a value clock and local History. The asserted change count and recommendation are local decisions.',
'TestDecideCoversWindowAtUnalignedInterval':'Virtual seventeen-second observations exercise local stabilization coverage and the returned replica count.',
'TestDecideCoversWindowShorterThanInterval':'Synthetic timestamp spacing checks coverage and rejects an over-age observation; no receiver clock or transport boundary is measured.',
'TestDecideDoesNotMutateHistoryAndPrunesOldRecommendations':'Copied recommendation values and returned history slices establish local immutability/pruning only.',
'TestDecideNeverSignalScalesToZero':'A zero synthetic signal must leave the local recommendation at one. No running service is scaled.',
'TestDecideTable':'Literal policies, readings, bounds, histories and timestamps exercise Decide reasons, cooldowns and returned changes.',
'TestPolicyValidate':'Direct policy mutations exercise local validity checks and error identity.',
'TestWindowStoreAggregatesInsideWindow':'Record/Read/Collect use map-backed synthetic samples; isolation and aggregation require no durable or network store.',
'TestWindowStoreDefaultRetentionCoversLongestWindow':'The assertion compares constructor retention with a policy duration; it does not wait for or observe external retention.',
'TestAlertingHysteresisOpensAtWarnAndClosesBelowClear':'Synthetic capacity ratios and prior alert state exercise local hysteresis without an incident request.',
'TestAllocateGrantsByPressureUntilTheCap':'Allocation ordering, cap arithmetic, reasons and output ordering derive from literal regional inputs; no grant admission/persistence occurs.',
'TestAllocateHoldsEveryRegionWhenSpendIsUnknown':'Missing/stale/future/currency-invalid synthetic spend exercises hold arithmetic and retention of known projection.',
'TestAllocateHoldsEveryRegionWithAnInvalidBudget':'A zero-cap local Budget must return a finite, valid hold value.',
'TestAllocateNeverGoesBelowNodes':'Synthetic demand below current Nodes checks the returned lower bound, without a removal effect.',
'TestAllocateNeverGrantsWithoutAPrice':'Zero local price makes Allocate hold the allowance; no pricing service is queried.',
'TestAllocateSaturatesTheProjection':'Maximum integer inputs exercise local saturation and the returned over-budget state.',
'TestAllocateStateThresholds':'Literal projection/cap ratios check local state thresholds.',
'TestAllocateWithoutBudgetHoldsEveryRegion':'A nil Budget exercises the local no-budget hold branch without document I/O.',
'TestAllowanceForChecksFreshnessAndCell':'Explicit timestamp/cell values exercise local selection and the inclusive freshness boundary.',
'TestCapacityEncodeDecodeRoundTripsAndRefusesBadAllowances':'Local JSON round-trip and mutated allowances exercise schema validation, without document transport.',
'TestCapacityValidateRequiresGrantTimeExactlyWhenGranted':'Direct grant timestamp mutations check a Capacity value invariant.',
'TestDecodeCapacityMarksInvalidDocuments':'Literal malformed or incomplete JSON is rejected by the local decoder.',
'TestNoReservationWhenSpendIsUnknownOrBudgetUnset':'Allocate clears recommendation grant timestamps for local unknown-spend/nil-budget inputs; this is not durable Reserve admission.',
'TestReservationExpiresAfterReservationTTL':'Explicit TTL boundary times reassign a recommendation slot locally; no durable commitment expires or launch occurs.',
'TestReservationHoldsTheSlotWhileStatusLags':'Prior Capacity preserves a recommendation slot/time during synthetic status lag and counts its projected cost locally.',
'TestReservationReleasedWhenNodesCatchUp':'A synthetic observed Nodes increase removes the recommendation reservation and counts cost once in returned values.',
'TestBudgetEncodeDecodeRoundTrip':'Budget structs and deterministic JSON bytes round-trip locally; ReadBudget/WriteBudget are not called.',
'TestBudgetValidateRefusesMalformedBudgets':'Direct field mutations fail local validation and encoding.',
'TestDecodeBudgetRefusesUnknownFieldsAndInvalidBudgets':'Literal unknown-field, schema, currency and garbage JSON exercise strict local decoding.',
'TestReservationLedgerSurvivesPeriodicWritesThroughHomeCAS':'The test-owned commitment append races sixteen actual home document writes; JetStream expected-sequence CAS and final reads materially support preservation of both commitments and metadata. It does not invoke production Reserve admission or prove financial completeness.',
'TestSignedSpendingAuthorityDeniesCanceledObservation':'Actual concrete SDK HTTP grant reads and real home JetStream document writes/readback support signed-authority and retained-hold assertions. Independent direct bootstrapLimit guards and ValidateBootstrapSpending(changed) at 280-282 exercise local targets on altered values. The already-canceled inventory produces incomplete evidence and does not establish successful cloud observation or spending.',
'TestStatusPageErrorsOmitTheToken':'A real HTTP 401 traverses StatusPage.post/HTTP.Do and its sanitized error branch; the token-absence assertion depends on that exchange.',
'TestStatusPageMissingTokenIsReported':'The injected token error returns from post before request construction or HTTP.Do. The loopback URL is incidental setup.',
'TestStatusPageOpenWarningPostsFixedWarning':'The actual HTTP handler observes method, path, bearer header and fixed JSON; the returned incident ID crosses the response boundary.',
'TestStatusPageRejectsBadIncidentIDs':'OpenWarning receives and rejects a bad ID through an actual HTTP response. A distinct ResolveWarning bad-input guard runs before post; the one-request count confirms that local branch.',
'TestStatusPageResolveWarningPostsResolvedUpdate':'The actual HTTP server checks the update path and resolved JSON emitted by production HTTP.Do.',
'TestIncompleteServiceCoverageMakesUsageIncomplete':'Synthetic covered replicas with disjoint service windows exercise local aggregate completeness.',
'TestMeasurementQueryExcludesBoundarySampleSpikes':'Synthetic out-of-window reports exercise local interval filtering and minimum-headroom calculation.',
'TestServiceCoverageRequiresAnOverlappingRange':'Direct replicaSeries literals check overlap edges and a returned aggregate mean.',
'TestConcurrentUsageSelectsBestPartialAndHonorsCancellation':'Concurrent real HTTP endpoints return partial answers or wait for cancellation. Selecting the best transported answer and preserving caller DeadlineExceeded materially traverse production HTTP.Do.',
'TestUsageQueriesHealthyThirdControllerWithinCallerDeadline':'Two actual handlers stall while a third waits for their start and then responds; completion and both server-side cancellation observations depend on concurrent real HTTP requests.',
'TestExpiredCapacitySeriesReleaseTheirSlots':'Synthetic expired samples fill and prune an in-memory series cap, allowing a new local series.',
'TestLaterTelemetryCannotAddRowsToAnEarlierWindow':'A synthetic report at the exclusive query end exercises immutable earlier rows/completeness through local history.',
'TestUsageAPIUsesRequestedInventoryWindow':'The production handler is invoked directly with ResponseRecorder and a synthetic inventory closure. Bounds, missing identity and 503 mapping cross no socket boundary.',
'TestMissingActiveServiceMeasurementsRemainUnknown':'Missing synthetic replicas/interior gaps keep usage/headroom unknown; formatting writes to bytes.Buffer only.',
'TestServiceStatisticsAlignUnequalCadencesAndSeparatePeakBounds':'Synthetic cadences and anti-aligned samples check local aligned statistics versus the sum of individual peak bounds.',
'TestServiceTotalsFollowReplicaLifetimes':'Literal lifetimes and reports exercise local replacement/start/gap/reactivation aggregation and bytes.Buffer formatting.',
'TestAllocatedRequestsSurviveMissingMeasurements':'Synthetic host/request maps preserve known allocations while leaving unmeasured usage unknown; no hostload subscription participates.',
'TestAuthenticatedAPIAndRegionalClient':'The real server/client exchange establishes unauthenticated 401, authenticated complete usage and mismatched-region refusal. Lines 161-167 re-encode that same transported result; local inspection of boundary output is not an independent local-only target. The token assertion covers the re-encoded typed Usage, not raw response bytes or discarded unknown JSON fields.',
'TestGapAndUnknownCannotClaimComplete':'Direct Point slices and an empty Row exercise local coverage/completeness predicates.',
'TestQueryClosesOwnedConnectionsAndPreservesCallerTransport':'Server ConnState observes real TCP creation/closure. Default owned transport must close its idle connection, while caller transport reuse is measured through two actual queries.',
'TestRecordRejectsSpoofedRegionAndThrottles':'Direct Origin/Report calls exercise local cell checks and receiver-time throttling; authenticated ingestion is absent.',
'TestRecoveredWindowDoesNotInheritEarlierOverflow':'A bounded in-memory history with injected dropped samples exercises window-scoped overflow accounting.',
'TestWindowTotalsAndMissingData':'Synthetic reports, identity lists, time bounds and bytes.Buffer output exercise local totals, missing rows and expiry.',
'TestTwentyRegionsScaleUnderOneBudget':'Unresolved: newRegion sets removed Scaler.Hosts, fakePool lacks required TargetSize, Control is omitted and Tick returns before decisions, and its cell-only Recipe fails current Validate before TargetSize. The post-Tick scale/budget assertions cannot establish a reachable current target. Intended memory-fake simulation is unit, without category credit.',
'TestRegionSuggestionsOverFortyDays':'Seeded synthetic statuses and forty virtual days exercise pure Suggest recommendations, home protection, minimum-region and idle timing rules. This root never calls newSim or Scaler.Tick. Per-root source classification is not package compilation qualification.'}
check(set(reasons)=={r['current_name'] for r in roots.values()},'57 independent rationales')
correction='internal/capacity/usage_test.go::TestAuthenticatedAPIAndRegionalClient'
peerroots=[]
for rid,r in roots.items():
 q={k:r[k] for k in ['root_id','path','original_name','current_name','kind','state','baseline_declaration','source_declaration','original_declaration_sha256','current_declaration_sha256','baseline_test_file_pin','current_test_file_pin','asserted_target','assertion_context_ref','assertion_context_is_complete_declaration','assertion_sites','condition_sites','setup_helper_refs','connected_production_refs','material_boundary','stubs_fakes_and_limits','current_target_reachability','survival_reconfirmed']}
 q.update({'owner_category':r['category'],'category':'integration' if rid==correction else r['category'],'verdict':'CORRECT_CATEGORY' if rid==correction else 'ACCEPT_SOURCE_DISPOSITION','independent_rationale':reasons[r['current_name']],'owner_rationale_for_comparison':r['rationale'],'runtime':RUNTIME,'retirement_authorized':False,'retirement_count':0,'original_safety_obligations_retained':True,'qualification_transfer_from_7330':False,'material_assertion_blocks':[]})
 for b in r['material_assertion_blocks']:
  pb=dict(b);pb['sha256']=sha(span(SRC,b['path'],b['start_line'],b['end_line']))
  if rid==correction and pb['start_line']==161:pb['category']='integration';pb['target']='Re-encoding and inspecting the actual transported typed Usage; no independent synthetic unit target'
  q['material_assertion_blocks'].append(pb)
 if rid==correction:
  q['asserted_target']='observability.Server.authenticate -> capacity.Handler -> capacity.Client.Query; inspection of the transported typed Usage'
  q['material_boundary']='Production authentication/handler/client across actual TCP HTTP; re-encoding checks that same boundary output'
  q['stubs_fakes_and_limits']=list(q['stubs_fakes_and_limits'])+['Token absence is asserted on re-encoded typed Usage only; raw wire and discarded unknown fields are not inspected.']
 peerroots.append(q)
counts=dict(sorted(collections.Counter(r['category'] for r in peerroots).items()));check(counts=={'integration':8,'mixed':2,'unit':46,'unresolved':1},'peer counts')
keyspans={
'authenticated_root':citation('internal/capacity/usage_test.go',137,171),
'client_query':citation('internal/capacity/cli.go',41,123),
'simulation_root':citation('internal/capacitysim/sim_test.go',37,57),
'simulation_step':citation('internal/capacitysim/sim_test.go',97,111),
'simulation_newRegion':citation('internal/capacitysim/sim_test.go',261,296),
'fakePool_complete_file':citation('internal/capacitysim/fakes_test.go',1,len(blob(SRC,'internal/capacitysim/fakes_test.go').splitlines())),
'Scaler_fields':citation('internal/nodescale/scaler.go',43,76),
'Scaler_Tick':citation('internal/nodescale/scaler.go',117,187),
'Scaler_decide':citation('internal/nodescale/scaler.go',674,775),
'Pool_interface':citation('internal/nodescale/pool.go',143,151),
'Recipe_validate':citation('internal/nodescale/pool.go',35,59),
'Capacity_validate':citation('internal/nodescale/capacity.go',47,59),
'signed_local_validator':citation('internal/budget/reservation_store_integration_test.go',266,282),
'status_mixed_blocks':citation('internal/budget/status_test.go',71,82)}
evidence={k:{**e,'text':span(SRC,e['path'],e['start_line'],e['end_line']).decode()} for k,e in d['evidence'].items()}
verification={'schema':'ts-source-peer-static-verification-v1','owner_report':ownerpin,'owner_manifest':manifestpin,'owner_manifest_entries_verified':manifest_entries,'owner_files_mode':'0444','owner_directory_mode':'0555','source_commit':SRC,'source_tree':TREE,'baseline_commit':BASE,'batch_id':'CAP57','allocated_roots':57,'literal_ids_exact':True,'declarations_rehashed':declarations,'complete_test_files':12,'source_file_pins_and_full_texts_verified':len(d['source_files']),'baseline_test_file_pins_verified':12,'unique_file_pin_versions_verified':len(pins),'allocation_bounded_spans_verified':len(batch['bounded_scope_reads']),'owner_evidence_spans_verified':len(evidence),'material_assertion_blocks_verified':blocks,'assertion_sites_verified':assertions,'condition_sites_verified':conditions,'all_direct_t_assertion_calls_covered':True,'flattened_exclusions':len(excluded),'excluded_overlap':[],'prior79_overlap':[],'owner_counts_verified':d['counts'],'peer_counts':counts,'category_corrections':1,'accepted_owner_dispositions':56,'unresolved_roots_preserved':1,'runtime':RUNTIME,'retirement_authorized':False,'retirement_count':0,'qualification_transfer_from_7330':False,'accounting_promotion_authorized':False,'project_source_git_ledger_mutation':False,'go_build_test_runtime_cloud_process_listener_lock_actions':False,'static_checker_is_not_runtime_evidence':True}
checked_input('/tmp/ts-mesh55-d4ac-source-classification-pfjjhj7x/classification.json','0bf0127bcc7915a633fe2ca78ab918703408eb69dd4c06dd554b86d3b72d3893')
checked_input('/tmp/ts-mesh55-d4ac-source-classification-pfjjhj7x/SHA256SUMS','f98d69253a6bcfedaf04cdb507567ff3322c5e8c7a6a6ed6a1adb7fe564d29b3')
report={'schema':'ts-cap57-independent-source-peer-v1','state':'INDEPENDENT_PEER_CORRECTION_REQUIRED_CANDIDATE_ONLY','reviewer':'/root/mesh/material','owner':'/root/cap/selection','coordinator':'/root/qa_integrator','batch_id':'CAP57','source_commit':SRC,'source_tree':TREE,'baseline_commit':BASE,'owner_report':ownerpin,'owner_manifest':manifestpin,'allocation':d['allocation'],'input_pins_independently_reconfirmed':inputs,'root_count':57,'test_file_count':12,'owner_counts':d['counts'],'counts':counts,'accepted_owner_dispositions':56,'corrected_owner_dispositions':1,'roots':peerroots,'classification_definitions':d['classification_definitions'],'evidence':evidence,'independent_key_spans':keyspans,'canonical_file_pins':sorted(pins.values(),key=lambda p:(p['commit'],p['path'])),'findings':[{'id':'CAP57-PEER-1','kind':'category_correction','root_id':correction,'from':'mixed','to':'integration','reason':reasons['TestAuthenticatedAPIAndRegionalClient'],'citations':['authenticated_root','client_query'],'owner_acknowledgment':'Owner /root/cap/selection agreed the proposed correction is consistent with the transported-result rubric; independent source rationale is decisive, not the acknowledgment.'},{'id':'CAP57-PEER-2','kind':'unresolved_preserved','root_id':'internal/capacitysim/sim_test.go::TestTwentyRegionsScaleUnderOneBudget','reason':reasons['TestTwentyRegionsScaleUnderOneBudget'],'blocker_chain':['newRegion sets Scaler.Hosts at 275; Scaler fields 43-76 have Control and no Hosts.','fakePool complete file defines no TargetSize; Pool requires TargetSize at 146.','newRegion omits Control; Tick returns unavailable at 135-136 before decisions/save.','newRegion Recipe contains only Cell at 274; decide validates at 735 before TargetSize at 741; required geometry and other recipe fields are missing.'],'citations':['simulation_root','simulation_step','simulation_newRegion','fakePool_complete_file','Scaler_fields','Scaler_Tick','Scaler_decide','Pool_interface','Recipe_validate','Capacity_validate']}],'qualification_limits':['Source categories describe actual assertion targets; no compilation or runtime result is inferred.','SDK module v65.126.0 is pinned in go.mod; external SDK implementation was not reviewed and no vendor implementation/runtime credit is granted.','The authenticated usage token assertion checks re-encoded typed Usage only, not raw wire bytes or unknown JSON fields discarded by the client decoder.','Signed spending combines genuine SDK HTTP and home JetStream boundaries with explicit independent local validators. Canceled inventory is incomplete; successful inventory, admission and full financial completeness are unproven.','Suggestions is a per-root local source path; the scale fixture blockers can still prevent package compilation.'],'runtime':RUNTIME,'retirement_authorized':False,'retirement_count':0,'original_safety_obligations_retained':True,'qualification_transfer_from_7330':False,'accounting_promotion_authorized':False,'accepted_accounting_unchanged':a['accepted_accounting'],'all_five_categories_remain_OPEN':True,'execution_and_mutation_limits':verification,'previous_MESH55_preserved':{'directory':'/tmp/ts-mesh55-d4ac-source-classification-pfjjhj7x','classification_sha256':'0bf0127bcc7915a633fe2ca78ab918703408eb69dd4c06dd554b86d3b72d3893','mutated':False}}
for name,value in [('review.json',report),('verification.json',verification)]: (OUT/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
(OUT/'README.md').write_text('Review `review.json`: CAP57 independent static peer review, exact d4ac source / bfca baseline.\n\n57 original roots: **8 integration, 46 unit, 2 mixed, 1 unresolved**. All 114 declaration hashes, 12 test files, 51 source file pins/full texts, 343 owner evidence spans, assertion/condition sites and material blocks independently match canonical immutable Git objects.\n\nOne correction: `TestAuthenticatedAPIAndRegionalClient` mixed → integration. Re-encoding the actual HTTP-derived typed result is an output check on the same boundary, not a separate local-only target. It does not prove absence of secrets in raw wire bytes or discarded unknown fields.\n\n`TestTwentyRegionsScaleUnderOneBudget` stays unresolved: removed Scaler.Hosts, missing Pool.TargetSize, absent Control (Tick rejects), and invalid cell-only Recipe. No source fix or execution occurred.\n\nThe two mixed roots retain independent direct local validators alongside real HTTP/JetStream assertions. All originals and safety obligations remain. Runtime: '+RUNTIME+'. Retirement 0; no accounting promotion or 7330 qualification transfer. MESH55 packet unchanged.\n\n`build_peer.py` is the static artifact builder/checker; it is not a runtime test or a semantic review of itself. `verification.json` records recomputed scope and pin checks. This directory is sealed files0444/dir0555 with SHA256SUMS.\n')
print(json.dumps(verification,indent=2))
