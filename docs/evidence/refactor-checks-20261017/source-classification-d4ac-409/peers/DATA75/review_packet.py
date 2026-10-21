import collections,hashlib,json,os,pathlib,re,stat,subprocess
D=pathlib.Path(__file__).parent; P=pathlib.Path('/tmp/ts-data75-d4ac-source-classification-y9dqe8af'); F=P/'classification.json'; H='5bd4d6d007d17894ee7f7957086841199e1075455fff49e36ba47399473fdf5f'; SH='4572d328b879440337ebd1e1e8ac0f208eb1a095b5f765a6508c0b6ae47e4c76'
C='d4ac68882716e7cfb14afca2f88ad596a38041af'; B='bfca60368f60d2da67f9016d1d489317ae8749c8'; T='3b73a410a025bd8050ad1d42e54acc7d5eda4b82'; G='/run/current-system/sw/bin/git'
sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(F.read_bytes())==H and sha((P/'SHA256SUMS').read_bytes())==SH
r=json.loads(F.read_bytes()); assert r['source_commit']==C and r['baseline_commit']==B and r['source_tree']==T
assert subprocess.check_output([G,'show','-s','--format=%T',C]).decode().strip()==T
ap=pathlib.Path('/tmp/ts-d4ac-next300-allocation-proposal-raxuc07l/allocation.json'); assert sha(ap.read_bytes())=='032cb201e692326da7274b12d7dfd15512b1befd325cce375188ae0447ca2523'
a=json.loads(ap.read_bytes()); batch=next(b for b in a['batches'] if b['batch_id']=='DATA75'); allocated={x['root_id']:x for x in batch['roots']}
assert len(allocated)==75 and {x['root_id'] for x in r['roots']}==set(allocated) and set(r['literal_root_ids'])==set(allocated)
assert len(r['roots'])==len({x['root_id'] for x in r['roots']})==75
# Independently verify sealed owner packet without executing its scripts.
listed={}
for line in (P/'SHA256SUMS').read_text().splitlines():
 h,name=line.split('  ',1); q=P/name; assert q.is_file() and sha(q.read_bytes())==h; listed[name]=h
allfiles={str(q.relative_to(P)) for q in P.rglob('*') if q.is_file() and q.name!='SHA256SUMS'}
assert set(listed)==allfiles
assert stat.S_IMODE(P.stat().st_mode)==0o555
assert all(stat.S_IMODE(q.stat().st_mode)==(0o555 if q.is_dir() else 0o444) for q in P.rglob('*'))
cache={}; pins={}
def read(p,c=C):
 k=c+':'+p
 if k not in cache:
  raw=subprocess.check_output([G,'show',k]); m=subprocess.check_output([G,'ls-tree',c,'--',p]).decode().split(); assert m[1]=='blob'
  cache[k]=raw; pins[k]={'commit':c,'path':p,'git_mode':m[0],'git_blob':m[2],'sha256':sha(raw),'bytes':len(raw)}
 return cache[k]
for p in r['source_pins']:
 raw=read(p['path'],p['commit']); actual=pins[p['commit']+':'+p['path']]
 for k in ['git_mode','git_blob','sha256','bytes']: assert p[k]==actual[k],(p,k)
 assert (P/p['packet_copy']).read_bytes()==raw
seen_citations={}
def verify_citation(x):
 p=x['path']; c=x['commit']; raw=read(p,c); lines=raw.splitlines(); s,e=x['start_line'],x['end_line']; assert 1<=s<=e<=len(lines)
 span=b'\n'.join(lines[s-1:e]); pin=pins[c+':'+p]
 assert x['git_blob']==pin['git_blob'] and x['git_mode']==pin['git_mode']
 assert sha(span)==x['span_sha256'] and len(span)==x['span_bytes'] and x['raw_span_excludes_following_LF'] is True
 if 'text' in x: assert x['text']==span.decode()
 key=(c,p,s,e,x['span_sha256']); seen_citations[key]=x
 return span
# Check every nested citation, including exact assertion/condition spans.
def walk(x):
 if isinstance(x,dict):
  if {'path','commit','start_line','end_line','git_blob','span_sha256','span_bytes'}<=x.keys(): verify_citation(x)
  for v in x.values(): walk(v)
 elif isinstance(x,list):
  for v in x:walk(v)
walk(r)
assert len(r['citation_catalog'])==149
# Functions read independently for the 18 resolvable body-local paths and shared blocker.
def cite(p,s,e,label):
 raw=read(p); span=b'\n'.join(raw.splitlines()[s-1:e]); return {'path':p,'function_or_declaration':label,'start_line':s,'end_line':e,'commit':C,'git_blob':pins[C+':'+p]['git_blob'],'git_mode':pins[C+':'+p]['git_mode'],'span_sha256':sha(span),'span_bytes':len(span),'source_text':span.decode()}
common=[cite('internal/delivery/service_test.go',208,227,'testService -> testServiceWithRuntime incomplete natscell configuration'),cite('internal/natscell/runtime.go',131,148,'Config complete struct with no Lab field'),cite('internal/natscell/runtime.go',349,351,'Start delegates to start'),cite('internal/natscell/runtime.go',363,367,'start calls cfg.validate before creating server'),cite('internal/natscell/runtime.go',585,660,'Config.validate required production credentials'),cite('internal/natscell/runtime.go',66,68,'TLSFiles.complete')]
prod={
 'retryMetadata':[cite('internal/delivery/artifact.go',245,295,'retryArtifactMetadataRead'),cite('internal/delivery/service.go',400,412,'retryableSubmitOperationReadError')],
 'retryOperation':[cite('internal/delivery/service.go',356,412,'retrySubmitOperationRead and error classification')],
 'diagnostic':[cite('internal/delivery/consumer.go',208,277,'stageDeliveryError / diagnostics.report / deliveryFailureClass')],
 'refusal':[cite('internal/delivery/consumer.go',369,376,'plannerRefusal')],
 'clone':[cite('internal/delivery/types.go',229,240,'Intent.Clone')],
 'message':[cite('internal/delivery/service.go',515,535,'operationValueFromMsg')],
 'strict':[cite('internal/delivery/types.go',217,226,'DecodeIntent'),cite('internal/protocol/json.go',33,66,'strict JSON decoding')],
 'cell':[cite('internal/delivery/service.go',157,163,'validCell'),cite('internal/protocol/subjects.go',22,50,'CanonicalRegion')],
 'counter':[cite('internal/delivery/consumer.go',330,358,'plannerRefusalCounter note/forget')],
 'shape':[cite('internal/delivery/shape_test.go',14,25,'synthetic shapedPlanner'),cite('internal/delivery/consumer.go',591,650,'plan/defaultPlanShape/planShape/validatePlan')],
 'protocol':[cite('internal/delivery/artifact.go',172,295,'artifactExistsForUpload -> authoritativeArtifactMetadata -> retryArtifactMetadataRead')],
 'storage':[cite('internal/delivery/service.go',482,484,'operationKey'),cite('internal/delivery/service.go',496,535,'getOperation -> operationValueFromMsg')],
}
U={
'TestRetryArtifactMetadataReadFailsClosedOnPersistentLeaderFailure':('retryMetadata','The callback increments calls and returns a constructed APIError; deadline/no-result assertions cover only context/timer and retry-loop state.'),
'TestRetryArtifactMetadataReadPreservesAbsenceAndPermanentErrors':('retryMetadata','Each table branch returns synthetic missing/error values from a closure; the single-call assertion proves local retry policy, not a broker read.'),
'TestRetryArtifactMetadataReadRecoversFromTransientLeaderFailure':('retryMetadata','The exact RawStreamMsg pointer is constructed locally and returned by the second closure call; pointer identity and two attempts require no I/O.'),
'TestRetryArtifactMetadataReadStopsOnCallerCancellation':('retryMetadata','The closure cancels its local context and returns a constructed API error; cancellation/count assertions exercise the local retry loop.'),
'TestDeliveryFailureClassUsesSafeKnownCategories':('diagnostic','All errors are constructed values/strings; stage wrapper and fixed class/code comparison are local.'),
'TestDeliveryRetryDiagnosticIsRateLimitedAndOmitsRawError':('diagnostic','slog writes into bytes.Buffer; forced next timestamp, counts and sanitized fields are in-process logging assertions.'),
'TestPlannerRefusalExemptsRetryableHostSnapshotClasses':('refusal','Synthetic error strings/sentinels feed local class-to-refusal policy; no host snapshot or placement request occurs.'),
'TestContainerIntentCloneRetainsIndex':('clone','Cloned Sequence/Index backing slices are mutated and compared with original in-memory bytes.'),
'TestOperationLeaderReadRejectsInvalidMessage':('message','Constructed nil/wrong-subject/zero-sequence/empty-data/marker RawStreamMsg values enter a pure message validator.'),
'TestStrictIntentRejectsDuplicateAndUnknownFields':('strict','Three byte literals go through strict JSON decoding; duplicate/unknown/trailing JSON errors precede any I/O.'),
'TestSubmitOperationReadPreservesPermanentErrorsAndCancellation':('retryOperation','Closures return permission/disabled/missing errors or cancel a local context; no connection is supplied and every assertion is closure-count/error propagation.'),
'TestSubmitOperationReadRetriesTransientLeaderFailure':('retryOperation','Constructed transient error then constructed operationValue pointer yield exactly two local calls.'),
'TestSubmitOperationReadUsesRecoveryBudgetAfterFiveTransientFailures':('retryOperation','The callback returns a synthetic transient error five times then a local operationValue; the sixth-call assertion establishes a retry budget, not broker failover.'),
'TestDeliveryCellsFollowProtocolRegionTokens':('cell','String regex/token processing accepts gru/us-east-1 and rejects global/malformed hyphens without discovery or membership I/O.'),
'TestPlannerRefusalCounterEvictsOnlyTheOldest':('counter','Map/order-slice bookkeeping with local mutex evicts oldest, preserves another count and resets forgotten key.'),
'TestValidatePlanHonoursRecordedShape':('shape','Service holds only a synthetic ShapedPlanner. Local desired slices and recorded/default plan shape are checked against generation/replica constraints.'),
}
I={
'TestArtifactMetadataReadCancelsBlockedBrokerRequest':('protocol','The root independently constructs raw server.NewServer and a real nats.Conn, subscribes to the exact MSG.GET API subject, flushes it, and calls artifactExistsForUpload. Production reaches Conn.JetStream/GetLastMsg with caller context; the silent subscriber records a real request, while prompt deadline/no-object assertions prove protocol dispatch/cancellation. No JetStream storage or leader recovery is exercised.'),
'TestOperationLeaderReadWithDirectGetDenied':('storage','An admin connection creates real JetStream KV state and Put revision. A second restricted connection is denied direct KV.Get but production getOperation uses standard MSG.GET; exact committed bytes/revision, missing key and Delete tombstone are checked over that actual server. One server only; no replication or failover.'),
}
roots=[]; gate_counts=collections.Counter(); declaration_checks=0
for x in r['roots']:
 original=allocated[x['root_id']]; p=x['path']; n=x['current_name']; sd=x['source_declaration']; bd=x['baseline_declaration']
 for k in ['path','original_name','current_name','original_declaration_sha256','current_declaration_sha256','state','source_declaration','baseline_declaration']: assert x[k]==original[k],(n,k)
 current=verify_citation(x['current_source']); baseline=verify_citation(x['baseline_source']); declaration_checks+=2
 assert sha(current)==x['current_declaration_sha256']==sd['sha256'] and sha(baseline)==x['original_declaration_sha256']==bd['sha256']
 assert current.startswith(b'func '+n.encode()+b'(') and current.endswith(b'\n}')
 assert (P/x['raw_current_declaration_packet_file']).read_bytes()==current
 assert x['runtime']=='UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION' and x['retirement_authorized'] is False and x['safety_obligations_retained'] is True
 lines=read(p).decode().splitlines(); source=[{'line':j,'text':lines[j-1]} for j in range(sd['start_line'],sd['end_line']+1)]
 gates=[{'line':j,'text':lines[j-1]} for j in range(sd['start_line'],sd['end_line']+1) if re.search(r'\b(?:testService(?:WithRuntime)?|natscell.Start)\(',lines[j-1])]
 category=x['category']
 if category=='unresolved':
  assert gates
  if n=='TestContainerIntentSignedBrokerRecovery':
   assert x['source_blocker']=='DATA75-B2' and any('Lab: true' in g['text'] for g in gates); blocker='DATA75-B2'; evidence=common+[cite(p,27,33,'direct incomplete natscell startup')]
  else:
   assert x['source_blocker']=='DATA75-B1' and all('testService' in g['text'] for g in gates); blocker='DATA75-B1'; evidence=common
  gate_counts[blocker]+=1
  rationale=f"Independent setup trace confirms {blocker}: the entry call(s) below enter a Config literal with unsupported Lab:true and missing required TLS/JWT. Config.validate would reject missing client material before server creation even if the obsolete field were removed. The body target therefore receives no integration/unit/mixed credit. All original assertions remain obligations."
  family=None
 else:
  assert not gates and x['source_blocker'] is None
  family,rationale=(U if category=='unit' else I)[n]; assert category in {'unit','integration'}
  evidence=prod[family]
  if family=='refusal': evidence=prod['diagnostic']+evidence
 roots.append({'root_id':x['root_id'],'path':p,'original_name':x['original_name'],'current_name':n,'owner_category':category,'peer_category':category,'peer_disposition':'ACCEPT_SOURCE_CATEGORY_ONLY' if category!='unresolved' else 'ACCEPT_UNRESOLVED_BLOCKER_RETAIN_OBLIGATION','independent_rationale':rationale,'baseline_declaration':x['baseline_source'],'current_declaration':x['current_source'],'survival_state':x['survival_state'],'setup_entry_citations':gates,'reviewed_assertion_source':source,'independent_boundary_or_blocker_citations':evidence,'owner_assertion_block_pins_verified':len(x['core_assertion_blocks']),'runtime':'UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION','retirement_authorized':False,'safety_obligations_retained':True,'package_build_status':'VISIBLE_STATIC_UNSUPPORTED_CONFIG_FIELD; no compiler executed. Body-local labels are source distinctions only.'})
assert declaration_checks==150 and gate_counts=={'DATA75-B1':56,'DATA75-B2':1}
counts=dict(collections.Counter(x['peer_category'] for x in roots)); assert counts=={'unresolved':57,'integration':2,'unit':16}
# Clarify exact dependency provenance without extending runtime claims.
gomod=read('go.mod'); assert b'replace github.com/nats-io/nats-server/v2 => ./third_party/nats-server' in gomod
serverpart=cite('third_party/nats-server/server/server.go',709,762,'NewServer initial option validation and optional TLS fields (bounded source excerpt)')
report={'schema':'data75-independent-source-peer-v1','state':'PEER_SOURCE_REVIEW_COMPLETE_CANDIDATE_ONLY_NO_LEDGER_PROMOTION','reviewer':'/root/core/readiness','dispatched_by':'/root/qa_integrator','batch_id':'DATA75','source_commit':C,'source_tree':T,'baseline_commit':B,'owner_packet':{'path':str(F),'sha256':H,'sha256sums_path':str(P/'SHA256SUMS'),'sha256sums_sha256':SH,'checksum_files_verified':len(listed),'modes_verified':'all files0444, directories0555'},'allocation':{'path':str(ap),'sha256':sha(ap.read_bytes()),'roots':75,'test_files':len({x['path'] for x in roots}),'exact_literal_id_set_verified':True},'peer_counts':{**{k:counts.get(k,0) for k in ['integration','unit','mixed','unresolved']},'allocated':75,'accepted_source_dispositions':75,'category_corrections':0,'runtime_qualified':0,'retirement_delta':0,'ledger_promotion_delta':0},'integrity':{'baseline_and_current_declarations_verified':150,'owner_source_file_pins_verified':len(r['source_pins']),'owner_citation_catalog_pins_verified':149,'unique_nested_owner_citation_spans_verified':len(seen_citations),'raw_current_declaration_packet_copies_verified':75,'all_owner_checksums_and_modes_verified':True,'shared_blocker_roots':56,'direct_blocker_roots':1},'findings':[{'severity':'retained_blocker','finding':'57 roots enter unsupported Lab:true plus missing required TLS/JWT setup; no imagined repaired fixture or incidental setup receives category credit.','category_change':False},{'severity':'qualification_limit','finding':'Whole-package static type mismatch applies to all tests. The 18 body-local labels describe independent assertion paths only and are not compilation/runtime acceptance.','category_change':False},{'severity':'documentation_clarification','finding':'Owner says dependency internals are not vendored/reviewed here. Canonical go.mod replaces NATS server with checked-in third_party/nats-server; peer pins that provenance and a bounded NewServer excerpt. This wording clarification changes no source category.','citation':serverpart,'category_change':False},{'severity':'boundary_limit','finding':'Protocol-cancellation root uses a silent synthetic API subscriber over actual NATS; it does not exercise JetStream storage. Leader-read root uses a single real JetStream server with admin Put/Delete and restricted reader; it does not exercise replication/failover.','category_change':False}], 'definitions':{'integration':'Core assertion materially crosses actual server/client/storage or protocol boundary, despite synthetic payloads.','unit':'Local callbacks, decoding, values, timers, logging buffer, maps/slices or synchronization with no genuine I/O target.','mixed':'Separate local-only and actual-boundary assertion blocks combined.','unresolved':'Blocked supplied setup prevents source category credit; obligations retained.'},'qualification_limits':['Every runtime result UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION; no Go/compiler/build/test/lint/benchmark/runtime execution.','Read-only immutable Git source and sealed owner evidence; only this fresh peer /tmp directory is written. No source/Git/cloud/listener/lock or ledger mutation.','No7330 qualification transfer; retirement0; all75 safety obligations retained. Source peer acceptance is separate from accepted-ledger promotion.','Accepted accounting remains19 retired/4300 retained/171 classified(100integration43unit28mixed)/4129unadjudicated, including the prior ten unresolved.','For 57 blocked roots, the peer verified each literal root setup entry and shared/direct blocker. No downstream body boundary was credited, and intended-path annotations remain noncredit obligations.','For18 resolvable body-local roots, the peer read complete assertion bodies and connected actual helper/production target functions; synthetic errors/RawStreamMsg/operationValue do not imply a broker exchange.'],'roots':roots,'source_file_pins':list(pins.values()),'owner_citation_catalog_pin_validation':{k:{'path':v['path'],'start_line':v['start_line'],'end_line':v['end_line'],'span_sha256':v['span_sha256'],'verified':True} for k,v in r['citation_catalog'].items()}}
(D/'peer-review.json').write_text(json.dumps(report,indent=2)+'\n')
(D/'README.md').write_text('''# DATA75 independent source peer review\n\nAll 75 per-root source dispositions accepted: 2 integration, 16 unit, 0 mixed, 57 unresolved. No category corrections. Counts remain candidates; no accepted ledger is changed.\n\nThe 57 unresolved roots independently enter unsupported `Lab: true` / incomplete TLS/JWT setup (56 through shared helpers; one direct). The entire package has a visible static field mismatch; the 18 body-local labels are source distinctions, not compilation or runtime success.\n\nIntegration scope: actual NATS dispatch/cancellation to a silent synthetic API subscriber, and actual single-server JetStream Put/Delete plus restricted-reader MSG.GET. No failover, replication, live OCI, production credentials or real host/application effect qualification. The16unit roots use only local callbacks/values/decoding/log buffer/map/slice state.\n\nValidated exact75IDs,150baseline/current declaration hashes,43owner source file pins,149catalog citations, all nested citation spans, raw declarations, sealed packet checksums and file/directory modes. Full numbered root assertions and independent target/blocker citations are in peer-review.json.\n\nDocumentation clarification only: canonical go.mod uses checked-in third_party/nats-server; dependency provenance is pinned independently.\n\nRuntime UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION. Retirement0, no7330transfer, all safety obligations retained. Independent source peer review does not promote a ledger. CORE65 remains immutable.\n''')
(D/'integrity-check.json').write_text(json.dumps({'status':'PASS_STATIC_SOURCE_PACKET_VALIDATION_ONLY','counts':report['peer_counts'],'integrity':report['integrity'],'peer_review_sha256':sha((D/'peer-review.json').read_bytes())},indent=2)+'\n')
print(json.dumps({'peer_directory':str(D),'counts':report['peer_counts'],'integrity':report['integrity'],'sha256':sha((D/'peer-review.json').read_bytes())}))
