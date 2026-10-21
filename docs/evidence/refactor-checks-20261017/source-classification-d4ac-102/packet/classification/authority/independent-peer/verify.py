import collections,csv,datetime,hashlib,json,os,pathlib,re,subprocess
G='/run/current-system/sw/bin/git'
REPO='/home/mariogk/Projects/TerraScale/ts-orchestrator'
HEAD='d4ac68882716e7cfb14afca2f88ad596a38041af'
TREE='3b73a410a025bd8050ad1d42e54acc7d5eda4b82'
BASE='bfca60368f60d2da67f9016d1d489317ae8749c8'
PACKET='/tmp/ts-authority-d4ac-classification-corrected-8e5nz_tg/review.json'
PACKET_SHA='084e17bc2f2575099b16f730cd5100b277d5693f330a6aa7406154c2da38e2c0'
OLD='/tmp/ts-authority-d4ac-classification-final-s_oehxoq/review.json'
OLD_SHA='0435e6b460cfe0c6bd5db39f9e018fc70ce9a22c1db03185ab816dd7f336ee3b'
INV='/tmp/ts-firstparty-vendor-d4ac-accepted-9h6_8guy/firstparty-survival.tsv'
INV_SHA='5fdf8adda8903b852d89a3d790dae9bbd46d3233349792988b15ac9806d93e73'
OUT=pathlib.Path(__file__).parent
sha=lambda b:hashlib.sha256(b).hexdigest()
def read_pin(p,h):
 b=pathlib.Path(p).read_bytes();assert sha(b)==h,(p,sha(b));return b
packet=json.loads(read_pin(PACKET,PACKET_SHA));old=json.loads(read_pin(OLD,OLD_SHA));invbytes=read_pin(INV,INV_SHA)
assert packet['canonical_head']==HEAD and packet['canonical_tree']==TREE
cache={}
def git(*args):
 return subprocess.check_output([G,'-C',REPO,*args],env={**os.environ,'GIT_OPTIONAL_LOCKS':'0'})
def source(rev,p):
 if (rev,p) not in cache:cache[rev,p]=git('show',rev+':'+p)
 return cache[rev,p]
assert git('rev-parse',HEAD+'^{tree}').decode().strip()==TREE
entries={}
for line in git('ls-tree','-r',HEAD).splitlines():
 meta,path=line.split(b'\t',1);mode,kind,blob=meta.decode().split();entries[path.decode()]={'mode':mode,'kind':kind,'blob':blob}
rows=[r for r in csv.DictReader(invbytes.decode().splitlines(),delimiter='\t') if r['kind']=='test' and r['path'].startswith('internal/authority/')]
rowmap={(r['path'],r['original_name']):r for r in rows}
assert len(rows)==len(rowmap)==len(packet['tests'])==93
keys=[(t['test']['path'],t['original_name']) for t in packet['tests']]
assert len(set(keys))==93 and set(keys)==set(rowmap)
def decl(data,name):
 m=re.search(rb'^func '+re.escape(name.encode())+rb'\(',data,re.M);assert m,name
 n=re.search(rb'^}',data[m.end():],re.M);assert n,name
 return data[m.start():m.end()+n.end()]
files={}
for p,v in packet['source_proof']['files'].items():
 b=source(HEAD,p);entry=entries[p]
 assert sha(b)==v['sha256'] and len(b)==v['bytes']
 assert entry['blob']==v['git_blob'] and entry['mode']==v['git_mode']
 files[p]={**v,'pin_validation':'PASS'}
assert len(files)==35
citations={};assertions=0
for t in packet['tests']:
 p=t['test']['path'];r=rowmap[p,t['original_name']]
 assert t['current_name']==r['current_name']==t['original_name']
 assert t['survival_state']==r['state']=='retained_body_exact'
 b=decl(source(BASE,p),t['original_name']);c=decl(source(HEAD,p),t['current_name'])
 assert b==c
 assert sha(b)==r['original_declaration_sha256']==r['current_declaration_sha256']==t['original_declaration_sha256']==t['current_declaration_sha256']
 for cite in [t['test']]+t['boundary_setup_citations']+t['connected_producer_citations']:
  key=(cite['path'],cite['function'],cite['line'],cite['end_line']);citations[key]=cite
 for a in t['assertion_evidence']:
  assert source(HEAD,p).decode().splitlines()[a['line']-1].strip()==a['assertion'].strip()
  assertions+=1
 assert t['runtime_qualification']=='UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION' and t['retirement_authorized'] is False
for (p,name,a,z),cite in citations.items():
 ls=source(HEAD,p).decode().splitlines()
 assert re.match(r'^func (?:\([^)]*\) )?'+re.escape(name)+r'\(',ls[a-1]),(p,name,a)
 assert ls[z-1]=='}' and all(l!='}' for l in ls[a:z-1]),(p,name,a,z)
 assert cite['git_blob']==files[p]['git_blob']
changed=[(a,b) for a,b in zip(old['tests'],packet['tests']) if a!=b]
assert len(changed)==1
before,after=changed[0]
assert after['original_name']=='TestHostHistoryExpiresAndReseedsWithoutLifetimeReplay'
assert before['classification']=='mixed' and after['classification']=='unit'
assert {k for k in before if before[k]!=after[k]}=={'classification','rationale','connected_producer_citations'}
assert old['source_proof']==packet['source_proof'] and old['accepted_scan']==packet['accepted_scan']
assert set(packet)-set(old)=={'supersedes'}
assert {k for k in old if old[k]!=packet[k]}=={'reviewed_at','counts','arithmetic','per_file_counts','tests'}
classes=collections.Counter(t['classification'] for t in packet['tests'])
assert dict(classes)=={'unit':20,'integration':72,'mixed':1}
for k,n in classes.items():assert packet['counts'][k]==n
assert packet['counts']['unresolved']==0
perfile={}
for t in packet['tests']:perfile.setdefault(t['test']['path'],collections.Counter())[t['classification']]+=1
assert {p:dict(v) for p,v in perfile.items()}==packet['per_file_counts']
unit_notes={
'TestBackupAttemptNeedsRosterWideAbortBeforeReuseOfOrdinal':'Only locally constructed BackupOperationRecord transitions are evaluated; no storage read or publish in the asserted target.',
'TestBackupHeldRequiresEveryCutAndAbortCannotClearNewerHold':'Local transition and immutable Cut byte checks; no broker boundary.',
'TestBackupCompleteRequiresCommittedProofsAndEveryAcknowledgment':'Local transition/proof-shape matrix with placeholder envelopes; no authenticated protocol or durable record exchange.',
'TestBackupRosterRequiresOneHostRelayPerMember':'Local roster validation rejects repeated relay identity.',
'TestOpenControlStreamWaitsForPostCreateMetadataVisibility':'Startup convergence is supplied by CreateStream/Info stubs; call counts do not observe live convergence.',
'TestCreatedControlStreamMissingInfoRetryIsBoundedAndCancelable':'Stub Info plus timers/context cancellation; no live server exchange.',
'TestOpenControlStreamDoesNotRetryPermanentOrExistingMissingInfo':'Stub API errors and retry counters only.',
'TestDeploymentIDIsRequiredAndCanonical':'Local configuration, decoder and Snapshot checks only.',
'TestVersionOneLeasePermanentlyFencesLegacyDecoder':'Locally marshalled bytes and strict decoders only.',
'TestHostHistoryExpiresAndReseedsWithoutLifetimeReplay':'Empty State.Subjects skips Seed broker loop; Window rejects before advance; next=1/watermark=0 skips Advance GetMsg loop. Only injected cache folding and local guards are asserted.',
'TestHostHistoryLockHonorsRequestDeadline':'Local channel gate/context deadline only.',
'TestIdentityResetRejectsInvalidTombstonePredecessorPins':'Assertions call local Validate with crafted pins; real fixture data is incidental setup.',
'TestIdentityResetRequiresV1AndMonotonicFloor':'Asserted SignIdentityReset/Validate paths use local identity/floor/version/record checks; fixture broker is incidental.',
'TestPendingEnrollmentEffectsSurviveLargeSettledHistory':'settledHistoryStream fabricates matching-subject Info and records; the 4098-entry enumeration is synthetic, even though initial Start uses real storage.',
'TestVerifyControlStreamConfigRejectsMessageEviction':'Struct mutation and local policy validation only.',
'TestVerifyControlStreamConfigAcceptsDurableControlStream':'Local expected-config validation; no broker policy durability observed.',
'TestAuthorityDiagnosticsAreSafeAndRateLimited':'In-process channel/atomic/log-buffer diagnostic behavior; APIError is constructed data.',
'TestClockHealthFencesGuardAndDurableMutations':'False ClockCheck exits asserted methods before their durable I/O; successful real Start is incidental and no broker readback is asserted.',
'TestStartupReconcileBoundsStreamInfoWithLongParent':'deadlineInfoStream is a local context-waiting stub.',
'TestStartupLeasePublishBoundsUnknownOutcomeWithLongParent':'deadlinePublish/failedOutcomeProbeStream simulate publication/probe failure without committed server state.'}
assert len(unit_notes)==20
file_notes={
'backup_operation_test.go':'CommitBackupOperationVerified reads durable backup/placement/update/terminal state and reaches real global/subject CAS; history assertions use actual bounded GetMsg/GetLastMsgForSubject reads. Local roster callbacks do not establish external roster truth.',
'deployment_test.go':'Published lease bytes flow through real Start/Guard/reconcile/Observe or successor acquisition; stored identity, stream sequence and epoch are asserted.',
'foreign_lease_test.go':'VerifyLeaseHolder reads real stream Info and last lease while two runtimes and released state exercise identity/term fencing.',
'function_integration_test.go':'Signed current intent and grants reach commitMutationVerified, durable floor reads and server CAS. Delayed read delegates to actual stream before waiting; race hook really publishes newer intent.',
'host_history_test.go':'Populated broker history exercises Seed last-subject reads and advance GetMsg; delegating counters bound actual storage reads. Empty-stream expiry root is separately unit.',
'identity_host_records_integration_test.go':'File-backed embedded control/KV history is passed through verified handoff and real public readers. Host stopped/format/volume facts remain constructed values.',
'identity_host_records_test.go':'Genuine root hold/committed-barrier verification and control/KV heads are read, replaced and completed. Fault hooks operate around acknowledged server writes; R3 case creates routed servers and stops a leader. Invalid head rejection follows an actual committed-barrier read.',
'identity_inventory_test.go':'Actual control/KV inventory and policy changes feed predecessor/hold/completion checks; sequence and untouched foreign-record readbacks establish durable scope.',
'identity_records_test.go':'ResetIdentityLease/ReplaceIdentityRecords/CompleteIdentityReset traverse real stream policy, barrier, leader-backed KV reads, per-subject publish CAS and immutable readback. Lost-response/delayed-writer hooks preserve genuine committed or competing state.',
'identity_records_tombstone_test.go':'Positive DEL/PURGE predecessor operation, revision and new-operation pins are observed in real server records; interruption/resume and final readback are genuine.',
'identity_reset_global_test.go':'Regional/global holds and completions use actual native atomic publish with global/subject predecessor CAS; races and preserved history are read from broker.',
'identity_reset_recovery_test.go':'Out-of-window holds carry actual broker timestamps; recovery observes immutable commitments and publishes fresh root authorization before real replacement/completion.',
'identity_reset_test.go':'Real opaque lease/barrier/log policy and sequence observations support signed reset, permanent-fence and changed-predecessor rejection assertions; local pre-I/O cases are scoped additional assertions.',
'log_test.go':'Real terminal/enrollment/placement/managed-update records reach reads and mutation CAS, including concurrent append conflicts. Local nested gates/proof callbacks alone do not prove external execution or grant truth.',
'netbird_state_test.go':'CommitNetBirdState uses genuine control-stream CAS and separate reader readback. Handoff hook really commits successor state; expiry wrapper delegates first to real read. No NetBird vendor protocol is exercised.',
'retirement_test.go':'Actual control-log writes and readbacks assert broker timestamps, subject revision and authority epoch fencing.',
'runtime_effect_integration_test.go':'Routed three-node R3 control journal, real epoch handoff/CAS and loopback HTTP proof exchange are boundaries. Stopped/running facts remain fixture booleans; no VM or native workload execution is established.',
'runtime_test.go':'Startup uses real stream create/lookup/config/lease read paths; ambiguous publish delegates and then loses acknowledgment, while permanent/canceled publish failures are injected. Existing unsafe stream rejection includes real Info absence-of-publish readback.'}
notes={
'TestStartDoesNotRetryPermanentOrCanceledLeasePublish':'Start genuinely opens/inspects the stream and reads its lease before reaching injected publish failure; this tests the production startup/retry path across a live broker, not actual server ACL rejection. Synthetic publication failure is explicitly scoped.',
'TestNestedWorkloadEffectUnderAnotherEpochIsFenced':'The successful same-epoch nested BeginActiveWorkloadEffect calls Guard at log.go:525, making durable lease observation part of asserted target; other-epoch nested rejection is local.',
'TestIdentityHostRecordsRejectMissingPlanActionAndUnknownDestinations':'Material local Validate/target tables coexist with real committed-barrier reads before invalid-head replacement rejection. One mixed root preserves both obligations; it cannot receive uniform integration credit.',
'TestIdentityHostRecordsRejectInvalidCurrentHeadBeforeAnyEffects':'ReplaceIdentityRecords calls verifyCommittedIdentityReset at identity_records.go:146 before checking constructed invalid head bytes. Asserted rejection follows actual committed-barrier observation; injected publisher forbids subsequent effects.'}
roots=[]
for t in packet['tests']:
 name=t['original_name'];cl=t['classification'];base=pathlib.Path(t['test']['path']).name
 note=unit_notes[name] if cl=='unit' else notes.get(name,file_notes[base])
 roots.append({'original_name':name,'current_name':t['current_name'],'path':t['test']['path'],'classification_submitted':cl,'classification_independently_accepted':cl,'independent_boundary_assessment':note,'submitted_rationale_agreed':True,'test':t['test'],'original_declaration_sha256':t['original_declaration_sha256'],'current_declaration_sha256':t['current_declaration_sha256'],'baseline_and_current_bytes_independently_equal':True,'survival_state':'retained_body_exact','boundary_setup_citations':t['boundary_setup_citations'],'connected_producer_citations':t['connected_producer_citations'],'assertion_lines_independently_validated':len(t['assertion_evidence']),'runtime_qualification':'UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION','retirement_authorized':False,'safety_obligations_preserved':True})
report={
'reviewer':'/root/qa_integrator/test_inventory','reviewed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'decision':'ACCEPT_CORRECTED_SOURCE_CLASSIFICATION_ONLY','scope':'Independent source peer review of all93 original internal/authority test roots; no runtime execution, retirement or ledger mutation.',
'canonical_head':HEAD,'canonical_tree':TREE,'baseline_head':BASE,
'reviewed_packet':{'path':PACKET,'sha256':PACKET_SHA},'superseded_packet':{'path':OLD,'sha256':OLD_SHA,'decision':'CORRECTION_REQUIRED_AS_ORIGINALLY_SUBMITTED'},
'accepted_inventory':{'path':INV,'sha256':INV_SHA,'selected_kind':'test','selected_package':'internal/authority','rows':93},
'classification_definitions_accepted':packet['classification_definitions'],
'counts':{'original_roots':93,'integration':72,'unit':20,'mixed':1,'unresolved':0,'retained_body_exact':93,'runtime_unknown':93,'runtime_pass_claims':0,'retirements_authorized':0,'ledger_changes':0},
'arithmetic':'72 + 20 + 1 + 0 = 93; all93 original declarations retained exactly; source classification is distinct from runtime qualification.',
'per_file_counts':{p:dict(v) for p,v in perfile.items()},
'independent_mechanical_verification':{'canonical_tree':'PASS','packet_and_inventory_sha256':'PASS','inventory_exhaustiveness_no_missing_extra_or_duplicate_roots':'PASS','baseline_current_declaration_byte_equality':93,'baseline_current_packet_inventory_hash_equality':93,'distinct_test_files':19,'canonical_file_blob_mode_sha256_size_pins':35,'distinct_exact_function_citation_spans':len(citations),'exact_assertion_line_citations':assertions,'packet_supersession_only_expected_root_and_derived_metadata_changed':'PASS','declaration_hash_convention':'Raw bytes from func start through column-zero closing brace, excluding following LF; independently extracted from both immutable Git commits.','citation_deduplication':'Tuple(path,function,line,end_line); count184 is distinct spans, not total repeated references.'},
'canonical_files_independently_pinned':files,
'finding_resolved':{'root':'TestHostHistoryExpiresAndReseedsWithoutLifetimeReplay','test_path':'internal/authority/host_history_test.go','test_span':[87,119],'original_classification':'mixed','accepted_classification':'unit','cause':'Empty subject inventory and zero watermark mean no asserted Seed/Window/Advance broker read occurs; broker setup is incidental.','evidence':[{'path':'internal/authority/host_history_test.go','lines':[88,99,103,107,110,113,116]},{'path':'internal/authority/host_history.go','function':'Seed','span':[45,83]},{'path':'internal/authority/host_history.go','function':'Window','span':[86,120]},{'path':'internal/authority/host_history.go','function':'advance','span':[134,181]}],'author_concurrence':'storage_compare independently reread the same paths, agreed, and sealed corrected successor; prior artifact unchanged.','correction_is_packet_only':True,'source_or_test_rewrite_required':False},
'source_review_method':['Read immutable canonical Git blobs, all93 test bodies and connected/shared setup and assertion helpers; trace asserted target paths rather than crediting incidental broker construction.','Distinguish real embedded broker/client/storage/HTTP exchanges from synthetic feeds, pre-I/O validation and injected external facts. Follow delegated failure hooks to acknowledged writes/readback or real competing CAS.','Independently verify corrected packet pins, all93 baseline/current declaration bytes, citation starts/closing braces and assertion lines; compare predecessor/successor packets for bounded correction.'],
'limits':['All93 runtime qualifications remain UNKNOWN. No Go, formatter, build, test, lint, benchmark, runtime or receipt qualification was performed.','Embedded NATS/R3 and loopback HTTP source paths do not establish production/cloud/native execution, real host stopped/volume state, external OCI IAM/ACL responses or NetBird vendor behavior.','Every original safety assertion and suite obligation remains. Unit/mixed classifications authorize no deletion, replacement or retirement.','This acceptance is bound only to the pinned corrected packet and d4ac source. It does not qualify later commits or mutate any adopted ledger.','No source, Git history, AGENTS.md or human working tree was modified; only this exclusive immutable temporary evidence directory was created.'],
'roots':roots}
(OUT/'review.json').write_text(json.dumps(report,indent=2,sort_keys=False)+'\n')
manifest=''.join(sha((OUT/n).read_bytes())+'  '+n+'\n' for n in ['review.json','verify.py'])
(OUT/'SHA256SUMS').write_text(manifest)
for n in ['review.json','verify.py','SHA256SUMS']:os.chmod(OUT/n,0o400)
os.chmod(OUT,0o500)
print(json.dumps({'path':str(OUT/'review.json'),'sha256':sha((OUT/'review.json').read_bytes()),'bytes':(OUT/'review.json').stat().st_size,'manifest_sha256':sha((OUT/'SHA256SUMS').read_bytes()),'counts':report['counts'],'citation_spans':len(citations),'assertions':assertions},indent=2))
