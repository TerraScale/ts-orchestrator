import collections, datetime, hashlib, json, os, pathlib, re, subprocess
OUT=pathlib.Path(__file__).parent
ALLOC=pathlib.Path('/tmp/ts-d4ac-next300-allocation-proposal-raxuc07l/allocation.json')
CONTRACT=ALLOC.parent/'OUTPUT-CONTRACT.md'
PEER=pathlib.Path('/tmp/ts-qa-next300-allocation-independent-2ivixd0j/review.json')
D=json.loads(ALLOC.read_bytes()); B=next(x for x in D['batches'] if x['batch_id']=='DATA75')
SOURCE=D['source_commit']; BASE=D['baseline_commit']; GIT='/run/current-system/sw/bin/git'
def git(*args): return subprocess.check_output([GIT,*args])
def sha(raw): return hashlib.sha256(raw).hexdigest()
assert sha(ALLOC.read_bytes())=='032cb201e692326da7274b12d7dfd15512b1befd325cce375188ae0447ca2523'
assert sha(CONTRACT.read_bytes())=='83ddfcf95cb31877ab2c40cab8ee8963e7491287e4780f29d9d6fcefabcd852b'
assert sha(PEER.read_bytes())=='4a1acb09fb4e6ee22f2d9eeb6ea610ed627c7de40851937676dfdc5bc96436a3'
assert git('rev-parse',SOURCE+'^{tree}').decode().strip()==D['source_tree']
PINS={}; RAW={}; LINES={}; FUNCTIONS={}
(OUT/'source-blobs').mkdir(exist_ok=True)
def pin(path,commit=SOURCE):
 key=(commit,path)
 if key not in PINS:
  raw=git('show',commit+':'+path); RAW[key]=raw; LINES[key]=raw.splitlines()
  mode,typ,blob=git('ls-tree',commit,'--',path).decode().split('\t')[0].split()
  assert typ=='blob'
  dest='source-blobs/'+commit[:12]+'__'+path.replace('/','__')+'.txt'
  (OUT/dest).write_bytes(raw)
  PINS[key]={'commit':commit,'path':path,'git_blob':blob,'git_mode':mode,'sha256':sha(raw),'bytes':len(raw),'packet_copy':dest}
 return PINS[key]
def cite(path,start,end,label,commit=SOURCE):
 p=pin(path,commit); lines=LINES[(commit,path)]; span=b'\n'.join(lines[start-1:end])
 return {'path':path,'function_or_declaration':label,'start_line':start,'end_line':end,'git_blob':p['git_blob'],'git_mode':p['git_mode'],'commit':commit,'span_sha256':sha(span),'span_bytes':len(span),'raw_span_excludes_following_LF':True}
def funcs(path):
 if path in FUNCTIONS:return FUNCTIONS[path]
 pin(path);lines=LINES[(SOURCE,path)]; found={}
 for i,line in enumerate(lines):
  m=re.match(rb'^func (?:\([^)]*\) )?(\w+)',line)
  if not m:continue
  name=m[1].decode(); end=i
  if not line.rstrip().endswith(b'}'):
   end=next(k for k in range(i+1,len(lines)) if lines[k]==b'}')
  found[i+1]=cite(path,i+1,end+1,name)
 FUNCTIONS[path]=found;return found
CAT={}
def ref(key,path,start):CAT[key]=funcs(path)[start]
def many(prefix,path,starts):
 for label,start in starts.items():ref(prefix+label,path,start)
many('s.','internal/delivery/service.go',{'validCell':157,'ConnectClient':168,'Open':191,'Submit':258,'SubmitVerified':312,'retryOperationRead':356,'retryOperationError':400,'publishIntent':414,'publishError':462,'operationKey':482,'getOperation':496,'operationValueFromMsg':515,'Status':537,'status':541,'StatusFor':575,'AcceptedIntent':586})
many('a.','internal/delivery/artifact.go',{'Prepare':54,'store':100,'exists':172,'metadata':226,'retryMetadata':245,'storeFull':297,'stage':302,'discardStage':327,'Accept':336,'touch':363,'persist':391,'verifyCurrent':456,'decodeAdmission':467,'getAdmission':482,'readAdmission':501,'Resolve':529,'verify':543,'check':576})
many('c.','internal/delivery/consumer.go',{'configDigest':37,'Run':66,'stageError':208,'report':220,'failureClass':240,'retryTransport':282,'counterNote':330,'counterForget':348,'process':363,'plannerRefusal':369,'processDelivery':380,'hold':570,'plan':591,'defaultShape':599,'planShape':603,'validatePlan':610,'verifiedIntent':656,'reject':703,'rejectIntent':720,'recordReceipt':725})
many('g.','internal/delivery/artifact_gc.go',{'Collect':70,'retained':167,'lastMessages':265,'size':289,'resize':303,'storeConfig':311})
many('t.','internal/delivery/types.go',{'requestValidate':62,'sourceValidate':69,'manifest':117,'recordValidate':127,'intentValidate':163,'fingerprint':196,'Fingerprint':207,'Decode':217,'Clone':229})
many('codec.','internal/delivery/codec.go',{'Sign':58,'Verify':80,'SignArtifact':102,'VerifyArtifact':127,'Archived':133,'verifyAt':141,'scopeAt':166})
many('container.','internal/delivery/container_consumer.go',{'process':15,'proof':99})
many('d.','internal/delivery/decisions.go',{'intent':15,'rejected':44})
ref('refuse','internal/delivery/refusal.go',10)
many('read.','internal/artifact/read.go',{'verified':24,'authoritative':49,'metadata':105,'chunks':114})
many('touch.','internal/artifact/touch.go',{'touch':26,'live':44,'delete':65,'publish':90})
many('nats.','internal/natscell/runtime.go',{'tlsComplete':66,'Start':349,'start':363,'validate':585})
CAT['nats.Config']=cite('internal/natscell/runtime.go',131,148,'Config (complete struct; no Lab field)')
CAT['nats.Embedded']=cite('internal/natscell/runtime.go',73,101,'Embedded')
many('p.','internal/protocol/json.go',{'strict':33,'decode':46})
ref('p.region','internal/protocol/subjects.go',22)
ref('p.envelope','internal/protocol/envelope.go',134)
many('h.','internal/host/controller.go',{'new':85,'guard':156,'Register':269,'Apply':394})
many('hm.','internal/host/mutations.go',{'registration':74,'desired':102})
many('j.','internal/decisionlog/journal.go',{'New':122,'Record':162,'Query':335})
many('jr.','internal/decisionlog/record.go',{'SetDefault':26,'Record':46})
# Every helper below was read as immutable source. These are evidence dependencies, never additional original roots.
for key,start in {'Publish':43,'admissionGet':52,'recordPublish':61,'codecSign':65,'codecVerify':66,'artifactSign':69,'artifactVerify':72,'archivedVerify':77,'fenceCurrent':83,'fenceGuard':87,'fetch':110,'ackFetch':136,'ack':166,'standbyCurrent':171,'standbyGuard':175,'planner':188,'writer':202,'testService':208,'testServiceWithRuntime':213,'testIntent':229,'mustJSON':1337}.items():
 # writer starts at 202? Resolve from signatures to avoid guessed positions.
 if key=='writer':
  ref('helper.writer','internal/delivery/service_test.go',next(s for s,c in funcs('internal/delivery/service_test.go').items() if c['function_or_declaration']=='ApplyDesired'))
 else:
  if True: # Resolve by actual function name even when a guessed anchor is another declaration.
   names={'Publish':'Publish','admissionGet':'Get','recordPublish':'recordPublishCall','codecSign':'Sign','codecVerify':'Verify','artifactSign':'SignArtifact','artifactVerify':'VerifyArtifact','archivedVerify':'VerifyArchivedArtifact','fenceCurrent':'Current','fenceGuard':'Guard','fetch':'Fetch','ackFetch':'Fetch','ack':'Ack','standbyCurrent':'Current','standbyGuard':'Guard','planner':'Plan','testService':'testService','testServiceWithRuntime':'testServiceWithRuntime','testIntent':'testIntent','mustJSON':'mustJSON'}
   choices=[s for s,c in funcs('internal/delivery/service_test.go').items() if c['function_or_declaration']==names[key]]
   start=min(choices,key=lambda s:abs(s-start))
  ref('helper.'+key,'internal/delivery/service_test.go',start)
for path,prefix in [('internal/delivery/artifact_test.go','artifactHelper.'),('internal/delivery/artifact_gc_test.go','gcHelper.'),('internal/delivery/consumer_diagnostics_test.go','diagHelper.'),('internal/delivery/prepared_intent_test.go','preparedHelper.'),('internal/delivery/container_consumer_integration_test.go','containerHelper.'),('internal/delivery/operation_keys_test.go','keysHelper.'),('internal/delivery/shape_test.go','shapeHelper.')]:
 for start,c in funcs(path).items():
  if not c['function_or_declaration'].startswith('Test'): CAT[prefix+str(start)]=c
GROUPS={
 'artifact':['a.Prepare','a.store','a.exists','a.metadata','a.retryMetadata','a.stage','a.discardStage','a.verify','a.check','read.verified','read.authoritative','read.metadata','read.chunks'],
 'admission':['a.Accept','a.touch','touch.touch','touch.live','touch.publish','a.persist','a.getAdmission','a.readAdmission','a.decodeAdmission','a.verifyCurrent','a.Resolve','a.verify','a.check','read.verified','read.chunks'],
 'operation':['s.getOperation','s.operationValueFromMsg','s.operationKey','s.Status','s.status','s.StatusFor','t.Fingerprint'],
 'submit':['s.Submit','s.retryOperationRead','s.retryOperationError','s.getOperation','s.publishIntent','s.publishError','t.intentValidate'],
 'process':['c.process','c.processDelivery','c.verifiedIntent','c.hold','c.reject','c.rejectIntent','c.recordReceipt','a.readAdmission','a.verify','a.check','read.verified','read.chunks','s.getOperation','s.StatusFor','s.status'],
 'run':['c.Run','c.retryTransport'],
 'gc':['g.Collect','g.retained','g.lastMessages','touch.delete','touch.publish','a.Resolve','a.readAdmission','a.verify','read.verified','read.chunks'],
 'quota':['s.Open','g.size','g.resize','g.storeConfig'],
 'metaRetry':['a.retryMetadata','s.retryOperationError'],
 'opRetry':['s.retryOperationRead','s.retryOperationError'],
 'diagnostic':['c.stageError','c.failureClass'],
 'refusal':['refuse','c.recordReceipt','s.getOperation','s.status','s.StatusFor'],
 'codec':['codec.Sign','codec.Verify','codec.SignArtifact','codec.VerifyArtifact','codec.Archived','codec.verifyAt','codec.scopeAt','p.envelope'],
 'localPlan':['c.plan','c.defaultShape','c.planShape','c.validatePlan','c.configDigest'],
 'container':['container.process','container.proof','t.intentValidate','t.Clone'],
}
# Ordinal is only a join key into the immutable literal allocation; IDs and names below come solely from that allocation.
# Potential category is a non-credit description of the intended assertion path, not an awarded category for a blocked root.
ROWS='''
1|integration|18-20,28-36,46-49,56-58|submit,process,operation|AcceptedIntent must ignore verified-wire cache entries, return the one accepted operation, and reject ambiguity after a second operation settles.|testCodec identity signing and testWriter receipts are synthetic; accepted/status enumeration would depend on real JetStream records.|s.AcceptedIntent,s.SubmitVerified,g.lastMessages
2|integration|107-119,136-150,154-170|gc,artifact,admission|Collector must preserve running/rollback/pending/recent artifacts, fence a racing touch/admission, delete obsolete objects and purge orphan chunks with broker readbacks.|inUse and authority guard are callbacks; history is synthetic records committed to intended real storage. No actual running host is observed. Guard refusal has storage preservation readback.|
3|integration|210-217|gc,artifact,admission|Historical preparation copies must not retain an obsolete release or discard rollback/current/pending digests; deletion and resolution are intended broker effects/readbacks.|Historical operation records and desired-use feed are synthetic. The target is collector storage effects, not history generation.|
4|integration|225-245|quota|Reopen must retain an existing larger stream quota and accept a larger configured quota, read through ArtifactStoreSize.|No process restart is created: two Service instances would bind the same embedded broker.|
5|integration|614-625|admission|Create/replay/resolve must use leader admission state despite a stale follower Get returning missing, with zero follower reads.|overriddenAdmissionGet stubs Get only; intended Create, leader GetLastMsg, artifact reads and resolution remain delegated.|
6|integration|725-737|admission|An existing conflicting leader admission must reject the original envelope and remain byte-identical despite a stale follower entry.|Synthetic conflicting record is explicitly Put into intended real KV; follower Get is overridden but leader path is not.|
7|integration|671-687|admission,codec|Authorized signer replacement must advance beyond the leader revision, retain the new envelope/actor, and avoid stale follower Get.|Old/new keys and authorization transitions are test controlled; intended CAS and readback are not stubbed.|
8|integration|128-155|artifact|artifactExistsForUpload sends an actual authoritative MSG.GET request over NATS to an intentionally silent subscriber, then returns the caller deadline promptly and confirms the subscriber received it.|Direct server.NewServer and nats.Connect are independent of testService. Server has no JetStream; API subscriber is a blackhole. This qualifies only NATS protocol dispatch/cancellation, not storage or leader recovery.|
9|integration|165-175|artifact|Authoritative metadata lookup must distinguish a missing object from a deleted object-store stream after an actual DeleteObjectStore.|Both absences would be real broker responses; no API error hook supplies the asserted values.|
10|integration|476-482|artifact|Quota reduction below stored bytes must reject a new object as ErrArtifactStoreFull while verified readback preserves the previously uploaded object.|The target would be real discard-new storage enforcement, not just translating a constructed error.|
11|unit|487-490|quota|Open rejects invalid configuration before I/O. This root supplies a negative quota but also omits Conn, so the assertion cannot isolate which invalid guard caused ErrInvalid.|Real broker setup is incidental to the local Open guard even after fixture repair.|
12|integration|438-451|artifact|PrepareArtifact must seek the changing source once, hash its first bytes, upload the staged snapshot and verify those exact stored bytes.|changingArtifactReader switches bytes only on a second seek. The digest/seek checks bind the same snapshot consumed by store/readback; no filesystem credit from the temp filename alone.|
13|integration|402-425|artifact|Malformed persisted size metadata must refuse upload without Put and remain byte-identical on authoritative broker readback.|Metadata corruption is a deliberate real publish; counting Put wrapper delegates on effect.|
14|integration|372-386|artifact|Purging existing chunks must force exactly one repair upload, preserve the record, change NUID and pass chunk/digest readback.|putCountingObjectStore delegates Put; the asserted missing chunks are actually purged rather than synthetic errors.|
15|integration|224-235|artifact|Transient post-Put metadata misses must retry to a successful verified object after one upload, with the expected metadata read count.|delayedVisibilityObjectStore injects two GetInfo misses then delegates; Put and final chunk reads remain genuine intended broker operations.|
16|integration|261-263|artifact|The signer callback must observe stored metadata before signing a claim after PrepareArtifact stores its bytes.|storedBeforeSigning performs intended real GetInfo from inside the callback; testCodec provides synthetic signing only.|
17|integration|291-318|artifact|Preparing identical bytes twice must retain record/chunks and perform exactly one Put, with GetInfo readbacks before/after retry.|putCountingObjectStore counts and delegates; authoritative existence and verified chunk reads would determine whether replacement is skipped.|
18|integration|332-352|artifact|A stale GetInfo miss must not replace an existing immutable object; record, NUID and chunks must stay unchanged with no Put.|The stale direct-read hook does not replace production leader MSG.GET or final underlying metadata readbacks.|
19|integration|743-749|admission|ResolveAdmittedArtifact must return the matching admitted/verified artifact and reject a missing role with leader-proven absence.|testIntent would create the claim and bytes; resolve traverses admission lookup and chunk verification, not only name validation.|
20|unit|65-71|metaRetry|Persistent constructed leader API errors must leave no object and end at the caller deadline after at least one closure call.|Direct retry helper over a local closure; no NATS connection or broker read occurs.|
21|unit|85-95|metaRetry|Constructed absence, missing-stream and permanent API errors must be preserved without retry.|The boolean, raw-message pointer and errors are synthetic closure results; no storage boundary.|
22|unit|49-58|metaRetry|One constructed 503/10008 error followed by an in-memory RawStreamMsg pointer must recover in exactly two closure calls.|Retry timing/error classification is local; RawStreamMsg is a struct, not evidence of a broker exchange.|
23|unit|102-109|metaRetry|Cancellation inside the read closure must immediately propagate context.Canceled with no object and exactly one read attempt.|The callback only cancels a Go context and returns a constructed API error.|
24|integration|534-599|admission,artifact,codec|Eight concurrent replacement claims must converge on the new authorized signer, retain immutable provenance, and reject a conflicting source.|Authorization and deterministic keys are local fixtures; intended admission Create/Update CAS, leader readback and object checks are the boundary.|
25|unit|272-280|artifact|verifyArtifact must return ErrInvalid after exactly the visibility-attempt bound when GetInfo always returns synthetic object-not-found.|Every target GetInfo is intercepted before real metadata/chunk reads. Preparing an object beforehand is incidental.|
26|unit|58-63|diagnostic|Known constructed host/timeout/API/unknown errors must map to safe fixed class/code values.|Direct local error classification; no host status, broker or logging I/O.|
27|mixed|29-42|process,diagnostic|The planner callback error must retain planner stage/class locally, while Status must prove no durable operation receipt was created.|diagnosticPlanner is a synthetic error producer. Source distinguishes local staging/classification assertions from the intended broker absence readback.|
28|unit|92-105|diagnostic|Two immediate reports must emit one warning; a forced later time must emit a second with stage/class/suppression fields and no raw tenant error.|slog writes only to bytes.Buffer. Manipulated next timestamp and in-process logging are local. Nothing contacts a log service.|c.report
29|unit|74-82|diagnostic|Constructed host-snapshot/unverified/deadline errors are retryable exemptions while capacity/unknown planner errors count as refusals.|Direct plannerRefusal with local synthetic errors; no host snapshot or planner service is read.|c.plannerRefusal
30|unit|198-208||Cloning an Intent must detach the Container Sequence and Index backing arrays so mutating the clone leaves original bytes unchanged.|Only in-memory slices and Clone; filename does not establish integration.|t.Clone
31|mixed|70-86,102-145,161-182|submit,process,operation,container,codec|Signed broker delivery, retained container proof, pending/accepted/held receipts and recovery would cross JetStream; the native/source/scope invalid arm Submit cases are separate pre-I/O validation.|ContainerApply only counts, reads proof and returns a synthetic manager failure/success. No SwarmKit, registry pull, application readiness or manager execution occurs; direct Lab fixture is blocked at line29. Tampered-wire rejection would write a broker rejection record.|
32|mixed|15-28,31-50|process|Accepted/held process replay paths would commit/read real operations; journal counts and fields use an in-memory Journal with no attached sink/archive.|NewJournal only allocates ring/queue; Query reads the local snapshot. No decision-stream durability follows from this root.|d.intent,d.rejected,j.New,j.Record,j.Query,jr.SetDefault,jr.Record
33|unit|93-102|operation|operationValueFromMsg must reject nil, wrong subject, zero sequence, empty body and unknown marker without reporting legitimate absence.|All RawStreamMsg values are constructed structs and the target is pure validation.|s.operationValueFromMsg
34|integration|66-84|operation|A restricted client denied direct KV Get must still read exact committed bytes/revision via production getOperation leader MSG.GET, and correctly reject missing/deleted keys.|Direct local JetStream server with admin/reader credentials; real Put/Delete and separate connection grants support the assertions. This is one server, no replication or failover.|
35|mixed|32-43|operation|operationKey must be valid and disjoint from the verified-wire key locally; after storing an impersonating operation, verifiedIntent must miss the actual cache and call the rejecting verifier.|rejectingWireVerifier only returns an error. The second assertion depends on real intended operation Create and cache GetLastMsg absence; cryptographic validity is not proved.|c.verifiedIntent
36|integration|54-62|process|Expired desired authorization returned by a writer hook must durably hold a claimed plan and prevent a second write on redelivery.|revokedDesiredWriter is a synthetic ErrInvalid callback. Only intended operation retention, hold CAS and Status readback could earn boundary credit; no actual authorization provider or host effect.|
37|integration|20-38|process|An invalid/unprepared planner result must create a durable refusal with no desired writes; a transient timeout must remain pending across a real Status read.|diagnosticPlanner supplies synthetic errors; asserted outcomes would traverse verified cache/admission/object reads and durable refusal/absence.|
38|integration|37-45|process,refusal|A late RefuseIntent must conflict with an already accepted operation and leave accepted receipt/write count unchanged.|Fencer/planner/writer are local fixtures; conflict preservation would be based on real intended operation CAS/readback.|
39|integration|14-29|refusal,process|Repeated refusal must preserve one rejected identity, conflict on changed generation and prevent desired reapplication during replay.|Authority/authorization callbacks and writer are synthetic; durable refusal creation and status are the intended real boundary.|
40|mixed|54-64|refusal,operation|Denied authorization and stale epoch must fail locally before refusal persistence; a separate Status lookup must prove the operation remains pending.|Authorize and testFence are test-controlled pre-I/O guards. The absence readback would contact JetStream; no authority service or real revoked grant is exercised.|
41|integration|91-115|refusal,operation|A current leader must settle the old-epoch intent identity while refusing to overwrite a separately claimed plan, whose value and revision stay unchanged.|Claimed operation payload is synthetic but would be genuinely created and read through KV.|
42|integration|75-84|operation|StatusFor must report pending for an exact persisted fingerprint and conflict for the same operation ID with a changed generation.|The comparison uses bytes obtained from intended real Create/GetLastMsg; this is not a standalone synthetic decode test.|
43|mixed|610-632|admission,artifact|A connected client must read the admission, reject provenance conflict and verify object bytes; client.Run refusal is a separate local ports guard.|ConnectClient would bind real resources, but its Run guard checks missing consumer configuration before fetch; testCodec provides no real signature.|s.ConnectClient,c.Run
44|mixed|655-669|admission,artifact,codec|Expired claim rejection is a pre-storage codec check; absent admission readback and later fresh admission/archive readback would cross JetStream.|Clock is a mutable fixture time; no NTP or external clock authority is exercised.|
45|integration|1055-1069|process,operation|A writer returning context.Canceled on the first call must leave no final receipt; replay must create an accepted receipt after a second attempt.|testWriter does not perform any host effect despite the test name. Intended real operation/cache reads, creation and result CAS support only delivery retry semantics.|
46|integration|1094-1105|process,operation|A synthetic desired-conflict result must become a durable held receipt and replay without repeating the writer.|No actual host desired conflict is created; only intended delivery receipt/operation durability would be integrated.|
47|integration|1002-1013|process,admission,operation|Consumer acceptance must ignore missing/mismatched follower admissions and use current leader admission, producing one accepted result.|overriddenAdmissionGet intercepts only follower Get. Intended leader MSG.GET, object verification and durable receipt remain real.|
48|integration|1020-1046|process,admission,operation|A leader-proven missing/deleted admission must reject a delivery with zero writer calls even when follower Get returns a stale valid record.|Missing-role and Delete exercise intended actual KV absence/tombstone; stale follower Get is synthetic.|
49|integration|728-756|run,process,submit,operation|Run must resume after one fetch-request or fetch-batch error and produce an accepted durable receipt after at least two fetch attempts.|failingFetchConsumer injects its first error then delegates to the real consumer; no physical broker shutdown is caused.|
50|integration|772-803|run,process,submit,operation|Run must replace an always-failing consumer, fetch the stored intent with the new broker consumer and expose acceptance before clean cancellation.|Permanent errors are injected by failingFetchConsumer. Recovery uses intended CreateOrUpdateConsumer; no actual broker permission change or deletion is performed.|
51|integration|854-877|run,process,submit,operation|A lost Ack callback after result persistence must leave an accepted durable receipt and keep Run alive.|Fetch delegates to the intended real consumer but failingAckMsg.Ack only signals and returns ErrServerShutdown. Root observes 400 ms survival, not actual AckWait redelivery or broker failover.|
52|integration|676-713|run,process,submit,operation|Transient writer failure must retry from a durable broker message, record acceptance, replay without reapplication and reject changed operation identity.|testWriter failure/count is synthetic. Intended intent stream, verified cache, operation CAS and status readback are the asserted delivery boundary.|
53|integration|1076-1087|process,operation|Synthetic ErrFenced from the writer must be held durably and replay without another writer call.|No real authority handoff or host effect occurs in this root. Intended operation CAS and readback establish only delivery hold semantics.|
54|integration|814-845|process,operation|Planner refusals must hold after both observed/broker counts reach the bound, persist/replay the held receipt and exempt transient or inflated delivery counts.|diagnosticPlanner and broker count arguments are synthetic. Some local counter branches occur after intended real verified/admission/object reads; durable hold/status is the core target.|c.counterNote,c.counterForget,c.plannerRefusal
55|integration|1206-1248|submit,run,process,operation|Two conflicting payloads before consumption must create two stream messages, accept the first exact identity and reject the second StatusFor fingerprint.|Both publish calls and stream Info would be real; planner/writer remain synthetic, so accepted means desired-call receipt only.|
56|integration|1251-1334|process,operation,admission|The real host Controller writer must commit generation1 desired state, then a test-controlled epoch change must yield a held operation and preserve generation1 on ordered readback.|Production host Register/ApplyDesired and authority readback are intended real control-log targets. No host agent, guest, TerraBase, application readiness, replication or clock qualification. Downstream authority path not credited because fixture is already blocked.|h.new,h.Register,h.guard,h.Apply,hm.registration,hm.desired
57|mixed|1130-1148|process,operation,admission,codec|A standalone codec.Verify expiry assertion is local; reprocessing the expired wire must use durable verified/admission records and produce acceptance after writer retry.|Mutable fixed clock and testWriter are fixtures; archived signature check is local crypto over broker-read data. No external time or host runtime proof.|
58|mixed|1183-1198|process,operation,codec|Revoking the Authorize callback after the first pending attempt must stop reapplication through durable replay; independently codec.Verify must reject a Lookup-missing signer locally.|Lookup/trusted/revoked booleans simulate policy changes; no external signer service is queried.|
59|integration|931-954|submit,run,process,operation|A signed but unadmitted intent must be consumed and create a query-visible rejected receipt saying artifact is not admitted.|testCodec treats plaintext JSON as verified operator wire, so crypto authenticity is synthetic; broker rejection persistence/readback is the intended boundary.|
60|integration|887-915|submit,run,process,operation|Standby must leave a published intent pending with zero writer calls; toggling leadership must let the same worker consume it and expose one accepted receipt.|testStandbyFence leader flag is local, not real distributed lease election. Intended broker message retention and receipt visibility are the boundary.|
61|unit|919-924||DecodeIntent must reject duplicate members, unknown members and trailing JSON values.|Direct decoding of three byte literals through strict JSON; no broker, file or runtime boundary.|t.Decode,t.intentValidate,p.strict,p.decode
62|unit|281-303|opRetry|Permanent permission/disabled/missing-operation errors must not retry, and closure-triggered cancellation must propagate after one call.|Read closure returns constructed errors and cancels a local context; no production getOperation connection is supplied.|
63|unit|244-256|opRetry|A constructed transient leader error followed by an in-memory operationValue must recover in exactly two read-closure calls.|No JetStream lookup or committed data; durable operation is a byte-string fixture.|
64|unit|259-271|opRetry|Five transient closure failures must recover on the sixth attempt within the local retry budget.|The observed count is synthetic closure calls, not leader recovery over a real stream.|
65|unit|576-603|submit|Generic API5xx must retry once while disabled-for-server/account errors stop immediately.|Every asserted Publish returns a constructed ack/error from interceptedPublish and never delegates. Open/testIntent and Submit pre-read are incidental to retry classification.|
66|unit|502-527|submit|publishIntent must stop at caller deadline and Submit must stop after one blocked callback when its caller is canceled.|Both Publish implementations are local stubs; no asserted publish exchange reaches the broker. Real setup/pre-read does not establish the cancellation target.|
67|unit|537-560|submit|Constructed permanent/disabled/invalid/permission/API4xx/unknown publish errors must return after one attempt.|interceptedPublish never delegates or stores a message. Only local retry policy is asserted.|
68|integration|454-488|submit|Six publishes surrounding five injected ambiguous errors must retain one sequence/message ID, mark duplicates and store exactly one message.|Wrapper explicitly calls base.Publish before each injected error. Intended actual broker acknowledgement/dedup state is material, unlike the stub-only retry roots. No real leader failure is induced.|
69|unit|335-352|submit|Typed transient publish errors must each yield exactly two attempts.|interceptedPublish returns synthetic errors/ack and never delegates; testIntent artifact storage is unrelated setup.|
70|unit|310-328|submit|Two retry attempts must preserve subject and signed payload after a synthetic no-stream response.|interceptedPublish only records arguments and returns an empty ack; no publish/readback verifies delivery or deduplication. testCodec signs identically.|
71|unit|361-374|submit|A callback waiting for its attempt context to expire must be retried once while the parent remains valid.|No Publish delegation. Only Go context deadline/retry control is asserted.|
72|integration|384-443|submit,run,process,operation|Two actual delegated publishes with an injected first ambiguous error must get one sequence with a duplicate ack, store one message and produce one accepted result.|Wrapper base.Publish materially crosses intended broker boundary before hiding the first ack; no real network fault or leader failover is induced. Payload equality refers to actual delegated publications.|
73|unit|61-71||validCell must accept valid regional tokens and reject reserved/global or malformed hyphenation.|Only regex and protocol.CanonicalRegion string validation; no membership/discovery or broker subjects are exercised.|s.validCell,p.region
74|unit|77-94||The bounded refusal counter must evict only its oldest entry, preserve another count and reset a forgotten key.|Only in-memory map/order slices and mutex; no durable delivery or concurrency stress.|c.counterNote,c.counterForget
75|unit|34-55|localPlan|Shaped planner dispatch, recorded/default shape recovery and plan bounds must honor the selected shape and reject mismatches.|shapedPlanner is synthetic and Service has no I/O ports; plan validation is entirely local.|
'''
NOTES={}
for line in ROWS.strip().splitlines():
 parts=line.split('|'); assert len(parts)==7,(len(parts),line)
 i=int(parts[0]); assert i not in NOTES
 NOTES[i]={'intended_character':parts[1],'assertion_ranges':parts[2],'groups':parts[3].split(',') if parts[3] else [],'target_rationale':parts[4],'seam_limits':parts[5],'extra':parts[6].split(',') if parts[6] else []}
assert set(NOTES)==set(range(1,76))
UNIT={20,21,22,23,26,28,29,30,33,61,62,63,64,73,74,75}; INTEGRATION={8,34}
roots=[]
for i,r in enumerate(B['roots'],1):
 note=NOTES[i]; path=r['path']; sd=r['source_declaration']; bd=r['baseline_declaration']
 current=cite(path,sd['start_line'],sd['end_line'],r['current_name'])
 baseline=cite(path,bd['start_line'],bd['end_line'],r['original_name'],BASE)
 assert current['span_sha256']==r['current_declaration_sha256']==sd['sha256']
 assert baseline['span_sha256']==r['original_declaration_sha256']==bd['sha256']
 assert r['state']=='retained_body_exact' and current['span_sha256']==baseline['span_sha256']
 category='unit' if i in UNIT else 'integration' if i in INTEGRATION else 'unresolved'
 core=[]
 for pair in note['assertion_ranges'].split(','):
  rr=pair.split('-');a=int(rr[0]);b=int(rr[-1]);assert sd['start_line']<=a<=b<=sd['end_line']
  c=cite(path,a,b,r['current_name']+' assertion/condition block');c['text']=b'\n'.join(LINES[(SOURCE,path)][a-1:b]).decode();core.append(c)
 assertions=[]
 for number in range(sd['start_line'],sd['end_line']+1):
  line=LINES[(SOURCE,path)][number-1].decode()
  if re.search(r'\bt\.(?:Fatalf?|Errorf?|FailNow)\(',line):
   assertions.append({'line':number,'text':line,'enclosing_conditions':'See complete canonical declaration and core_assertion_blocks; setup/helper failures are retained, not independently credited.'})
 refs=[]
 for group in note['groups']:refs.extend(GROUPS[group])
 refs.extend(note['extra']);refs=list(dict.fromkeys(refs))
 # Resolve only actual connected target calls for independent roots; avoid attributing unused group members.
 if i==8:refs=['a.exists','a.metadata','a.retryMetadata','s.retryOperationError']
 if i==9:refs=['a.metadata']
 if i==11:refs=['s.Open']
 if i in [33,34]:refs=['s.getOperation','s.operationValueFromMsg','s.operationKey'] if i==34 else ['s.operationValueFromMsg']
 production=[dict(CAT[key],citation_key=key,path_status='BLOCKED_INTENDED_PATH_NO_CREDIT' if category=='unresolved' else 'CONNECTED_BODY_PATH_SOURCE_ONLY') for key in refs]
 setup=[]
 if category=='unresolved':
  if i==31:
   setup.append(cite(path,27,51,'direct incomplete natscell.Start/Open setup'))
   blocker='DATA75-B2'
  else:
   setup += [dict(CAT['helper.testService'],citation_key='helper.testService'),dict(CAT['helper.testServiceWithRuntime'],citation_key='helper.testServiceWithRuntime')]
   blocker='DATA75-B1'
  setup.extend(dict(CAT[key],citation_key=key) for key in ['nats.Config','nats.Embedded','nats.tlsComplete','nats.Start','nats.start','nats.validate'])
  # All fixture-related helper methods are pinned. Per-root related helper functions are explicit, never extra roots.
  body=b'\n'.join(LINES[(SOURCE,path)][sd['start_line']-1:sd['end_line']]).decode()
  helperkeys=['helper.testIntent','helper.codecSign','helper.codecVerify','helper.artifactSign','helper.artifactVerify','helper.archivedVerify','helper.fenceCurrent','helper.fenceGuard','helper.planner','helper.writer']
  if any(x in body for x in ['interceptedPublish','recordPublishCall']): helperkeys+=['helper.Publish','helper.recordPublish']
  if 'overriddenAdmissionGet' in body:helperkeys+=['helper.admissionGet']
  if 'failingFetchConsumer' in body:helperkeys+=['helper.fetch']
  if 'failingAckConsumer' in body:helperkeys+=['helper.ackFetch','helper.ack']
  if 'testStandbyFence' in body:helperkeys+=['helper.standbyCurrent','helper.standbyGuard']
  if i==31:helperkeys=['helper.fenceCurrent','helper.fenceGuard']
  setup.extend(dict(CAT[k],citation_key=k) for k in helperkeys)
  # Only helpers in the current test file are added here; all other shared helpers are cited above.
  for k,c in CAT.items():
   if c['path']==path and not k.startswith(('s.','a.','c.','t.','codec.')) and any(k.startswith(pre) for pre in ['artifactHelper.','gcHelper.','diagHelper.','preparedHelper.','containerHelper.','keysHelper.','shapeHelper.']):setup.append(dict(c,citation_key=k))
  rationale='UNRESOLVED: '+blocker+' blocks the fixture before these assertions. '+note['target_rationale']+' Intended path character ('+note['intended_character']+') is recorded solely to preserve obligations; it awards no category credit.'
 else:
  blocker=None;rationale=note['target_rationale']+' '+('Core assertions materially traverse the direct server/client protocol boundary.' if category=='integration' else 'The asserted target has no genuine I/O boundary.')
  if i in [8,34]:setup=[cite(path,sd['start_line'],sd['end_line'],'complete direct NATS server/client fixture and assertions')]
  if i==75:setup=[dict(c,citation_key=k) for k,c in CAT.items() if k.startswith('shapeHelper.')]
 root={**r,'allocation_ordinal':i,'category':category,'category_rationale':rationale,'current_source':current,'baseline_source':baseline,'declaration_hashes_reconfirmed':True,'current_test_git_blob':current['git_blob'],'survival_state':r['state'],'runtime':'UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION','retirement_authorized':False,'retirement_delta':0,'safety_obligations_retained':True,'source_blocker':blocker,'target_obligation':note['target_rationale'],'fake_stub_and_external_limits':note['seam_limits'],'core_assertion_blocks':core,'all_failure_assertion_lines':assertions,'connected_production_citations':production,'actual_setup_helper_citations':setup,'noncredit_intended_path_character':note['intended_character'] if blocker else None,'package_compilation_qualification':'UNKNOWN; shared delivery test source visibly contains unsupported Config.Lab fields. No root was compiled or executed. Independent body-path category is not package buildability qualification.'}
 roots.append(root)
counts=collections.Counter(r['category'] for r in roots)
for cat in ['integration','unit','mixed','unresolved']:counts.setdefault(cat,0)
assert dict(counts)=={'unresolved':57,'integration':2,'unit':16,'mixed':0},counts
assert len(roots)==75 and len({r['root_id'] for r in roots})==75
# Preserve exact canonical root bodies separately for reviewer navigation.
(OUT/'declarations').mkdir(exist_ok=True)
for r in roots:
 sd=r['source_declaration']; raw=b'\n'.join(LINES[(SOURCE,r['path'])][sd['start_line']-1:sd['end_line']]);name=f"declarations/{r['allocation_ordinal']:02d}.txt";(OUT/name).write_bytes(raw);r['raw_current_declaration_packet_file']=name
packet={
 'schema':'ts-original-root-source-classification-v1','state':'CANDIDATE_SOURCE_ONLY_REQUIRES_INDEPENDENT_PEER_REVIEW_NO_PROMOTION','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'owner':'/root/data/executor_hooks','dispatched_by':'/root/qa_integrator','batch_id':'DATA75','scope':['internal/delivery'],'source_commit':SOURCE,'source_tree':D['source_tree'],'baseline_commit':BASE,
 'allocation':{'path':str(ALLOC),'sha256':sha(ALLOC.read_bytes()),'literal_batch_copy':'allocation-DATA75.json','allocation_was_a_proposal':'QA dispatched separately; this candidate does not mutate dispatch fields or ledgers'},
 'output_contract':{'path':str(CONTRACT),'sha256':sha(CONTRACT.read_bytes())},'allocation_independent_review':{'path':str(PEER),'sha256':sha(PEER.read_bytes())},
 'classification_definitions':{
  'integration':'Core assertion materially crosses a genuine server/client/storage, OS/process or protocol boundary. Here only two independent direct-NATS body paths are resolved; no runtime receipt.',
  'unit':'Core assertion is local validation, decoding, retry/clock/context control, logging to a buffer or synthetic callback data.',
  'mixed':'Separate material local-only and genuine boundary assertion blocks within one root. No blocked fixture earns mixed credit.',
  'unresolved':'The actual pinned setup blocks the asserted path or connected source cannot establish it. Intended paths are notes only; no integration/unit/mixed credit.',
  'incidental_setup':'A broker/file/server created before the asserted target does not by itself make local stub or pre-I/O guard assertions integration.',
  'independent_body_path_scope':'A visible package compilation blocker applies globally to execution. The two integration and sixteen unit source categories describe self-contained assertion paths independent of the broken natscell fixture; none assert this package compiles.'},
 'counts':{'allocated_originals':75,'integration':counts['integration'],'unit':counts['unit'],'mixed':counts['mixed'],'unresolved':counts['unresolved'],'retained_body_exact':75,'retirement_delta':0,'runtime_qualified':0,'ledger_promotion_delta':0},
 'source_blockers':[
  {'id':'DATA75-B1','affected_original_roots':56,'cause':'testServiceWithRuntime constructs natscell.Config with Lab:true, but canonical Config has no Lab field. It additionally omits required client TLS/JWT and embedded operator/system/cell JWT, route/client TLS and broker IDs. No fake or repaired fixture may be substituted in this source-only review.','citations':[CAT[k] for k in ['helper.testService','helper.testServiceWithRuntime','nats.Config','nats.Embedded','nats.Start','nats.start','nats.validate','nats.tlsComplete']]},
  {'id':'DATA75-B2','affected_original_roots':1,'cause':'TestContainerIntentSignedBrokerRecovery directly uses unsupported Lab:true and absent production TLS/JWT material before Open. Its manager callback is synthetic regardless of fixture repair.','citations':[cite('internal/delivery/container_consumer_integration_test.go',27,51,'direct incomplete fixture'),CAT['nats.Config'],CAT['nats.start'],CAT['nats.validate']]}
 ],
 'findings':[
  {'id':'DATA75-F1','finding':'All 75 baseline/source declaration spans match the pinned manifest exactly; every original and assertion remains retained.','retirement_authorized':False},
  {'id':'DATA75-F2','finding':'57 fixture-dependent roots remain unresolved. Unsupported Lab field is static evidence, not an observed compiler result; required-credential guards independently make the supplied setup unsuitable.'},
  {'id':'DATA75-F3','finding':'Eight blocked roots (65,66,67,69,70,71 stubbed publishes,25 stubbed visibility and11 Open guard) have noncredit unit intended paths despite incidental broker setup; distinct delegated-publish roots68/72 materially call base.Publish but remain blocked.'},
  {'id':'DATA75-F4','finding':'Root8 uses a real NATS protocol exchange to a silent synthetic API subscriber; it does not test actual JetStream storage. Root34 uses a genuine one-server JetStream storage/permission path with Put/Delete and independent reader.'},
  {'id':'DATA75-F5','finding':'Root11 negative-quota assertion is confounded by missing Conn; root45 writer cancellation performs no host effect; root51 only observes survival after an injected Ack error, not actual broker redelivery. No source changes proposed or made.'}
 ],
 'literal_root_ids':[r['root_id'] for r in roots],'roots':roots,'citation_catalog':CAT,'source_pins':sorted(PINS.values(),key=lambda p:(p['commit'],p['path'])),
 'integrity':{'all_150_declaration_spans_verified':True,'all_75_retained_exact':True,'canonical_source_tree_verified':True,'span_hash_convention':'Inclusive declaration/citation line span, raw bytes joined by LF, excluding following LF. Full file SHA256 and Git blob are separately pinned.','counts_exhaust_only_DATA75':True,'source_edits':0,'git_mutations':0,'go_build_test_runtime_commands':0,'cloud_actions':0,'ledger_mutations':0},
 'qualification_limits':['Runtime UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION for all75; no Go/discovery/build/test/lint/format/runtime commands run.','All75 original obligations retained; no retirements, implementation changes or ledger promotion. Independent peer review remains required.','No classification credit transfers to current7330. All global qualification categories remain OPEN.','No TerraBase, OCI, multi-node replication, true leader failover, manager execution, guest/application readiness, clock/NTP or production credential delivery qualification.','External NATS SDK/server APIs are referenced at canonical first-party callsites; dependency internals are not vendored/reviewed here. Direct-server tests demonstrate intended real protocol paths in source only.','Whole package compilation has a visible unsupported Config.Lab blocker. Independent root source labels are not build success or runtime proof.']}
(OUT/'classification.json').write_text(json.dumps(packet,indent=2)+'\n')
(OUT/'README.md').write_text('''# DATA75 candidate source review

75 original roots retained exactly: **2 integration, 16 unit, 0 mixed, 57 unresolved**. Runtime: UNKNOWN for every root. Retirement delta and ledger promotion: 0.

The 57 unresolved roots depend on incomplete `natscell.Start` fixtures using `Config{Lab: true}`. Canonical `natscell.Config` has no Lab field; validation also requires TLS/JWT material absent from these fixtures. Source-only review cannot repair or substitute fixtures. Each root records its intended assertion target without granting it classification credit.

The 18 resolved categories describe independently connected assertion paths. Whole delivery-package compilation is visibly blocked by shared unsupported fields and has not been run. The two integration paths use direct `server.NewServer` fixtures: root08 checks real NATS dispatch/cancellation to a silent synthetic API subscriber; root34 checks actual one-server JetStream Put/Delete, restricted direct-read permissions and production leader reads. Neither earns execution, replication or current7330 credit.

`classification.json` contains literal allocated IDs, exact baseline/current declarations, independent per-root rationales, assertion text/conditions, helper/production spans with Git blobs and SHA256, file pins, limitations and findings. `declarations/01.txt` through `75.txt` contain exact source declaration bytes without following LF. `source-blobs/` contains canonical full-file bytes for every citation. `build_packet.py` is the reproducible static generator, not a source change or test execution.

Source: d4ac68882716e7cfb14afca2f88ad596a38041af; tree: 3b73a410a025bd8050ad1d42e54acc7d5eda4b82. Baseline: bfca60368f60d2da67f9016d1d489317ae8749c8. The input manifest/contract/independent-allocation-review hashes are embedded in JSON. Every baseline/source declaration pin was independently rechecked.

Candidate only. Independent peer review and separate accepted-ledger promotion are required before accounting changes. No source/Git/ledger changes, Go commands, process/listener/lock actions, cloud work or runtime execution occurred. Files sealed0444 and directories0555 with SHA256SUMS. All original safety obligations remain open.
''')
print(json.dumps(packet['counts'],sort_keys=True));print('PINNED_FILES',len(PINS)); print('REPORT',OUT/'classification.json')
