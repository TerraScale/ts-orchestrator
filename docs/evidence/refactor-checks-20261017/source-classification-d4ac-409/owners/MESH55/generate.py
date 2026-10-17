"""Static artifact builder. Reads immutable Git objects; never imports/runs Go."""
import collections, hashlib, json, pathlib, re, subprocess
D=pathlib.Path('/tmp/ts-mesh55-d4ac-source-classification-pfjjhj7x')
G='/run/current-system/sw/bin/git'
C='d4ac68882716e7cfb14afca2f88ad596a38041af'
B='bfca60368f60d2da67f9016d1d489317ae8749c8'
T='3b73a410a025bd8050ad1d42e54acc7d5eda4b82'
RUNTIME='UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION'
AP=pathlib.Path('/tmp/ts-d4ac-next300-allocation-proposal-raxuc07l/allocation.json')
CP=AP.with_name('OUTPUT-CONTRACT.md')
QP=pathlib.Path('/tmp/ts-qa-next300-allocation-independent-2ivixd0j/review.json')
def sha(b):return hashlib.sha256(b).hexdigest()
assert sha(AP.read_bytes())=='032cb201e692326da7274b12d7dfd15512b1befd325cce375188ae0447ca2523'
assert sha(CP.read_bytes())=='83ddfcf95cb31877ab2c40cab8ee8963e7491287e4780f29d9d6fcefabcd852b'
assert sha(QP.read_bytes())=='4a1acb09fb4e6ee22f2d9eeb6ea610ed627c7de40851937676dfdc5bc96436a3'
a=json.loads(AP.read_bytes()); batch=next(b for b in a['batches'] if b['batch_id']=='MESH55')
assert json.loads((D/'allocation-slice.json').read_bytes())==batch
assert subprocess.check_output([G,'rev-parse',C+'^{tree}']).decode().strip()==T
cache={};pins={};citations={};funcs={}
def source(path,commit=C):
 key=(commit,path)
 if key not in cache:
  data=subprocess.check_output([G,'show',commit+':'+path])
  entry=subprocess.check_output([G,'ls-tree',commit,'--',path]).decode().strip()
  mode,kind,tail=entry.split(' ',2);blob,gotpath=tail.split('\t',1)
  assert kind=='blob' and gotpath==path
  p={'git_mode':mode,'git_blob':blob,'sha256':sha(data),'bytes':len(data)}
  # Git-object SHA1 is checked independently of ls-tree.
  assert hashlib.sha1(('blob '+str(len(data))+'\0').encode()+data).hexdigest()==blob
  cache[key]=data; pins.setdefault(path,{})['source' if commit==C else 'baseline']=p
 return cache[key]
def span(path,start,end,commit=C):
 data=source(path,commit); lines=data.splitlines(); raw=b'\n'.join(lines[start-1:end])
 return {'path':path,'commit':commit,'git_blob':pins[path]['source' if commit==C else 'baseline']['git_blob'],
 'start_line':start,'end_line':end,'span_sha256':sha(raw),'raw_bytes':len(raw),'text':raw.decode()}
def index(path):
 if path not in funcs:
  lines=source(path).decode().splitlines();out={}
  for i,line in enumerate(lines):
   m=re.match(r'^func (?:\(([^)]*)\) )?([A-Za-z_]\w*)',line)
   if not m:continue
   receiver,name=m.groups();receiver=(receiver.split()[-1].lstrip('*') if receiver else '')
   key=(receiver+'.' if receiver else '')+name
   end=i if line.endswith('}') else next(j for j in range(i+1,len(lines)) if lines[j]=='}')
   assert key not in out,(path,key)
   out[key]=(i+1,end+1)
  funcs[path]=out
 return funcs[path]
def cite(path,name):
 key=path+'::'+name
 if key not in citations:
  start,end=index(path)[name];citations[key]={'function':name,**span(path,start,end)}
 return key
def refs(path,names):return [cite(path,n) for n in names.split()]
def unique(seq):return list(dict.fromkeys(seq))
GC='internal/globalcontrol/';GV='internal/globalview/'
# Production groups terminate at explicit real NATS/JetStream API calls, or show local guards.
gc_open=refs(GC+'store.go','OpenHome validMirrorPeers')+refs(GC+'stream.go','HomeStreamConfig openStream inspectStream verifyHome ensureMirrorConsumers verifyMirrorConsumer removeStaleMirrorConsumers MirrorConsumerConfig')
gc_store=refs(GC+'store.go','Writer.PutRoster Writer.PutDirectory Writer.put Writer.establishTerm Reader.Roster Reader.Directory Reader.read Reader.info Reader.Term readTerm epochHeaderMatches Writer.Fence wrongLastSequence subject')+refs(GC+'types.go','Roster.Validate Roster.Active DirectoryEntry.Validate DirectoryEntry.ValidateAgainst DirectoryEntry.Key DirectoryKey')+refs('internal/entityid/id.go','Valid Parse Derive')
gc_auth=refs('internal/authority/runtime.go','Start Config.validate Runtime.run Runtime.reconcileWithRetry Runtime.reconcile Runtime.acquire Runtime.appendLease Runtime.Current Runtime.Guard Runtime.guardLocked')+refs('internal/authority/log.go','openControlStream inspectCreatedControlStream verifyControlStreamConfig')
gc_real_help=refs(GC+'globalcontrol_test.go','newTestJetStream startAuthority')
gc_fake_help=refs(GC+'fencing_test.go','openFencedPair pausedFencer.Current pausedFencer.Guard')+refs(GC+'globalcontrol_test.go','newTestJetStream testRoster')
gv_basic=refs(GV+'view.go','NewView View.Regions View.Region View.region View.listed View.Changed View.Accept View.Follow decode validate normalize View.prune')
gv_http=refs(GV+'http.go','Handler writeJSON')
gv_publish=refs(GV+'publish.go','Publish publishOnce')
gv_build=refs(GV+'build.go','Build buildControllers buildVersions buildNodes buildServices fillHost nodeHealth nearFull buildTotals wanSources buildReplication buildLinks buildRoutes buildVolumes buildScaling buildDatabases buildErrors buildHealth keep peak clip')+refs(GV+'managed_services.go','boundedManagedServices')+refs('internal/observability/views.go','DistinctFilesystems')
gv_kv=refs(GV+'view.go','OpenBucket View.KeepLastKnown View.Persist View.markPersisted View.load')
gv_observed=refs(GV+'boundary_test.go','observedRollup followedTestView readTestRegion')+refs(GV+'view_test.go','startNATS waitClosed')
gv_wire=refs(GV+'boundary_test.go','followedTestView publishTestRollup publishTestRaw readTestRegion readTestRegions')+refs(GV+'view_test.go','startNATS rollupAt fakeClock.Now closed')
# One entry per literal original name: category, independent target rationale, core assertion blocks.
# Blocks are inclusive canonical source spans; full raw declaration accompanies all failure sites.
spec={}
def add(name,category,rationale,blocks,local=(),limit=''):
 assert name not in spec
 spec[name]={'category':category,'rationale':rationale,'core':blocks,'local':list(local),'limit':limit}
add('TestDocumentsRelayExactBytesAsNextGenerations','mixed',
 'Invalid kind/cell/payload and zero/foreign epoch calls assert local rejection. Separately, valid writes, generation/idempotence, absent/other-cell reads, refusal against stored bytes, and forged stored records traverse real JetStream publish/read/CAS. The admit callback synthesizes refusal but receives bytes read from the real stream.',
 [(59,100,'real stored-document generations, idempotence and global payload readback'),(111,128,'stored prior-byte refusal and unchanged readback'),(129,131,'real forged-record read rejection')],[(23,58,'local document guards and epoch guard'),(104,106,'local invalid regional cell read')])
add('TestFollowOffersTheDocumentOnEveryChangeAndRecheck','mixed',
 'Invalid kind/recheck calls fail locally. Valid follow creates a production ordered consumer and consumes actual stored documents; callback offers, foreign-cell suppression, update delivery, repeated rechecks, and cancellation observe that connected path.',
 [(174,212,'document delivery, update, suppression, cancellation and recheck offers')],[(144,149,'local invalid follow arguments')])
add('TestOpenHomeRaisesAnOldMessageBound','integration',
 'A real preexisting stream with an old message bound is opened and updated through production OpenHome; fresh stream Info and a maximum-size document append assert the resulting server configuration.',[(229,237,'actual stream bound readback and admitted payload write')])
add('TestOldLeaderCannotCommitAfterNewTerm','integration',
 'Both writers use a fake passing lease fencer. The beforePublish hook delegates to the new writer’s real Fence; server term-barrier CAS rejects stale writes, and real roster/term readback verifies no overwrite. The interleaved flag observes execution of that delegated boundary hook.',[(64,105,'actual old/new term writes, delegated barrier race, rejection and readback')],limit='Proves the global-stream barrier under synthetic lease facts; does not prove actual leader election or lease expiry.')
add('TestNewLeaderFirstWriteFencesTheOldTerm','integration',
 'With synthetic lease facts, successful real old/new roster appends establish an epoch-2 barrier. Subsequent old directory and idempotent roster attempts read actual stream state and must return ErrFenced.',[(115,129,'committed new-term barrier fences valid old-leader attempts')],limit='Fake fencers deliberately keep old lease admission passing; genuine lease lifecycle is outside the asserted seam.')
add('TestConcurrentWritersNeverInterleaveTerms','unresolved',
 'The intended concurrent append/CAS seam is unreachable: both 26-character ID bases receive numeric suffixes, so every entry has noncanonical 27/28-character identifiers. PutDirectory first reads the real roster but rejects at ValidateAgainst -> Validate -> entityid.Valid/Parse before Writer.put. Errors are discarded. The final term/header scan observes the setup barrier and roster only and cannot establish concurrent-writer safety.',
 [(146,149,'invalid suffixed IDs and ignored concurrent write errors'),(164,181,'real stored setup records checked without evidence of any concurrent directory append')],limit='Original concurrent-writer safety obligation remains open; no replacement, retirement or unit/integration credit.')
add('TestConcurrentReadsAndAppends','integration',
 'Valid derived partition IDs let concurrent PutDirectory calls reach actual JetStream append/CAS while another goroutine repeatedly reads the stored roster. Both operations assert errors; fake lease admission narrows the claim to the storage concurrency path.',[(202,212,'valid directory writes and roster reads in concurrent goroutines')],limit='No race-detector or runtime execution reviewed; source classification only.')
add('TestForgedRecordsAreRejected','integration',
 'The test reads a genuine committed record, republishes its bytes with a mismatched epoch header, injects a corrupt term barrier, and asserts production reads and subsequent writes reject the actual stored corruption.',[(232,253,'forged record/term publish, production read rejection and fail-closed append')])
add('TestHomeRemovesMirrorConsumersOfRemovedPeers','integration',
 'OpenHome creates actual server consumers, then reopens with fewer peers; fresh consumer lookups assert removed-peer deletion and retained peer/unrelated audit consumer survival.',[(264,288,'actual consumer creation, removal and independent readback')],limit='Single embedded server contract-consumer lifecycle, not cross-region mirror replication.')
add('TestHeaderlessRecordsBeforeTheFirstBarrierAreRejected','integration',
 'A synthetic valid record body is published without the epoch header into the actual stream. Production Reader.Roster performs a real stored read and rejects it as corruption before any barrier.',[(310,315,'real headerless append and production read rejection')])
add('TestMirrorWithFiniteLimitsIsRefused','unit',
 'Each case constructs and mutates StreamConfig values and directly calls verifyMirror. There is no server creation, stream lookup or persisted configuration in the asserted target.',[(327,334,'local config acceptance and finite-limit rejection')])
add('TestEmptyMirrorWithoutHomeContactFailsClosed','integration',
 'A manually marked mirror Reader uses a genuine empty ordinary stream. Roster and Term perform actual missing-message/stream Info reads and must return ErrMirrorNotCaughtUp.',[(348,354,'real empty-stream reads fail closed')],limit='Reader.mirror is synthetic and the stream is not a real remote mirror; no home contact or interregion topology is established.')
add('TestStreamVerificationRefusesTransformsAndLateMirrorStarts','unit',
 'Home and mirror configs are local values; direct verifyHome/verifyMirror calls reject a subject transform and delayed start sequence before any server I/O.',[(362,371,'local incompatible-config guards')])
add('TestRosterValidation','unit',
 'Synthetic roster values exercise Validate, Active and rejection cases entirely in memory; OCI region strings are inputs, not OCI discovery.',[(31,58,'local valid/active/mutated roster assertions')])
add('TestDirectoryValidation','unit',
 'Directory keys and Validate/ValidateAgainst operate on synthetic identifiers and a local roster. No stored directory or region placement is read or written.',[(65,94,'local key and directory validation assertions')])
add('TestMirrorConfigIsReadOnlyAndPinnedToHome','unit',
 'The target is local StreamConfig construction and direct verifier checks. OpenMirror receives nil JetStream with identical home/cell and returns from the distinct-cell guard before touching it.',[(100,142,'local mirror/home configuration and early OpenMirror guard')])
add('TestHomeWriterGuardsAndCompareAndSets','mixed',
 'Wrong authority scope/peers/home and zero/foreign epochs have separate local guard assertions. Valid home open/reopen, consumer inspection, roster/directory generation checks and corruption/purge rejection use genuine JetStream state. The inactive-region directory rejection depends on a real roster read.',
 [(160,185,'actual stream/consumer setup, stored roster requirement and CAS/idempotence'),(198,229,'actual directory/roster readback, stored corruption and server purge rejection')],
 [(152,158,'local authority-scope and peer guards'),(187,197,'local wrong-home and foreign/zero epoch guards')])
add('TestHomeRefusesADriftedMirrorConsumer','mixed',
 'A real server consumer is created with a drifted delivery subject and OpenHome inspects/rejects it. A separate direct verifyMirrorConsumer call compares a freshly constructed config to a different peer without I/O.',[(270,281,'real existing drifted consumer rejected on home open')],[(282,284,'separate local wrong-peer config verifier')])
add('TestHeartbeatValidation','unit',
 'Heartbeat fields are synthetic local structs; Validate checks version/region/time formats with no subscription, heartbeat delivery or cloud interaction.',[(11,29,'local heartbeat acceptance and rejection table')])
add('TestNextRosterFollowsHeartbeats','unit',
 'NextRoster transforms a supplied in-memory heartbeat map at explicit times. Assertions cover generation, membership, freshness and retaining home, with no genuine network discovery or storage.',[(45,69,'local roster transformation and freshness assertions')])
# Every Build root below routes its observed result through production publish -> remote Follow -> listening HTTP server.
add('TestBuildHealth','integration','Synthetic health scenarios become actual production rollup wire data. Status/reason assertions inspect the remote HTTP-decoded rollup after Build -> publishOnce -> NATS -> remote Follow; the target materially crosses both protocols.',[(119,125,'remote health status/reason assertions')])
add('TestBuildNodeHealthPerNode','integration','Node health, count and memory values are read from the remotely published HTTP rollup rather than directly invoking the pure builder. Reports/grants are synthetic; their acquisition is outside this claim.',[(131,141,'remote node health/count/memory assertions')])
add('TestBuildNodeMissingReportIsDown','integration','A missing synthetic input report is carried through production Build and real NATS/HTTP. The remote API must retain grant services while reporting that node down.',[(148,151,'remote missing-report node status/services')])
add('TestBuildTotalsExcludeDownNodesAndCountBeyondCap','integration','Seventy synthetic node reports exercise totals beyond the display cap; all totals, down-node and truncation assertions inspect the actual NATS-delivered HTTP representation.',[(165,179,'remote totals, resource sums, cap and down-node assertions')])
add('TestBuildFilesystemsDedupeByDevice','integration','Synthetic filesystem metrics are deduplicated locally by production DistinctFilesystems/fillHost, then transported through real NATS and HTTP before assertions on roles, clamped usage and totals.',[(190,198,'remote deduplicated filesystems and disk totals')],limit='No statfs or real filesystem metric acquisition/readback is asserted.')
add('TestBuildLinksCarryWANLag','integration','Injected link probes and WAN observations are transformed by production Build and then cross real NATS/HTTP. Link fields and peak replication lag are asserted on the remote representation.',[(219,237,'remote link and replication-lag assertions')],limit='No actual WAN probe or replication measurement is executed by the asserted source path.')
add('TestBuildRoutes','integration','Synthetic NATS peer/RTT facts are converted into route observations and cross actual publish/follow and HTTP before route fields are compared.',[(253,265,'remote route error/lag/RTT assertions')],limit='Does not establish genuine multi-server NATS routing or latency measurement.')
add('TestBuildErrorsFromEvents','integration','Injected events are filtered, clipped and converted by production buildErrors; the asserted errors come back through real NATS and HTTP, including Unicode clipping and node attribution.',[(277,289,'remote filtered/clipped event errors')])
add('TestBuildErrorsClipsNodes','mixed','Remote node clipping/count/truncation assertions cross NATS/HTTP. The separate len(nodes) assertion examines only the original local input slice header after Build.',[(300,305,'remote error-node clipping and truncated flag')],[(307,309,'local original input slice length')],limit='The local length assertion does not establish preservation of underlying slice contents.')
add('TestBuildErrorsSourceOverridesEvents','integration','The error-source precedence result is asserted only after production Build publishes it through real NATS and the remote HTTP API.',[(316,319,'remote explicit-error source precedence')])
add('TestBuildDatabasesSortedAndCapped','mixed','Remote database sort/cap/truncation assertions cross NATS/HTTP. A distinct local assertion checks that the original database input order was preserved.',[(327,332,'remote database sort/cap/truncation')],[(334,336,'local original input database order')])
add('TestBuildDatabasePeersSortedAndCapped','mixed','Peer ordering/cap and truncation are read remotely after NATS/HTTP. The original db.Peers order is checked separately in local memory.',[(346,352,'remote peer sort/cap/truncation')],[(354,356,'local original input peer order')])
add('TestBuildAutoscaleSkipsAwaitingRelease','integration','Synthetic autoscale results pass through production Build, real NATS follow and HTTP; the remote services list must exclude awaiting-release.',[(365,368,'remote autoscale service filtering')],limit='No actual scaling, release acquisition or deployment occurs.')
add('TestBuildVolumesSortedAndCapped','integration','Synthetic volume records are sorted/capped into the rollup and pass through actual NATS/HTTP before the volume order and truncation checks.',[(376,381,'remote volume cap/order and truncation')],limit='No genuine volume provisioner or placement-store acquisition is asserted.')
add('TestBuildVersionsAndControllers','integration','Controller and version facts are synthetic inputs; their production transformation and transport are asserted using the remote NATS-fed HTTP result.',[(389,398,'remote controller summary and grouped build versions')])
add('TestBuildRollupJSONStaysUnder16KB','integration','The measured JSON is a re-encoding of observedRollup, whose result necessarily passed production publishing, a separate remote NATS subscriber and a real HTTP response. The byte bound therefore observes a transported output; there is no separate direct local Build assertion.',[(428,435,'byte bound on the transported and HTTP-decoded rollup')],limit='The assertion bounds this synthetic 12-node/20-link scenario and its re-encoded rollup, not all possible rollups or the enclosing HTTP Region response.')
add('TestCollectReadsSourcesOnce','mixed','The closed connection makes Aggregator.Cluster fail at local ChanSubscribe admission before a request is sent; clock UTC, error precedence and direct collected-input assertions are local. The resulting critical normalized rollup is separately published and read through genuine NATS/HTTP.',[(465,468,'remote critical normalized rollup')],[(450,463,'local error-source selection, closed-client result and collected inputs')],limit='The name does not itself prove all sources are read once; assertions show only the supplied callbacks/fields. Initial server setup is incidental to the closed-client failure.')
add('TestCollectEventsWhenNoErrorSource','mixed','Cluster collection exchanges genuine NATS snapshot requests/replies and the event error then crosses the production rollup NATS/HTTP path. Separately, the injected Events callback asserts its local limit and the collected event/error fields are checked directly.',[(477,499,'real snapshot request/reply yields ClusterOK'),(502,505,'remote transported event error')],[(492,494,'local injected Events callback limit'),(499,501,'local event/error selection fields alongside boundary-derived ClusterOK')],limit='Default collector system introspection is incidental; no OS metric correctness or real event source is established.')
add('TestFailedVolumeReadIsNotAnEmptyList','mixed','failingVolumes returns a synthetic error with no storage I/O; Sources.Collect’s direct failure flag is local. That flag is then carried by production Build and real NATS/HTTP to assert degraded remote health and unavailability.',[(529,533,'remote unavailable flag and degraded health')],[(523,526,'local fake volume error maps to unavailable')],limit='No actual placement-store failure or volume backend is established.')
add('TestFunctionObservationsCrossNATSAndHTTP','integration','Synthetic function observations/error hooks flow through Sources.Collect -> Build -> production publishOnce -> remote NATS Follow -> actual HTTP client/server. Status/state/tenant filtering assertions inspect actual responses, including unavailable paths.',[(26,40,'production collect/build/publish and actual HTTP response assertions'),(44,59,'current/not-found/unavailable request scenarios')],limit='Injected callbacks supply all function facts and failures; no actual function manager/worker executes.')
add('TestManagedServicesCrossSourceNATSAndHTTP','integration','Synthetic service/task observations and error hooks flow through Sources.Collect -> Build -> NATS -> separate remote view -> real HTTP. Response status/state and service payload assertions materially cross those boundaries.',[(24,38,'production collect/build/publish and actual HTTP response assertions'),(42,76,'service data/not-found/unavailable/stale/truncated scenarios')],limit='No actual Swarm/native service manager, task scheduler or deployment effects are exercised.')
add('TestHandlerListsListedRegionsAndRejectsOthers','unit','Direct Handler.ServeHTTP calls use NewRecorder/NewRequest in memory. Listing, normalized region lookup and not-found status checks have no listening HTTP server, socket exchange or NATS subscriber.',[(18,32,'local HTTP-handler recorder responses')])
add('TestViewAccept','integration','Invalid/outdated/newer synthetic rollups are actually published and flushed through NATS; production Follow decodes and accepts/rejects them. Changed-channel assertions and the HTTP read observe the resulting remote view, rather than direct local Accept calls.',[(131,155,'actual wire rejection/accept notification and remote newer timestamp')])
add('TestViewRegions','mixed','Actual NATS-fed rollups are listed/read over a real HTTP endpoint. The separate direct Region(hidden) call returns from the local registry guard before consulting the held rollup, so it independently checks local-only behavior.',[(163,171,'wire inputs and HTTP listed-region order'),(176,180,'HTTP listed/local rollup availability')],[(173,175,'separate local unlisted-region guard')])
add('TestViewRegionsStale','integration','A synthetic rollup crosses NATS and its staleness is asserted in actual HTTP responses at two injected clock values. The clock is fake; the response path is genuine.',[(187,195,'remote staleness threshold on delivered rollup')])
add('TestDecodeRejectsInvalidRollups','integration','Invalid encoded fields/subjects/size/JSON are injected onto real NATS, not passed directly to decode. After dispatch synchronization, the HTTP list must contain no accepted observation.',[(214,229,'invalid wire scenarios, genuine publish and remote rejection')])
add('TestDecodeAcceptsUnknownField','integration','Forward-compatible JSON is actually published through NATS and decoded by production Follow; a listening HTTP read must contain the accepted remote rollup.',[(240,245,'unknown-field wire publish and HTTP acceptance')])
add('TestViewAcceptBoundsRegions','integration','Every bounded/pruned map state is produced by actual synchronized NATS callbacks. Missing late entry and final map size are observations of those protocol effects, while actual HTTP reads verify accepted cells. There is no independent direct local Accept invocation.',[(253,273,'wire-driven bounds, HTTP accepted cells and map-state readback')],limit='The unlisted late observation is refused at the full map bound; listing alone is not claimed to filter every incoming rollup.')
add('TestFollowLoadsAndFollows','integration','A real JetStream KV entry is loaded by KeepLastKnown, then a newer rollup arrives through actual NATS Follow. Direct view assertions observe those genuine storage/protocol effects; cancellation joins the subscriber loop.',[(290,302,'real KV preload and production load result'),(311,323,'actual live update and follower cancellation')])
add('TestKeepLastKnownPersistsWhileLeading','integration','Local input and a constant true leading callback drive production KeepLastKnown; genuine KV Get readback must observe the persisted key. The callback supplies leadership, not storage success.',[(336,345,'production persistence and actual KV readback')],limit='Does not prove genuine authority/leader election or crash recovery.')
add('TestPersistWritesOnCadence','integration','With an injected clock, production Persist writes real KV data, skips early updates and writes at cadence; independent KV revisions and stale-key Get verify actual storage changes/deletion.',[(361,395,'actual KV writes/revisions/cadence and unlisted key deletion')])
add('TestPersistKeepsKeysBeforeTheRegistryIsRead','integration','A key is genuinely written to KV before a nil synthetic registry is supplied; production Persist and subsequent KV.Get assert that the existing last-known key survives.',[(405,414,'actual existing KV key preserved')])
add('TestTwentyRegionsFollow','integration','Twenty synthetic full rollups traverse one real NATS connection/server and production Follow; held count/freshness and cancellation assertions depend on delivered messages.',[(433,464,'real repeated publication, eventual acceptance and fresh region listing')],limit='One embedded server and synthetic region data do not establish twenty deployed regions, WAN behavior, or production throughput.')
add('TestPublishWhileLeading','integration','An atomic callback supplies leadership; a genuine NATS subscription must time out while false and receive a production Publish message once true. The held local view is checked after the same publish path.',[(499,512,'real nonpublication/publication subscription and held published view')],limit='Build callback and leadership are synthetic; no authority election or actual metrics collection is established.')
add('TestDecodeKeepsOnlyTheRegionsOwnScaleStatus','integration','Synthetic valid/foreign/invalid scale status is encoded and published over actual NATS. Production decode calls Status.Validate and strips inappropriate scale fields; a real HTTP response asserts the result.',[(529,542,'wire-driven own/foreign/invalid scale filtering through HTTP')],limit='No actual scaling decision or resource mutation is exercised.')
assert len(spec)==55
# Per-root production and helper references are scoped to the actual asserted route.
roots=[]
for original in batch['roots']:
 name=original['current_name'];s=spec[name];p=original['path'];base=original['baseline_declaration'];cur=original['source_declaration']
 for commit,ranges,expected in [(B,base,original['original_declaration_sha256']),(C,cur,original['current_declaration_sha256'])]:
  proof=span(p,ranges['start_line'],ranges['end_line'],commit)
  assert proof['span_sha256']==expected==ranges['sha256'],(name,commit)
  assert proof['text'].startswith('func '+name+'(') and proof['text'].endswith('\n}')
  expected_file=a['canonical_test_file_pins'][p]['source' if commit==C else 'baseline']
  assert pins[p]['source' if commit==C else 'baseline']==expected_file
 body=span(p,cur['start_line'],cur['end_line']);text=body['text'];helper=[];prod=[]
 if p.startswith(GC):
  if s['category']!='unit':
   if name!='TestEmptyMirrorWithoutHomeContactFailsClosed':prod+=gc_open
   if p.endswith('document_test.go'):
    prod+=refs(GC+'store.go','Writer.put Writer.establishTerm Reader.read readTerm epochHeaderMatches wrongLastSequence subject')
   elif name in ['TestHomeRemovesMirrorConsumersOfRemovedPeers','TestHomeRefusesADriftedMirrorConsumer']:
    pass # The asserted boundary is real consumer configuration/lifecycle, not writer append.
   elif name=='TestHeaderlessRecordsBeforeTheFirstBarrierAreRejected':
    prod+=refs(GC+'store.go','Reader.Roster Reader.read epochHeaderMatches subject')+refs(GC+'types.go','Roster.Validate')
   elif name=='TestEmptyMirrorWithoutHomeContactFailsClosed':
    prod+=refs(GC+'store.go','Reader.Roster Reader.Term Reader.read readTerm Reader.info epochHeaderMatches subject')
   else:prod+=gc_store
   if 'startAuthority(' in text:helper+=gc_real_help;prod+=gc_auth
   elif 'openFencedPair(' in text:helper+=gc_fake_help
   else:helper+=refs(GC+'globalcontrol_test.go','newTestJetStream')
   if 'pausedFencer{' in text:helper+=refs(GC+'fencing_test.go','pausedFencer.Current pausedFencer.Guard')
   if 'testRoster(' in text:helper+=refs(GC+'globalcontrol_test.go','testRoster')
   if 'assertMirrorConsumers(' in text:helper+=refs(GC+'globalcontrol_test.go','assertMirrorConsumers')
   if p.endswith('document_test.go'):prod+=refs(GC+'document.go','validDocument Writer.PutDocument Reader.Document Reader.Follow Reader.watch')
   if name=='TestEmptyMirrorWithoutHomeContactFailsClosed':prod+=refs(GC+'store.go','Reader.checkMirrorGapFree')
  else:
   if 'testRoster(' in text:helper+=refs(GC+'globalcontrol_test.go','testRoster')
   if name=='TestRosterValidation':prod+=refs(GC+'types.go','Roster.Validate Roster.Active validOCIRegion')
   elif name=='TestDirectoryValidation':prod+=refs(GC+'types.go','DirectoryEntry.Key DirectoryKey DirectoryEntry.Validate DirectoryEntry.ValidateAgainst Roster.Active')+refs('internal/entityid/id.go','Valid Parse')
   elif name in ['TestMirrorConfigIsReadOnlyAndPinnedToHome','TestMirrorWithFiniteLimitsIsRefused','TestStreamVerificationRefusesTransformsAndLateMirrorStarts']:prod+=refs(GC+'stream.go','HomeStreamConfig MirrorStreamConfig verifyHome verifyMirror OpenMirror')
   elif name=='TestHeartbeatValidation':prod+=refs(GC+'heartbeat.go','Heartbeat.Validate')+refs(GC+'types.go','validOCIRegion')
   elif name=='TestNextRosterFollowsHeartbeats':prod+=refs(GC+'heartbeat.go','Heartbeat.Validate NextRoster')+refs(GC+'types.go','Roster.Validate Roster.Active validOCIRegion')
 else:
  prod+=gv_basic
  if p.endswith('build_test.go'):
   helper+=gv_observed;prod+=gv_build+gv_publish+gv_http
   if 'healthyRegion(' in text:helper+=refs(GV+'build_test.go','healthyRegion reportOf ptrTo')
   if 'reportOf(' in text:helper+=refs(GV+'build_test.go','reportOf ptrTo')
   if 'samePtr(' in text:helper+=refs(GV+'build_test.go','samePtr')
   if name.startswith('TestCollect') or name=='TestFailedVolumeReadIsNotAnEmptyList':prod+=refs(GV+'build.go','Sources.Collect')
   if name.startswith('TestCollect'):prod+=refs('internal/observability/aggregate.go','NewAggregator Aggregator.Cluster')
   if name=='TestCollectEventsWhenNoErrorSource':prod+=refs('internal/observability/aggregate.go','ServeSnapshots')+refs('internal/observability/collector.go','NewCollector Collector.Snapshot')
   if name=='TestFailedVolumeReadIsNotAnEmptyList':helper+=refs(GV+'build_test.go','failingVolumes.Volumes')
  elif p.endswith('function_integration_test.go') or p.endswith('managed_services_integration_test.go'):
   helper+=refs(GV+'boundary_test.go','followedTestView')+refs(GV+'view_test.go','startNATS waitClosed');prod+=gv_build+gv_publish+gv_http+refs(GV+'build.go','Sources.Collect')+refs(GV+'drilldown.go','Region.ResourceState mountDrilldowns drilldownData writeResource')
   if p.endswith('/function_integration_test.go'):prod+=refs(GV+'function_http.go','mountFunctionViews')+refs(GV+'functions.go','Region.FunctionState')
   else:prod+=refs(GV+'managed_services.go','Region.ManagedServiceState')
  elif p.endswith('/http_test.go'):prod+=gv_http
  else:
   if 'followedTestView(' in text:helper+=gv_wire;prod+=gv_http
   else:helper+=refs(GV+'view_test.go','startNATS rollupAt')
   if name in ['TestFollowLoadsAndFollows','TestKeepLastKnownPersistsWhileLeading','TestPersistWritesOnCadence','TestPersistKeepsKeysBeforeTheRegistryIsRead']:prod+=gv_kv
   if name=='TestFollowLoadsAndFollows':helper+=refs(GV+'view_test.go','publishUntil waitClosed')
   if name=='TestTwentyRegionsFollow':helper+=refs(GV+'view_test.go','fullRollup allHeld');prod+=[]
   if name=='TestPublishWhileLeading':helper+=refs(GV+'view_test.go','waitClosed');prod+=gv_publish
   if name=='TestDecodeKeepsOnlyTheRegionsOwnScaleStatus':prod+=refs('internal/nodescale/status.go','Status.Validate')
 def block(v,kind):
  first,last,role=v
  assert cur['start_line']<=first<=last<=cur['end_line'],(name,v)
  return {'role':role,'assertion_kind':kind,**span(p,first,last)}
 all_lines=source(p).decode().splitlines()
 sites=[{'line':i,'text':all_lines[i-1].strip()} for i in range(cur['start_line'],cur['end_line']+1) if re.search(r'\bt\.(?:Fatalf?|Errorf?)\(',all_lines[i-1])]
 assert sites,(name,'missing assertions')
 if s['category']=='unit':boundary='No genuine external I/O in the asserted target.'
 elif s['category']=='unresolved':boundary='Real setup stream writes and roster/term reads occur; intended concurrent append/CAS boundary is blocked by invalid input.'
 elif p.startswith(GC):boundary='Actual embedded NATS/JetStream client/server stream or consumer operations; file-backed setup is not independent filesystem qualification.'
 elif p.endswith('build_test.go') or p.endswith('_integration_test.go'):boundary='Actual NATS publication/subscription to a separate remote view plus a listening httptest HTTP server/client exchange.'
 elif 'Persist' in name or name=='TestFollowLoadsAndFollows':boundary='Actual JetStream KV storage API and independent Get/revision readback; Follow additionally consumes actual NATS publications.'
 elif name=='TestPublishWhileLeading':boundary='Actual NATS sync subscription timeout/receipt from production Publish.'
 else:boundary='Actual NATS wire publication -> production Follow and resulting view/HTTP observations; HTTP where cited helpers perform listening-server client reads.'
 facts=[]
 if 'pausedFencer' in text or 'openFencedPair' in text:facts.append('pausedFencer returns synthetic Current/Guard facts; real term and stream outcomes are not stubbed.')
 if 'beforePublish' in text:facts.append('beforePublish is a delegating interleaving hook calling the next writer’s actual Fence; it does not fabricate a publish result.')
 if 'admit :=' in text:facts.append('admit returns an injected refusal; prior bytes come from actual stored record reads.')
 if p.startswith(GV):facts.append('Rollup/clock/registry/metrics/service/function input facts are supplied by test values or callbacks; transport and readback are the only genuine external boundaries claimed.')
 if name=='TestCollectReadsSourcesOnce':facts.append('Initial NATS server is incidental to the closed-client Cluster failure; ChanSubscribe rejects before PublishRequest.')
 if name=='TestCollectEventsWhenNoErrorSource':facts.append('Events callback is synthetic. Collector may read default system state incidentally; specific OS metrics are not asserted.')
 if name=='TestFailedVolumeReadIsNotAnEmptyList':facts.append('failingVolumes.Volumes always returns an injected error and performs no external read.')
 if name=='TestEmptyMirrorWithoutHomeContactFailsClosed':facts.append('Reader mirror flag is set manually over an ordinary empty stream, not an actual remote mirror.')
 root={**original,'category':s['category'],'rationale':s['rationale'],'boundary_and_limits':boundary,
 'qualification_limits':s['limit'] or 'Source category only; no execution, production topology, availability or runtime qualification follows.',
 'runtime':RUNTIME,'retirement_authorized':False,'retirement_credit':0,'safety_obligations_retained':True,
 'current_test_git_blob':pins[p]['source']['git_blob'],'baseline_test_git_blob':pins[p]['baseline']['git_blob'],
 'raw_declaration_hash_convention':'Inclusive func-to-column-zero-final-brace bytes, excluding the following LF.',
 'declarations_reconfirmed':True,'baseline_declaration_evidence':span(p,base['start_line'],base['end_line'],B),
 'source_declaration_evidence':body,'assertion_sites':sites,
 'core_assertion_spans':[block(v,'local' if s['category']=='unit' else 'blocked_intended_boundary' if s['category']=='unresolved' else 'genuine_boundary') for v in s['core']],
 'local_only_assertion_spans':[block(v,'local') for v in s['local']],
 'connected_setup_helper_refs':unique(helper),'connected_production_refs':unique(prod),'fakes_stubs_external_facts':facts,
 'all_assertion_conditions':'Exact conditions, tables, callback assertions and select cases are preserved in source_declaration_evidence.text; core/local spans identify classification-bearing blocks.'}
 roots.append(root)
counts=dict(collections.Counter(r['category'] for r in roots));counts['total']=len(roots)
assert counts=={'mixed':11,'integration':35,'unresolved':1,'unit':8,'total':55},counts
assert {r['root_id'] for r in roots}=={r['root_id'] for r in batch['roots']} and len({r['root_id'] for r in roots})==55
assert all(r['state']=='retained_body_exact' and not r['retirement_authorized'] for r in roots)
# Snapshot source pins include every citation, with baseline pins for every allocated root's test file.
report={'schema':'ts-original-root-source-classification-v1','state':'CANDIDATE_PENDING_INDEPENDENT_PEER_REVIEW_AND_SEPARATE_PROMOTION',
 'batch_id':'MESH55','owner':'/root/mesh/material','source_commit':C,'source_tree':T,'baseline_commit':B,
 'allocation_manifest':{'path':str(AP),'sha256':sha(AP.read_bytes())},'output_contract':{'path':str(CP),'sha256':sha(CP.read_bytes())},
 'allocation_activation_evidence':{'path':str(QP),'sha256':sha(QP.read_bytes()),'dispatch':'QA owner dispatch under ROOT next300 source-read authorization, inherited session task.'},
 'runtime':RUNTIME,'retirement_authorized':False,'retirement_credit':0,'safety_obligations_retained':True,
 'category_definitions':{'integration':'Core asserted result materially traverses genuine server/client/storage or protocol I/O. Synthetic input narrows the claim but does not erase a demonstrated transport seam.',
 'unit':'Asserted target is local validation, transformation or synthetic/recorder API behavior without genuine target I/O.',
 'mixed':'Separate local-only assertion blocks and genuine boundary assertion blocks materially coexist in the original root.',
 'unresolved':'Intended assertion seam is blocked or connected source evidence is insufficient; independent of runtime UNKNOWN.'},
 'counts':counts,'originals':roots,'source_pins':pins,'citations':citations,
 'qualification_limits':['No Go, gofmt, build, test, lint, benchmark, executable, cloud or runtime command was invoked for this report.',
 'Only static Python and immutable Git-object reads were used; no source/project/Git/ledger mutations were made.',
 'Embedded NATS/JetStream/HTTP boundaries are source-reachable claims, not proof those tests compile or pass.',
 'No R3 quorum, OCI, deployed multi-region/WAN, real function/Swarm execution, genuine production metrics acquisition or disk crash durability is qualified.',
 'The current 7330 qualification does not transfer. All five qualification categories remain OPEN. No newly added helper/test or unallocated root receives credit.'],
 'findings':[{'root_id':GC+'fencing_test.go::TestConcurrentWritersNeverInterleaveTerms','severity':'unresolved_original_safety_obligation',
 'summary':'Invalid suffixed entity IDs block every concurrent directory append before CAS; errors are ignored.',
 'test_spans':[span(GC+'fencing_test.go',142,149),span(GC+'fencing_test.go',164,181)],
 'production_refs':refs(GC+'store.go','Writer.PutDirectory')+refs(GC+'types.go','DirectoryEntry.ValidateAgainst DirectoryEntry.Validate')+refs('internal/entityid/id.go','Valid Parse'),
 'static_literal_lengths':{'0000000000B703KMD4B8J6EWBB':len('0000000000B703KMD4B8J6EWBB'),'0000000000KJ432RJ85B7APRW2':len('0000000000KJ432RJ85B7APRW2')},
 'consequence':'Do not infer concurrent term ordering from setup log scans; retain original safety assertion obligation without retirement.'}],
 'accounting_effect':{'ledger_mutated':False,'promotion_authorized':False,'retirement_delta':0,'classified_accepted_delta':0,
 'accepted_before_and_after':a['accepted_accounting'],'candidate_scope_only':55,
 'required_next_step':'Independent peer source review, followed by separately authorized accepted-ledger promotion.'}}
# findings refs are already cited; ensure every citation resolves and every file pin is canonical.
for r in roots:
 for cid in r['connected_setup_helper_refs']+r['connected_production_refs']:assert cid in citations
for c in citations.values():assert c['git_blob']==pins[c['path']]['source']['git_blob']
report['source_pins']=pins
(D/'classification.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
summary={k:report[k] for k in ['batch_id','owner','source_commit','source_tree','baseline_commit','counts','runtime','retirement_authorized','retirement_credit','state','allocation_manifest']}
summary['unresolved_root_ids']=[r['root_id'] for r in roots if r['category']=='unresolved']
summary['classification_json_sha256']=sha((D/'classification.json').read_bytes())
(D/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
(D/'README.md').write_text('''# MESH55 candidate source classification\n\nRead `classification.json` for the exact 55 original roots, raw declaration evidence, core/local assertions and connected helper/production citations. `summary.json` supplies immutable source/allocation pins and category totals.\n\nCandidate counts: **35 integration / 8 unit / 11 mixed / 1 unresolved = 55**. No accepted ledger count changes.\n\nThe unresolved root is `internal/globalcontrol/fencing_test.go::TestConcurrentWritersNeverInterleaveTerms`. Numeric suffixes make both IDs longer than the canonical 26-character ULID format. Production `PutDirectory` reads the roster, then validation returns before concurrent append/CAS; the test discards all errors. Log assertions observe setup state and do not establish the intended concurrent-writer obligation. No original is retired or replaced.\n\nGlobalview Build roots use the shared `observedRollup` helper: production Build -> publishOnce -> actual NATS -> separate remote Follow -> listening HTTP server/client -> asserted rollup. Pure synthetic inputs limit acquisition claims; they do not make this demonstrated transport incidental. Separate local input-preservation assertions are classified mixed. HTTP recorder-only assertions remain unit.\n\nRuntime: **UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION**. Source review does not prove compilation, passing tests, production availability, R3 quorum, cloud effects or deployed multi-region behavior. No 7330 qualification transfers. Retirement authorization and credit: **false / 0**.\n\nIntegrity: all allocated baseline/source declaration hashes and test-file pins were recomputed from immutable Git blobs; every cited source file and function span is pinned. Raw declaration/span SHA256 excludes the following LF. `generate.py` is the static artifact builder; it invokes Git object reads and performs no Go/runtime execution. `integrity.json` records the independent static packet checks. `SHA256SUMS` covers every other artifact.\n\nNext: independent peer review of these candidates. Accepted-ledger promotion requires a separate authorization.\n''')
print(json.dumps({'counts':counts,'files_pinned':len(pins),'citations':len(citations),'report_sha256':summary['classification_json_sha256']}))
