import collections
import hashlib
import json
import os
import pathlib
import re
import subprocess

ROOT = pathlib.Path('/tmp/ts-net48-d4ac-source-classification-k9shja9e')
GIT = '/run/current-system/sw/bin/git'
inputs = json.loads((ROOT / 'review-inputs.json').read_text())
CURRENT = inputs['source_commit']
BASELINE = inputs['baseline_commit']
UNKNOWN = 'UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION'

def digest(data):
    return hashlib.sha256(data).hexdigest()

def git(*args):
    return subprocess.check_output([GIT, *args])

assert digest(pathlib.Path(inputs['allocation_manifest']).read_bytes()) == inputs['allocation_sha256']
assert git('rev-parse', CURRENT + '^{tree}').decode().strip() == inputs['source_tree']
qa_path = pathlib.Path('/tmp/ts-qa-next300-allocation-independent-2ivixd0j/review.json')
assert digest(qa_path.read_bytes()) == '4a1acb09fb4e6ee22f2d9eeb6ea610ed627c7de40851937676dfdc5bc96436a3'

pins = {}
source = {}
functions = {}
for version, commit in [('current', CURRENT), ('baseline', BASELINE)]:
    for local in sorted((ROOT / 'source' / version).rglob('*.go')):
        path = str(local.relative_to(ROOT / 'source' / version))
        data = local.read_bytes()
        assert data == git('show', commit + ':' + path), (version, path)
        entry = git('ls-tree', commit, '--', path).decode().strip()
        mode, kind, tail = entry.split(' ', 2)
        blob, recorded_path = tail.split('\t', 1)
        assert kind == 'blob' and recorded_path == path
        key = version + ':' + path
        pins[key] = dict(path=path, commit=commit, git_blob=blob, git_mode=mode,
                         sha256=digest(data), bytes=len(data), archived_as=str(local.relative_to(ROOT)))
        lines = data.decode().splitlines()
        source[key] = lines
        if version == 'current':
            for i, line in enumerate(lines):
                match = re.match(r'^func (?:\([^)]*\) )?([^ (\[]+)', line)
                if not match:
                    continue
                end = i + 1 if line.rstrip().endswith('}') else next(j + 1 for j in range(i + 1, len(lines)) if lines[j] == '}')
                functions[(path, match[1])] = (i + 1, end)

def cite(path, name, role='connected production/helper declaration'):
    start, end = functions[(path, name)]
    pin = pins['current:' + path]
    raw = '\n'.join(source['current:' + path][start-1:end])
    return dict(path=path, function=name, start_line=start, end_line=end,
                git_blob=pin['git_blob'], git_mode=pin['git_mode'], file_sha256=pin['sha256'],
                file_bytes=pin['bytes'], declaration_sha256=digest(raw.encode()), role=role)

M = 'internal/netbird/manager/'
S = 'internal/netbird/sshlogin/'
P = 'internal/netbird/pathaudit/'
D = 'internal/netbird/dns/'
B = 'internal/netbird/foundation/'
A = 'internal/authority/'
V = 'internal/vaultsecret/'
N = 'internal/networkplan/plan.go'

def refs(path, *names):
    return [(path, name) for name in names]

HTTP = refs(M+'api.go', 'NewAPI', 'do') + refs(M+'fake_test.go', 'newFakeManager', 'api', 'serve', 'read', 'write', 'seedLegacy')
SYNC = refs(M+'sync.go', 'Sync', 'run', 'planGroups', 'planPolicies', 'planAccount', 'planDNS', 'planZone', 'planRecords', 'verifySetupKey') + refs(M+'peers.go', 'admittedPeerRecords')
PRUNE = refs(M+'peers.go', 'Prune', 'serverPeers', 'serversGroupID', 'cleanLabel', 'slotIP') + refs(M+'sync.go', 'run')
LOOP = refs(M+'loop.go', 'withDefaults', 'Run', 'cycle', 'leading', 'sameAuthority')
VALIDATE = refs(M+'desired.go', 'GRU', 'Validate', 'withServerGroups') + refs(N, 'RegionReservation', 'ValidateRegion')
CLI = refs(M+'cli.go', 'Run', 'readToken', 'writeReport')
KEY = refs(M+'setupkey.go', 'CreateServerSetupKey')
AUTH = refs(A+'runtime.go', 'Start', 'Current', 'Guard', 'guardLocked', 'appendLease', 'Close') + refs(A+'log.go', 'openControlStream') + refs(A+'types.go', 'CanMutate') + refs(M+'automatic_integration_test.go', 'accountAuthorityStore', 'accountAuthorityConfig', 'Current', 'Guard')
DEX = refs(S+'sshlogin_test.go', 'newFakeDex', 'verification') + refs(S+'sshlogin.go', 'deviceLogin', 'sameOrigin', 'firstForm')
PROCESS = refs(S+'sshlogin.go', 'run', 'signIn', 'copyOutput', 'verificationURL') + refs(S+'sshlogin_test.go', 'TestHelperNetBird', 'approved')

# Each entry is independently tied to the root's assertions below; shared references
# identify actual connected declarations, not additional classified original roots.
spec = {}
def add(name, category, rationale, trace, local, deps, limits='', hooks=''):
    assert name not in spec
    spec[name] = dict(category=category, rationale=rationale, assertion_to_target_trace=trace,
                     local_only_assertion_blocks=local, dependencies=deps,
                     qualification_limits=limits, injected_hooks_and_fixtures=hooks)

add('TestOperatorDNSPermissionsWithPrivateUmask', 'mixed',
    'Combines a local subscriber-path invariant with actual production mkdir/write effects verified by filesystem Stat under umask 0077.',
    'Test calls mkdir(owned), write(subscriber), and mkdir(existing); production creates/chmods only new owned paths. os.Stat readback requires 0755/0644 and preserves an existing 0700 directory.',
    'Lines 14-16 independently compare filepath.Dir(subscriber) with /etc; no I/O supports that assertion.',
    refs(D+'dns.go', 'mkdir', 'write'), 'Does not invoke the installer, systemd, resolver, or NetBird process.', 'Temporary paths replace installation paths; actual OS umask and filesystem calls remain.')
add('TestPlanAndRejectUnsafeDNSSetup', 'unit',
    'Assertions cover rendered plan text and local argument validation; every invocation omits --apply.',
    'Run parses arguments, rejects control characters/invalid addresses/config combinations, renders to bytes.Buffer, and returns at !apply before filesystem/process installation.',
    'All asserted cases are local rendering or pre-apply validation.', refs(D+'dns.go', 'Run'),
    'The command text mentioning podman does not launch Podman or NetBird.')
add('TestBackupRestorePersistentIdentityAndProtectedCopies', 'integration',
    'Core assertions recover exact persistent bytes and committed SQLite rows through genuine processes, archive/filesystem operations and OCI SDK HTTP uploads/downloads.',
    'sqlite helper launches python3 to create databases; a real writer commits both stores when quiesce closes its pipe and Wait joins it. Backup snapshots real files, resumes, and uploads both regional objects through SDK HTTP. Disk-backed handler checks immutable-write/KMS/checksum headers and persists O_EXCL objects. LatestBackup lists paginated objects. Restore downloads/verifies/extracts/atomically installs; ReadFile and a second Python SQLite process verify encryption/signing bytes, integrity and exact rows. Protection downgrades, cancellation, partial upload failure, corrupt bodies and digest-valid traversal are asserted through the same protocol/filesystem paths.',
    'Fixture construction checks are prerequisites to the boundary scenario, not separate product validation branches.',
    refs(B+'backup.go', 'Backup', 'protected', 'writeBackup', 'appendBackupFile', 'LatestBackup', 'download', 'Restore', 'backupObjectDigest') + refs(B+'backup_integration_test.go', 'sqlite', 'writeJSON') + refs('internal/ociresource/ociresourcetest/factory.go', 'Server'),
    'Synthetic database schema and HTTP Object Storage responses; no deployed NetBird service, OCI account, actual regional loss, real retention lock, IAM authorization, TLS or production cryptographic signature verification. Server helper checks Authorization presence only.',
    'Quiesce truly closes/joins the SQLite writer once; resume is an atomic flag callback. HTTP public/unlocked/failSFO faults alter persisted fixture responses; cancellation callback is injected.')
add('TestManagementAuthorityCancelsCommittedWriteAndRecoversFromSnapshot', 'mixed',
    'Independent missing-authority local guard assertions precede a real committed HTTP write whose headers/body response is interrupted, cancelled and recovered without replacing identity.',
    'Follower cycle exits before token read. Authorized Loop.cycle calls Sync -> API.do -> loopback handler; handler delegates f.serve to commit the first group, optionally flushes an incomplete response, flips leader false and waits for request cancellation. Watcher cancels active HTTP; assertions require exactly one committed group/write. Reenabled leader reads server state and converges retaining createdID.',
    'Missing authority returns errAuthorityLost and reads zero credentials before any request (lines 44-56).',
    HTTP + SYNC + PRUNE + LOOP,
    'Leadership is atomic.Bool, credentials are callback bytes, and manager state is synthetic in-memory HTTP state. No actual NATS authority, Vault or NetBird deployment.', 'Injected Leader transition happens after genuine handler-side commit; incomplete response faults are actual HTTP cancellation seams.')
add('TestManagementAuthorityFencesEveryPeerRenameWriteAndRecovers', 'integration',
    'The asserted intermediate rename and later recovery are server-side effects of genuine HTTP PUTs, fenced between successive writes.',
    'Sync initializes fake manager through API.do. Prune peer rename runs under Loop; wrapper delegates f.serve then revokes atomic leadership on the first PUT. Assertions inspect exactly one mutation and name+"-renaming"; restored leadership reads and completes the rename through HTTP.',
    'No independent local-only target block; leader toggles are injected controls around actual writes.', HTTP + SYNC + PRUNE + LOOP,
    'Synthetic NetBird handler semantics and callback leadership; no real account authority or daemon.', 'Wrapper revokes Leader after first HTTP PUT has committed in f.serve.')
add('TestAutomaticAccountAuthorityRecoversAcrossOwnerRestart', 'integration',
    'Core owner continuity assertions cross actual embedded NATS JetStream authority storage and genuine HTTP manager writes/readback.',
    'accountAuthorityStore starts a real loopback NATS server/client with disk storage. authority.Start creates the durable stream/lease. Automatic cycle uses Current and per-write Guard. First group POST commits through f.serve, closes first authority and starts a successor against the same stream; returned/lost response variants must fence the old cycle after one write. New cycle retains the committed group ID and converges.',
    'No separate local validation target; counts and IDs read externally committed fixture state.', HTTP + SYNC + PRUNE + LOOP + AUTH + refs(M+'automatic.go', 'Automatic'),
    'Single embedded local NATS server (Replicas 1), synthetic manager state and injected PAT; no distributed failover or live NetBird/OCI qualification.', 'accountAuthority delegates to a replaceable actual Runtime; HTTP wrapper injects handoff after real fixture-state commit.')
add('TestAutomaticManagementGuardsWritesDuringAuthorityStoreLoss', 'integration',
    'The safety assertion depends on real JetStream unavailability rather than the still-live local snapshot.',
    'After real NATS shutdown and WaitForShutdown, Current().CanMutate remains true as a scenario precondition. Loop.cycle reaches API.beforeWrite -> Runtime.Guard -> guardLocked stream.Info/GetLastMsgForSubject/appendLease. Store loss must return authority/deadline error and leave manager mutations empty.',
    'The locally live lease check establishes the fault premise; it is not independent unit coverage.', HTTP + SYNC + PRUNE + LOOP + AUTH + refs(M+'automatic.go', 'Automatic'),
    'Does not qualify clustered NATS loss or production remote manager behavior. Reads may fail before a mutation guard if authority renewal observes loss; either actual store loss fences the target.', 'Injected PAT callback; actual server shutdown is the fault, synthetic HTTP mutations are the effect oracle.')
add('TestAutomaticManagementRefusesForeignRegionalAuthority', 'unit',
    'The asserted foreign-scope refusal is a local snapshot comparison before credential lookup or any manager request.',
    'Automatic receives an actual authority Runtime initialized for fra, but cycle uses Current (atomic local snapshot), then sameAuthority rejects expected.Scope != gru before Token callback. reads must remain zero.',
    'Entire core target is sameAuthority/CanMutate local guard. NATS setup is incidental to supplying the snapshot.', LOOP + AUTH + refs(M+'automatic.go', 'Automatic'),
    'No authority Guard call or manager/Vault I/O establishes the assertion.', 'Credential callback increments an atomic counter; its body does not contact Vault.')
add('TestAutomaticManagementWaitsForFoundationWithoutExiting', 'unit',
    'The asserted log-and-retry behavior comes from an injected credential error and local loop/channel timing; NATS is only snapshot setup.',
    'Automatic Token closure invokes the supplied ref callback. It returns foundation unavailable before ReadCurrentRefs, API construction or any Guard. Run logs through injected callback and remains alive until cancellation. Current/leading read local snapshots.',
    'All target assertions concern the local injected error, log signal and nonexit over 20ms.', LOOP + AUTH + refs(M+'automatic.go', 'Automatic'),
    'Does not demonstrate a missing real OCI foundation, Vault outage, or recovery when one becomes available.', 'Ref callback always returns errors.New; Logf sends a channel notification; actual embedded NATS setup is incidental.')
add('TestEnrollmentRecoversCommittedResponsesAndDelivery', 'integration',
    'Recovery, duplication, revocation and protected escrow assertions traverse genuine filesystem writes/readback and both NetBird and OCI SDK HTTP boundaries.',
    'ReconcileServerEnrollment opens/flocks protected escrow, records intent and attempted/key/secret state using sync+rename, calls API.do for groups/keys and vaultsecret.Ensure/ReadVersioned via actual OCI SDK clients. Disk-backed HTTP handlers persist committed key/Vault JSON before injected lost responses. Reopening the production store on repeat reconciliation must recover one delivered identity, revoke only orphaned key and retain 0600 enrollment.json.',
    'Injected term-check branches are controls inside the recovery scenarios, not standalone local-only target blocks.',
    refs(M+'enrollment.go', 'ReconcileServerEnrollment', 'enrollmentKey', 'CreateSecret') + refs(M+'enrollment_store.go', 'openEnrollmentStore', 'read', 'write', 'close') + refs(M+'api.go', 'NewAPI', 'do') + VALIDATE + refs(M+'enrollment_integration_test.go', 'readEnrollmentJSON', 'persistEnrollmentJSON', 'writeEnrollmentJSON') + refs(V+'vault.go', 'Ensure', 'lookup', 'ReadVersioned', 'readBundle', 'decodeBundle', 'ValidateDeliveryRefs') + refs('internal/ociresource/ociresourcetest/factory.go', 'Server'),
    'No real OCI IAM/Vault service or NetBird account. Authorization signature presence, not cryptographic validation; no TLS. Quiesce is a nil-return stub, so real daemon drain/shutdown is unqualified.',
    'beforeWrite/authority.Check compare atomic term; Quiesce returns nil. Fault handlers lose committed responses; persistent upstream/Vault JSON and SDK transport remain genuine local I/O.')
add('TestSetupKeyCreatesOnlyItsCanonicalRegionalGroup', 'mixed',
    'Combines real HTTP planning/create/group scoping assertions with independent pre-I/O noncanonical-group rejection.',
    'CreateServerSetupKey reads groups/setup keys through API.do, plans missing fra group and key, then applies group POST before setup-key POST. Handler mutation sequence and scoped auto_groups/secret output are asserted. A second Desired targeting ts-ops-gateway is rejected by withServerGroups before HTTP.',
    'Lines 129-133 independently reject a non-server group with zero mutations.', HTTP + KEY + VALIDATE,
    'Synthetic manager group/key state and generated fake key value; no actual enrollment.')
add('TestSyncDiscoversRegionalGroupsWithoutNATSOrPeerHealth', 'integration',
    'Discovery and access scoping are asserted on genuine HTTP observations and writes, including subsequent CLI/Loop reconciliation and retained server state.',
    'Sync/API.do initially observes only admitted groups. Fixture then adds offline SFO and empty FRA groups; CLI sync and Loop.cycle read those over HTTP and write eight narrowly scoped policies per remote region. Assertions compare rule fields, IDs, memberships/resources and operator/ungrouped exclusions; second cycle requires no writes.',
    'Names and rules are checked locally after protocol-side writes; no separate pre-I/O input-validation target.', HTTP + SYNC + LOOP + CLI + VALIDATE,
    'Synthetic peers/groups; no NATS mesh, remote region, peer health or actual overlay traffic.', 'Leader/PAT callbacks are injected for Loop; remote groups and health are synthetic handler records.')
add('TestSyncRefusesUntrustedOrAmbiguousRegionalGroupsBeforeMutation', 'integration',
    'Refusal is based on records actually fetched through the production HTTP client, with zero handler-side mutations asserted.',
    'For jwt/integration/empty/duplicate issuer fixtures, Sync first validates Desired, API.do GET /groups decodes the actual loopback response, then issuer/withServerGroups ambiguity guards refuse before planned writes.',
    'The decision is local validation of HTTP observations, not an injected direct API feed; no independent pre-request guard block.', HTTP + refs(M+'sync.go', 'Sync') + VALIDATE,
    'Only protocol-to-validation integration against a synthetic manager. Does not validate real NetBird issuer guarantees.')
add('TestAPIWrapsTransportErrorsWithoutTheToken', 'mixed',
    'Combines an actual OS TCP refusal and production error wrapping with precancelled-context handling and malformed-PAT local guards.',
    'Test opens a loopback listener, records its address and closes it. API.do GET invokes real http.Transport and must expose url.Error/ECONNREFUSED without token/auth leakage. Already-cancelled POST checks cancellation; invalid PAT variants fail NewAPI before transport construction/use.',
    'Cancelled context and malformed token cases are independent local branches (lines 241-252).', refs(M+'api.go', 'NewAPI', 'do', 'ValidateManagementURL'),
    'No successful HTTP protocol exchange. Address reuse races and OS error identity remain runtime-unknown; no execution reviewed.')
add('TestAddressPlanRejectedBeforeManagerRequests', 'unit',
    'Core assertion explicitly requires invalid address plans to fail without entering the real HTTP server.',
    'Mutated GRU NetworkRange reaches Sync -> Desired.Validate and returns an address plan error before API.do. The independent handler request counter must remain zero.',
    'All cases are pre-request address-plan guards; httptest.NewServer setup is incidental.', refs(M+'sync.go', 'Sync') + VALIDATE + refs(M+'api.go', 'NewAPI'),
    'Server existence supplies no integration credit when no request is permitted.')
add('TestCLIReadsPATSafelyAndPrintsNoSecrets', 'mixed',
    'Combines protected PAT file reads/symlink checks and actual HTTP CLI output assertions with standalone local argument guards.',
    'Run -> readToken opens nofollow PAT files, validates mode/type and reads bytes; inventory/Sync/Prune traverse API.do to real loopback manager. Output/mutation assertions check secrecy and dry-run behavior. Loose file, symlink and directory fixtures are rejected through actual filesystem checks. Too-short offline threshold and unknown command are separate argument branches.',
    'Lines 316-323 independently reject offline threshold and unknown command before production I/O.', HTTP + SYNC + PRUNE + CLI + refs(M+'inventory.go', 'ReadInventory'),
    'No live Vault or CLI executable process; Run is called directly. Fake manager state/PAT are synthetic.', 'Temp PAT files and environment PAT are supplied by test; filesystem flags and HTTP transport are production implementations.')
add('TestCLIReportOmitsSummaryWhenTheRunFailed', 'integration',
    'CLI failure output depends on a genuine HTTP 500 response received through production transport.',
    'Synthetic handler failStatus is set to 500; direct Run sync dry/apply and prune apply call API.do, consume server status and return errors. Assertions forbid success-like no changes summary.',
    'No independent argument-only assertion block.', HTTP + SYNC + PRUNE + CLI,
    'Fault is synthetic server HTTP status; no live manager outage or separate CLI process.', 'failStatus changes real handler response, rather than returning a stubbed Go API error.')
add('TestLoopPrunesEvenWhenSyncRefuses', 'integration',
    'A real HTTP observation makes Sync refuse while the same production cycle still deletes the stale peer through HTTP.',
    'Duplicate SFO groups are fetched by Sync; Loop joins that refusal with subsequent Prune, which GETs peers and DELETEs stale replaced revision through API.do. Assertions require error mentioning sfo-servers and absent stale handler record.',
    'No independent pre-I/O argument branch; credentials/leader callbacks only control entry.', HTTP + SYNC + PRUNE + LOOP,
    'Synthetic records/callback leadership; no real account or authority store.', 'Leader always true and Token returns fixture PAT; no Vault call.')
add('TestLoopSkipsFollowersAndSurvivesFailuresAndPanics', 'mixed',
    'Independent local follower/token-error/panic branches are combined with a successful recovery cycle that performs genuine HTTP reconciliation.',
    'Run with leader=false must never call Token or mutate manager. Direct cycles consume injected token failure, then panic, then valid PAT. Final cycle reaches Sync/Prune -> API.do and creates actual handler-side canonical group and DNS zone, with captured log output.',
    'Follower read counter, injected Vault error and panic recovery are standalone local-only branches (lines 326-361).', HTTP + SYNC + PRUNE + LOOP,
    'No genuine Vault error or production distributed leadership; actual I/O scope is loopback HTTP only.', 'Token returns errors.New, panics, then fixture bytes. Leader atomic callback and logger are injected.')

for name, rationale, trace in [
    ('TestPruneDeletesReplacedRevisionsAndRestoresSlotNames', 'Dry-run, selective delete/rename/SSH flags and idempotence are verified after production HTTP reads and writes.', 'Prune GETs group/peer state, plans six changes without mutations, then applies DELETE/PUT requests through API.do. Handler records and peer/name/DNS/SSH fields prove old/orphan removal, retained peers and second-run no-op.'),
    ('TestPruneLeavesAmbiguousSlotsAlone', 'Ambiguous-slot safety is asserted from real HTTP peer observations with no mutations.', 'Prune reads two conflicting connected identities through API.do; report requires one warning and zero changes. Local decision consumes protocol data rather than a direct injected inventory.'),
    ('TestPruneLeavesSlotWhoseNameIsHeldByAnotherConnectedPeerAlone', 'Contested-name safety is checked across repeated real HTTP observations and retained handler state.', 'Two Prune runs fetch peers/group over HTTP; each must produce one warning, no changes/mutations. Assertions ensure stale/live/squatter all remain and neither live name is changed.'),
    ('TestPruneRenamesAPeerAfterItsRenamedNode', 'Canonical node renaming is an actual handler-side effect of a production HTTP peer update.', 'Prune reads legacy name/group/IP, performs API.do PUT and assertions read peer name and DNSLabel from mutated server state.'),
    ('TestPruneReportsDNSLabelHeldOutsideTheServersGroup', 'The DNS-label conflict is exposed by an actual peer update and response/readback path.', 'Fixture reserves ts-gru-2 label on an outside peer. Prune/API.do updates the admitted live peer; fake freeLabel models conflict, resulting DNS verification returns the asserted error while live Name is still canonical.'),
]:
    add(name, 'integration', rationale, trace, 'No independent pre-I/O target branch; synthetic time/peer fixtures are setup.', HTTP + PRUNE + VALIDATE + refs(M+'fake_test.go', 'addPeer', 'peer', 'freeLabel', 'peerView'), 'Synthetic NetBird peer/name/allocation semantics over real loopback HTTP; no real overlay/daemon behavior.', 'PruneOptions.Now fixes comparison time where supplied; fixture peers are in-memory handler state.')

add('TestRemovePeersDeletesOnlyDisconnectedServerPeersOfTheNamedSlots', 'mixed',
    'Combines unknown-slot local rejection with real HTTP dry-run/selective deletion and state retention assertions.',
    'Remove rejects controller-z before reading inventory. Valid slot and all-slot paths GET peers/group via API.do, preserve connected/outside peers, and DELETE only disconnected scoped server records; handler readback checks each retained/deleted identity.',
    'Lines 434-436 independently reject unknown slot before HTTP.', HTTP + refs(M+'peers.go', 'Remove', 'serverPeers', 'serversGroupID') + VALIDATE,
    'Synthetic manager records and connection flags; no actual host decommissioning.')
add('TestSetupKeyCommandWritesTheKeyOnlyToANewOwnerOnlyFile', 'mixed',
    'Combines actual HTTP key creation and protected file readback/refusal with independent malformed CLI argument guards.',
    'Run setup-key dry-run reads HTTP groups/keys and must leave output absent. Apply creates new output file with O_EXCL/0600 then CreateServerSetupKey issues HTTP group/key POST. ReadFile/Stat require exact secret and permissions, handler key fields require least scope, existing file must refuse before any new mutation. Other regional group is created/key-scoped via HTTP.',
    'Final malformed command arrays are pre-I/O argument checks. Noncanonical nobody servers group is also a local scope guard.', HTTP + CLI + KEY + refs(M+'cli.go', 'createSetupKeyFile') + VALIDATE,
    'Synthetic secret returned by HTTP server; no real server enrollment or Vault delivery.')
add('TestSyncIgnoresRevokedSetupKeysWithTheServerKeyName', 'integration',
    'Revoked-key handling is asserted on production HTTP inventory decoding and report generation.',
    'Fixture adds revoked same-name setup key. Sync dry-run GETs manager state including /setup-keys via API.do; verifySetupKey skips revoked entry and must yield zero warnings.',
    'No standalone pre-request branch.', HTTP + SYNC,
    'Only synthetic setup-key protocol shapes; no actual credential revocation.')
add('TestSyncWarnsAboutSetupKeyWithoutChangingIt', 'integration',
    'Warnings derive from actual HTTP setup-key inventory with no apply mutations.',
    'Fixture mutates auto_groups and state; Sync(false) reads through API.do and verifySetupKey must produce two warnings.',
    'No independent input-only target branch.', HTTP + SYNC,
    'Synthetic setup-key state; no real credential validation or mutation.')
add('TestSyncWarnsAboutUnmanagedPoliciesAndBroadSetupKeysWithoutChangingThem', 'integration',
    'Report and preservation assertions require genuine HTTP reconciliation of manager policy/key state.',
    'Sync apply reads all policies/keys through API.do, converges managed resources, then second Sync yields no changes with exact unmanaged-policy/broad-key warnings. Assertions inspect retained enabled Default policy and two-group setup key.',
    'No independent pre-I/O argument guard.', HTTP + SYNC,
    'Synthetic HTTP account semantics; no live policy enforcement or actual overlay access.')
add('TestValidateRejectsSlotsOutsideThePrivateCellSubnetAndUnknownAliasRoles', 'unit',
    'Every core assertion is a local Desired validation rejection before any manager request.',
    'Mutated slot subnet/public address, role aliases, historical group references or duplicate aliases reach Sync -> d.Validate and fail before first API.do. len(f.mutations)==0 checks no writes, while connected Sync source proves no reads either.',
    'All nine scenarios exercise pre-I/O Desired invariants; fake server setup is incidental.', refs(M+'sync.go', 'Sync') + VALIDATE + refs(M+'api.go', 'NewAPI') + refs(M+'fake_test.go', 'newFakeManager', 'api'),
    'No HTTP observation or external service participates in asserted guard decisions.')
add('TestPodmanManagerSyncAndPrune', 'unresolved',
    'Intended end-to-end assertion path is statically blocked by a region/subnet mismatch before the first production Prune request; incidental real setup cannot establish the core category.',
    'Root starts Podman NetBird/server/client fixtures and seeds legacy API state, then d := GRU() retains cell gru-1 while replacing Resource.Address with cellSubnet() = 10.252.<random>.128/25. Prune immediately calls Desired.Validate -> networkplan.ValidateRegion. GRU reservation is 10.251.0.0/16; SFO owns 10.252.0.0/16. Validate rejects subnet and root t.Fatal at lines 64-65 precedes intended dry-run/Sync/Prune/traffic/enrollment assertions. Those original assertions remain retained obligations.',
    'Blocking guard is local; genuine Podman/HTTP setup occurs before it but does not fulfill downstream core assertions.',
    refs(M+'podman_integration_test.go', 'newPodmanStack', 'cellSubnet', 'slotIP', 'podman', 'startServer', 'serviceUserToken', 'seedLegacy', 'verifySynced', 'verifyTraffic', 'client', 'call') + PRUNE + VALIDATE + refs(M+'sync.go', 'Sync'),
    'Requires source clarification/correction under separate authorization and later execution; no execution has verified or contradicted static reachability. TS_NETBIRD_PODMAN=1 and installed podman are explicit runtime gates.',
    'Real external Podman setup is described only as source intent; no containers/processes were launched during this review.')
add('TestDirectPeerDNSRefusesAmbiguousOrInvalidAdmissionBeforeWrites', 'integration',
    'The refusal assertions integrate HTTP group/peer observation decoding with admission validation and zero writes.',
    'Synthetic name/address/duplicate-peer/issuer faults are serialized by actual loopback handler. Sync obtains groups and (where applicable) peers through API.do; issuer guard or admittedPeerRecords rejects prior to p.run. Assertions require error and no recorded HTTP mutations.',
    'Validation is local after actual production HTTP reads, not an injected inventory API. There is no separate pre-request Desired-validation case.', HTTP + SYNC + VALIDATE,
    'Does not qualify real identity admission, JWT validation or actual DNS service; handler records are synthetic.')
add('TestDirectPeerPolicyAndDNSConvergeWithoutTSOps', 'integration',
    'Policy/DNS least-scope, retained identity/unowned state and drift recovery assertions depend on actual production HTTP reads/writes.',
    'Seeded manager is observed via API.do. Sync migrates historical fabric policies, account settings and custom-zone records by HTTP while preserving routing/groups/unmanaged settings. Test inspects handler policy ports/direction/sources, direct-overlay records and alias exclusions; repeated Sync must be no-op, injected DNS TTL/stale-record drift reconverges, empty observed peer membership must retain existing DNS.',
    'Fixture and local output comparisons verify server-side effects; no independent input-only branch.', HTTP + SYNC + refs(M+'sync.go', 'verifyHistoricalFabric') + refs(M+'fake_test.go', 'serveRecords') + VALIDATE,
    'Actual loopback transport with synthetic NetBird state; no actual DNS resolution, policy enforcement, peer traffic or NATS.', 'seedHistoricalFabric and direct handler-record mutations introduce realistic shape/drift, not real remote controllers.')
add('TestHistoricalFabricConflictStopsBeforeAccountWrites', 'integration',
    'Conflict refusal is driven by policy data read through real HTTP and asserts no destructive account mutation.',
    'Sync fetches groups/peers/policies using API.do; verifyHistoricalFabric rejects custom ports 22 before p.run can apply planned group/account writes. Error text and empty handler mutation log are required.',
    'Local shape validation consumes real HTTP observations; no separate pre-request branch.', HTTP + SYNC + refs(M+'sync.go', 'verifyHistoricalFabric') + refs(M+'policy_integration_test.go', 'seedHistoricalFabric'),
    'Synthetic policy definitions; no real policy enforcement or traffic.')
add('TestImageInputCLIWritesAllRegionsWithoutPeerMaps', 'integration',
    'Production output-file creation and a separately reopened/decoded client configuration establish actual filesystem effect/readback.',
    'Test writes real regional plan files. Run image-input -> writeImageInput reads plan, writes netbird.json with scoped secret reference. client.ValidateConfig independently os.Open/ReadAll/decodes it; assertions require OCI region, exact secretID and no peer map for GRU and SFO.',
    'Field comparisons validate bytes read from the real output file; no independent guard-only block.', CLI + refs(M+'imageinput.go', 'writeImageInput') + refs('internal/netbird/client/client.go', 'ValidateConfig') + refs('internal/netbird/config.go', 'ValidSecretID', 'ValidatePeerNames'),
    'No actual OCI secret read, image build, enrollment, DNS or cloud resources; plans and secret OCIDs are synthetic.')
add('TestAuditContinuesAfterFailureButCannotPassMissingOrMixedNodes', 'unit',
    'All audit observations/errors are supplied by an injected Fetch callback, with in-memory output and local selection validation.',
    'Audit creates per-node deadline contexts and invokes callback; callback records visited nodes, returns unreachable then observation(publicIP). inspect rejects mismatched evidence. Assertions require two FAIL outputs and all nodes visited; invalid node lists reject locally before a nil Fetch can execute.',
    'Entire root is local control-flow/deadline/output/selection validation.', refs(P+'audit.go', 'Audit', 'inspect') + refs(P+'audit_test.go', 'observation'),
    'No SSH process, remote host, socket inventory or live daemon.', 'Fetch is synthetic Go closure; observation constructs status, PID, address and ss strings.')
add('TestInspectRequiresLiveConsistentDaemonEvidence', 'unit',
    'Despite its name, core assertions decode and inspect entirely synthetic JSON/string evidence.',
    'observation builds snapshot structures and fake PID/address/socket text; inspect parses and compares it against expected IP. Table exercises daemon/endpoint/relay/transport/address/PID/mixed-socket and malformed/missing evidence branches.',
    'Every assertion is local decoding/evidence validation.', refs(P+'audit.go', 'inspect') + refs(P+'audit_test.go', 'observation'),
    'No real daemon, DNS lookup, process, socket, SSH or network activity.')
add('TestRemoteCommandStreamsLargeSocketInventory', 'integration',
    'Large-inventory streaming/filtering and subprocess failure propagation run the production shell pipeline through actual OS processes and filesystem inputs.',
    'Test writes status/socket files >128KiB and executable command stubs to TempDir. exec.CommandContext launches sh -c RemoteCommand (only executable path substituted), actual jq filters stdout fed from fake netbird/systemctl/getent/ss. inspect and decoded output require exactly 2048 matching PID sockets, no nginx/PID1234; ss exit1 must make command.Output fail.',
    'Fixture-size check is only a prerequisite; actual streaming is the target.', refs(P+'audit.go', 'inspect') + refs(P+'audit_test.go', 'observation'),
    'Requires jq (skips if absent). No real sockets/NetBird/systemd/getent/SSH; process boundary is shell+jq plus command stubs.',
    'PATH command stubs cat real fixture files or printf synthetic status. ss status controlled by environment; real process exit/pipe behavior remains.')
add('TestCopyOutputDropsOnlyTheLeadingLoginLine', 'unit',
    'copyOutput is exercised only with strings.Reader and bytes.Buffer.',
    'Table compares exact output after optional leading authenticated marker removal, preservation of later/partial markers and empty/short input.',
    'Entire root is in-memory stream/string transformation.', refs(S+'sshlogin.go', 'copyOutput'), 'No subprocess or real terminal/pipe.')
add('TestDestinationNamingAPeerUsesItsNetBirdIP', 'unit',
    'Address family parsing and argv rewriting use synthetic status bytes without calling Addresses or spawning NetBird.',
    'peerAddresses/allPeerAddresses parse literal JSON; withPeerAddress maps only intended destination while preserving original argument slices. Invalid JSON/IP and unknown/remote-command cases retain correct arguments.',
    'All assertions are local parser/map/slice behavior.', refs(S+'sshlogin.go', 'peerAddresses', 'ipv4Addresses', 'allPeerAddresses', 'withPeerAddress'),
    'No status subprocess, DNS lookup, live peer or SSH session.')
add('TestDeviceLoginAnswersTheDexForms', 'integration',
    'Success and exact POST count depend on production HTTP cookie/form/redirect handling against a real loopback server.',
    'deviceLogin GETs/POSTs verification, email/password with csrf+cookie and approval forms from newFakeDex. Handler approves only correct fields/session; final approved flag and posts==3 are external protocol effect oracles.',
    'No independent local-only branch.', DEX,
    'Synthetic Dex pages and credentials; no genuine Dex/NetBird/OIDC/Vault, TLS or production auth policy.')
add('TestDeviceLoginRefusesMFAAndOtherOrigins', 'mixed',
    'Combines actual HTTP MFA/foreign-redirect refusal with independent pre-I/O rejection of a foreign initial verification URL.',
    'MFA fixture returns TOTP form after real password HTTP POST. Foreign initial URL is rejected by sameOrigin before a request; other.posts stays0. Redirecting fixture sends real HTTP Location to other origin; redirect guard refuses and other.posts stays0.',
    'Lines 136-139 foreign initial URL assertion is local pre-request origin validation.', DEX,
    'Synthetic HTTP IdP/redirect servers; no real MFA challenge or TLS. other.posts measures POSTs, not all GETs.', 'mfa/elsewhere fields alter actual handler pages/responses.')
add('TestDeviceLoginStopsWhenAFormComesBack', 'integration',
    'Wrong-code/password safety requires actual HTTP form round trips and observed POST counts.',
    'newFakeDex echoes rejected form after production deviceLogin submits wrong code/password. Returned error, approved=false and <=2 posts show it stops without repeated credentials.',
    'Both table variants traverse real HTTP; no independent input-only branch.', DEX,
    'Synthetic IdP pages/credentials only; no real authentication or rate-limit policy.')
add('TestHelperNetBird', 'unresolved',
    'Allocated Test root is an env-gated subprocess fixture without independent assertions; its callers own the actual assertions.',
    'Without SSHLOGIN_HELPER_DEX it immediately returns. With env it prints login instructions, polls approved via http.Get, emits synthetic session output and exits based on stdin length. No t.Fatal/Error/assertion independently validates a product behavior in this root. Caller tests exercise this helper, but do not transfer original-root classification credit.',
    'No independent assertion block exists.', refs(S+'sshlogin_test.go', 'approved') + refs(S+'sshlogin.go', 'run'),
    'Unresolved source-helper-no-independent-assertion. Remains an original retained obligation, no retirement or category credit.', 'Fixture stands in for netbird ssh; polling and subprocess effects support callers only.')
add('TestRunRejectsBadArgumentsBeforeVaultOrNetBird', 'unit',
    'All invalid-argument/help assertions return before Vault loading or NetBird process entry.',
    'Run rejects the misplaced -L flag during parsing; Session rejects missing/incorrect vault ID and empty command or session arguments before calling Addresses or using credentials. --help returns flag.ErrHelp handling with expected password secret help text.',
    'Entire root is pre-I/O CLI argument/shape validation and help formatting.', refs(S+'sshlogin.go', 'Run', 'Session'),
    'No credential retrieval, status command or SSH subprocess.')
add('TestRunSignsInOnlyWhenNetBirdAsks', 'integration',
    'Both fresh/cached assertions cross an actual subprocess and pipes; fresh login additionally traverses real loopback HTTP forms.',
    'run launches the test binary selecting TestHelperNetBird, connects actual stdin/stdout/stderr pipes and detects verification URL. Fresh helper polls fake Dex; signIn invokes injected credential callback and deviceLogin HTTP, then child returns exact session bytes. Cached helper skips auth while still executing actual child/pipes; callback count, stderr, output and approval are asserted.',
    'Callback count is conditioned on actual child protocol, not an independent pure unit branch.', PROCESS + DEX,
    'Test binary impersonates NetBird; credentials are stub callback. No Vault fetch, real netbird binary or real SSH/PTY.', 'TestHelperNetBird uses SSHLOGIN_HELPER_DEX/CACHED env to simulate protocol; actual process/pipe/HTTP remain.')
add('TestRunStopsTheClientWhenLoginFailsAndKeepsItsExitStatus', 'integration',
    'Error sanitization/timely child termination and cached session exit status depend on actual subprocess/pipes and HTTP rejection.',
    'run launches helper blocked waiting for login; deviceLogin submits wrong password to real loopback IdP, then run kills/waits child on auth failure. Error must be sanitized and elapsed<=4s. Cached child reads odd stdin and os.Exit(1); run must preserve netbird ssh exit status1.',
    'No independent pre-I/O target branch; both cases use actual subprocess state.', PROCESS + DEX,
    'Fake netbird binary and credential callback; no actual SSH server/NetBird/Vault or production latency guarantee.', 'Wrong credentials supplied by callback; cached helper exits based on synthetic stdin length.')
add('TestVerificationURL', 'unit',
    'Only local line parsing extracts or rejects verification links.',
    'verificationURL receives table strings; exact returned URL is compared with expected, including no-code/browser-instruction/waiting cases.',
    'Entire root is in-memory line/URL validation.', refs(S+'sshlogin.go', 'verificationURL'), 'No HTTP request or child process.')

roots = []
bounded_spans = []
for meta in inputs['batch']['bounded_scope_reads']:
    raw = '\n'.join(source['current:' + meta['path']][meta['start_line']-1:meta['end_line']])
    assert digest(raw.encode()) == meta['span_sha256']
    bounded_spans.append(dict(**meta, verified=True, git_blob=pins['current:'+meta['path']]['git_blob']))
for allocated in inputs['batch']['roots']:
    name, path = allocated['current_name'], allocated['path']
    decision = spec[name].copy()
    dependencies = decision.pop('dependencies')
    evidence = []
    for version, meta, expected_name in [('current', allocated['source_declaration'], name), ('baseline', allocated['baseline_declaration'], allocated['original_name'])]:
        lines = source[version + ':' + path]
        start, end = meta['start_line'], meta['end_line']
        raw = '\n'.join(lines[start-1:end])
        assert lines[start-1].startswith('func ' + expected_name + '(')
        assert lines[end-1] == '}'
        assert digest(raw.encode()) == meta['sha256']
        pin = pins[version + ':' + path]
        evidence.append(dict(version=version, function=expected_name, start_line=start, end_line=end,
                             raw_declaration_sha256=digest(raw.encode()), git_blob=pin['git_blob'],
                             git_mode=pin['git_mode'], file_sha256=pin['sha256'], file_bytes=pin['bytes'],
                             archived_as=pin['archived_as']))
    assert evidence[0]['raw_declaration_sha256'] == allocated['current_declaration_sha256']
    assert evidence[1]['raw_declaration_sha256'] == allocated['original_declaration_sha256']
    start, end = evidence[0]['start_line'], evidence[0]['end_line']
    lines = source['current:' + path]
    assertion_sites = []
    for i in range(start-1, end):
        if not re.search(r'\bt\.(?:Fatalf?|Errorf?)\(', lines[i]) and not re.match(r'\s*assert ', lines[i]):
            continue
        # Keep the full root declaration as exact context; this index makes every
        # failure site and the nearest controlling if easy to find independently.
        candidates = []
        for j in range(start-1, i):
            if not re.match(r'\s*if\b', lines[j]):
                continue
            indent = lines[j][:len(lines[j])-len(lines[j].lstrip('\t'))]
            if len(indent) >= len(lines[i])-len(lines[i].lstrip('\t')):
                continue
            # Gofmt's block closing brace has the same indentation as its if.
            # Discard completed preceding guards instead of implying enclosure.
            close = next((k for k in range(j+1,end) if lines[k].startswith(indent+'}') and not lines[k].startswith(indent+'\t')), end)
            if close >= i:
                candidates.append(j)
        condition_start = candidates[-1] if candidates else i
        assertion_sites.append(dict(failure_line=i+1, exact_failure_text=lines[i],
                                    condition_context_start_line=condition_start+1,
                                    condition_context_end_line=i+1,
                                    exact_condition_context='\n'.join(lines[condition_start:i+1]),
                                    context_note='Nearest unclosed less-indented if where present; otherwise failure site itself. Complete declaration below retains all loops/selects/closures and multiline branches.'))
    citations = []
    seen = set()
    for dep in dependencies:
        if dep not in seen:
            seen.add(dep)
            citations.append(cite(*dep))
    # The remote shell pipeline is a constant, not a Go function.
    if name == 'TestRemoteCommandStreamsLargeSocketInventory':
        cpath=P+'audit.go'; clines=source['current:'+cpath]
        cs=next(i+1 for i,l in enumerate(clines) if l.startswith('const RemoteCommand'))
        ce=next(i+1 for i in range(cs,len(clines)) if clines[i].endswith('`'))
        citations.append(dict(path=cpath, symbol='RemoteCommand', start_line=cs, end_line=ce,
                              git_blob=pins['current:'+cpath]['git_blob'], exact_text='\n'.join(clines[cs-1:ce]), role='actual subprocess pipeline'))
    root = dict(root_id=allocated['root_id'], path=path, original_name=allocated['original_name'],
                current_name=name, survival_state=allocated['state'], kind=allocated['kind'],
                baseline=evidence[1], current=evidence[0], **decision,
                exact_assertion_sites=assertion_sites,
                exact_current_declaration_with_all_assertions='\n'.join(f'{i+1}: {lines[i]}' for i in range(start-1,end)),
                connected_declarations=citations, runtime_result=UNKNOWN,
                retirement_authorized=False, retirement_delta=0,
                safety_obligations='Every original declaration, subtest, assertion, failure branch and connected helper assertion remains retained. Changed current bodies do not retire any baseline obligation. No assertion removed, weakened, executed or credited as runtime evidence.',
                classification_credit='candidate_only_pending_independent_peer_review_and_separate_ledger_promotion')
    roots.append(root)

assert len(roots) == 48 == inputs['batch']['root_count']
assert len({r['root_id'] for r in roots}) == 48
assert set(spec) == {r['current_name'] for r in roots}
counts = dict(collections.Counter(r['category'] for r in roots))
assert sum(counts.values()) == 48
assert counts['unresolved'] == 2
qa = dict(path=str(qa_path), sha256=digest(qa_path.read_bytes()))
report = dict(
    schema='source-only-original-root-classification-v1',
    report_state='CANDIDATE_SOURCE_REVIEW_ONLY_NO_LEDGER_PROMOTION',
    batch='NET48', owner='/root/net/service',
    allocation_manifest=dict(path=inputs['allocation_manifest'], sha256=inputs['allocation_sha256'],
                             dispatch_note='Original allocation proposal says HOLD; separate ROOT-authorized QA reactivation supplied in task history. Scope remains exactly NET48.'),
    allocation_acceptance=qa,
    source_commit=CURRENT, source_tree=inputs['source_tree'], baseline_commit=BASELINE,
    baseline_tree=git('rev-parse', BASELINE+'^{tree}').decode().strip(),
    hash_convention='Raw UTF-8 declaration bytes from func through column-zero closing brace, excluding following LF. Exact immutable Git blob bytes checked before hashing.',
    definitions=dict(integration='Core asserted target materially crosses a genuine storage, server/client, OS process/filesystem or protocol boundary. Synthetic service semantics limit scope.',
                     unit='Core assertion is local validation, decoding, selection, concurrency/timing/logging or a synthetic/stub feed. External setup alone is incidental.',
                     mixed='Distinct meaningful local-only and genuine boundary assertion blocks coexist in the original root.',
                     unresolved='Connected source does not establish a category for the retained original obligation; separate from runtime UNKNOWN.'),
    counts=dict(allocated_original_roots=48, candidates_by_category=counts,
                resolved_source_candidates=sum(counts[c] for c in ('integration','unit','mixed')),
                reviewed_unresolved_candidates=counts['unresolved'], retirement_delta=0, ledger_promotion_delta=0),
    accepted_global_counts_unchanged=dict(originals=4319, retained=4300, retired=19,
                                         classified=171, integration=100, unit=43, mixed=28,
                                         unadjudicated=4129, prior_reviewed_unresolved_within_unadjudicated=10),
    all_five_categories='OPEN', runtime_result=UNKNOWN, retirement_authorized=False,
    ledger_promotion_authorized=False, qualification_7330_transfer=False,
    source_pins=list(pins.values()),
    allocated_bounded_scope_reads=bounded_spans,
    verification=dict(allocation_sha256=True, source_tree=True, exact_48_literal_root_ids=True,
                      baseline_and_current_96_declaration_hashes=True,
                      copied_source_bytes_match_immutable_git_blobs=True,
                      every_cited_file_pinned=True, six_bounded_scope_span_hashes=True, category_counts_exhaust_allocation=True,
                      method='Python static data/hash/coverage assertions and read-only Git only; no Go/build/format/lint/test/runtime/cloud/listener/lock action or application/test subprocess launch.'),
    findings=[dict(root_id=next(r['root_id'] for r in roots if r['current_name']=='TestPodmanManagerSyncAndPrune'),
                   code='source-unreachable-regional-subnet-mismatch', severity='classification_blocker',
                   detail='GRU Desired retains gru-1; test subnet 10.252.<random>.128/25 lies outside GRU 10.251/16. First Prune fails Desired.Validate/networkplan.ValidateRegion before intended assertions. Real setup remains incidental.',
                   action='Preserve unresolved candidate; source owner/QA must separately review the exact blocker. No source fix authorized here.'),
              dict(root_id=next(r['root_id'] for r in roots if r['current_name']=='TestHelperNetBird'),
                   code='source-helper-no-independent-assertion', severity='classification_blocker',
                   detail='Literal allocated root is a subprocess fixture with no independent assertions; no caller credit transferred.',
                   action='Preserve original root and unresolved candidate as already agreed with QA.')],
    qualification_limits=[
        'No receipts reviewed and no test execution occurred. Source categories do not imply PASS, production readiness, retirement or coverage qualification.',
        'Real loopback HTTP is distinguished from synthetic direct Go feeds. Handler data is fabricated; asserting protocol reads/writes is limited to client/serialization/control-flow integration.',
        'OCI clients use a raw synthetic provider and actual SDK HTTP. Loopback Server checks Authorization presence only, not cryptographic signature validity, IAM, TLS or real service persistence/retention guarantees.',
        'Embedded NATS uses a single local server and test storage. No production mesh, quorum partition or regional failover is qualified.',
        'Shell/Python/test-binary subprocesses and temp-file readback are real boundaries in source intent; stubs do not establish live NetBird, Dex, SSH, DNS, systemd or OCI service behavior.',
        'The Podman gate and jq availability skip remain explicit source conditions. Source review invoked neither executable and changed no gate.',
        'Only these 48 original roots receive candidate entries. Helpers and connected dependencies receive citations, never additional original-root counts.'
    ], roots=roots)

out = ROOT/'classification.json'
out.write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
readme = f'''# NET48 candidate source classification

Review `classification.json` for all 48 literal original roots at `{CURRENT}` (tree `{inputs['source_tree']}`).

1. Candidates: {counts['integration']} integration, {counts['unit']} unit, {counts['mixed']} mixed, {counts['unresolved']} unresolved; total 48.
2. Unresolved: `TestHelperNetBird` has no independent assertion. `TestPodmanManagerSyncAndPrune` keeps GRU while assigning a 10.252/16 subnet, so first Prune validation blocks the intended assertions.
3. All 96 baseline/current declaration hashes and copied immutable Git blobs verified. Exact root declarations, assertion/failure indexes, helper/production spans and file pins are retained in JSON and `source/`.
4. Runtime: `{UNKNOWN}`. No Go/build/format/test/lint/runtime/cloud or process/listener/lock action. Retirement false; delta 0; no ledger promotion or 7330 qualification transfer. Global accepted counts remain 171 classified / 4129 unadjudicated / 19 retired.
5. Next: independently peer-review the candidates and both unresolved findings. A separate accepted promotion is required for any ledger count change.

Allocation: `{inputs['allocation_manifest']}` SHA256 `{inputs['allocation_sha256']}`.
Baseline: `{BASELINE}`. QA acceptance: `{qa['path']}` SHA256 `{qa['sha256']}`.

`SHA256SUMS` covers every report file except itself; files are sealed 0444 and directories 0555. The builder is retained as static report-generation provenance; its execution only reads pinned Git objects and writes this exclusive report directory. No source, Git, allocation or ledger file was changed.
'''
(ROOT/'README.md').write_text(readme)
print(json.dumps(dict(report=str(out), sha256=digest(out.read_bytes()), counts=counts, file_pins=len(pins), assertion_sites=sum(len(r['exact_assertion_sites']) for r in roots)),sort_keys=True))
