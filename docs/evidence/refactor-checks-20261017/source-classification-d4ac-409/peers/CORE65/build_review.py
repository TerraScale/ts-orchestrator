import collections
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
PYTHON = '/home/mariogk/.local/share/mise/installs/python/3.15.0/bin/python3.15'
OWNER = Path('/tmp/ts-core65-d4ac-source-classification-Yz6avQIW/classification.json')

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def write_json(name, value):
    (HERE / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')

verification = json.loads(subprocess.check_output([PYTHON, '-I', '-B', str(HERE / 'verify_inputs.py')]))
write_json('verification.json', verification)
owner = json.loads(OWNER.read_text())

# Each note describes the independently followed asserted target, not the test name.
notes = [
    'GetNode readback and AdmitNode GetNode/UpdateNode calls verify retained manager-owned labels and replay. Worker.ControlClient rejects locally before obtaining a control connection; that separate assertion makes the root mixed.',
    'Actual manager replica updates/CAS and service/task reads support scale results; the readiness callback sends HTTP to the local server. Unknown-cell SetPolicies rejects locally. Signals and executor readiness are supplied by synthetic fixtures, not measured production load.',
    'bootstrapVaultServer checks signed SDK requests over real local HTTP and retains create-once fixture values. startAcceptedNodeAt reads/publishes material, persists exact scope and upstream CA/node state, joins/reopens managers and reads manager identity. Those state/protocol effects support the target; the fixture is not live Vault or the genuine founder authority producer.',
    'The wrapper delegates to testContainerCredentialExpiry with container role. A child test process creates a real containerd/runc task and production shim logger, exits, and parent task Wait/status readback verifies credential deadline termination. No runtime result was observed by this review.',
    'Prepare writes/chowns/syncs/renames exact task files, ctr.Spec confirms readonly binding, task output/log/PID readbacks show material use, another executor recovers the same object, and Remove clears it. Separate invalid bindings, expiry, environment/path and immutable Update guards remain local; material authority is injected.',
    'The function-worker branch of testContainerCredentialExpiry launches the real child agent, containerd task and shim guardian. Parent wait/readback after agent exit targets the credential deadline. Its provider supplies fixture material, not production-issued secrets.',
    'effectSessionR3 starts three routed embedded servers with separate disk stores; authority runtime-effect writes/readbacks use the real control stream and R3. Successor recover restores holds, real NATS host request/reply authenticates the fresh session, and manager node/CA reads participate in stop-proof denial. The direct wrong-epoch challenge guard and in-memory terminal gate are separate local assertions. Forged proof denial does not establish a genuine stopped writer.',
    'taskset starts a copy of the test executable with a single allowed CPU; the wrapper checks process success and the exact one-CPU/750m allocatable output. Describe obtains containerd version and kernel capacity. The nested lifecycle is a helper execution and earns no additional root credit.',
    'Actual Prepare/Start/Wait/LoadContainer metadata, task PID, logs and removal checks target containerd/runc recovery after a child agent exits. Update compares immutable decoded task/fingerprint locally, so recovery assertions and the separate mutation guard warrant mixed.',
    'Function material is staged on disk, mounted readonly into an actual task, observed through task output, reconstructed from a second executor and removed. Local provider/binding/path/expiry/Update denials remain separate. BindFunctionMaterial validates Region with intentName; its fixture value "gru" does not encounter AdmitNode\'s canonical-region blocker.',
    'AdmitFunctionRegistryTask fetches actual manager task/service/node and immutable Config floor state, then rechecks those exact observations after current-function verification. Persisted assignment changes, renewal force-update and rollback support boundary assertions. Direct serviceSpec/VerifyTask mutation checks are local; current intent and signed qualification are generated fixture data.',
    'importCacheFixture writes content, exports/imports an OCI archive, and Prepare uses actual cached GetImage/content/native unpack plus task completion and corrupt metadata readbacks. Cached admission refusals use the injected resolver before cached object use. The denied resolver is a counter/error adapter, not a network deny rule; setup client.Pull may contact the base image registry. Zero adapter requests only scopes the prepared cached paths.',
    'The root connects over a second actual Unix gRPC socket; socketPeer reads SO_PEERCRED and verifyPeer reads /proc/PID/cgroup. Delegated upstream manager Create/Get/Update/CAS and denied requests traverse that socket. Refresh revocation is an atomic callback; no production authority-reader or fixed service-account admission is established.',
    'StartNode performs filesystem admission/CA/raft reads and writes, state flock exclusion and upstream TLS manager/worker join. Test parses actual certificate bytes and observes persistent service/node identity across restart and missing-state errors. Worker.ControlClient, pre-cancelled Wait and missing-discovery/admission input paths include independent local guards; idle executor task readiness is synthetic.',
    'reservePorts takes an actual host flock and enumerates containerd object labels. A new executor/controller recovers those reservations, rejects collision using retained metadata, and task removal permits the other prepared task. This is metadata ownership/reservation behavior, not proof of kernel TCP port exclusivity.',
    'ServiceBackends calls ObserveService/GetService/ListTasks and current GetNode for decisions. Healthy/unhealthy/redirect/closed-listener cases perform actual HTTP requests on a private host address. Missing inventory or invalid loopback targets avoid HTTP after manager reads. No NLB API mutation is exercised.',
    'NewOCIRegistryResolver calls PullSecrets.Resolve -> ReadCurrent using the real signed SDK TLS transport to the fixture, then VerifyCurrent and ctx.Err before returning credentials. Counters distinguish pre-Vault rejection from post-read injected cancellation/revocation. The missing final-verifier guard is local. This root does not perform a registry pull.',
    'privateRegistryResolver performs Resolve/Fetcher/Fetch against a real local TLS Basic-auth server; exact manifest bytes and authenticated requests are asserted. The credentials callback returns literal username/password values. Wrong image/Fetcher/Pusher and missing admission/node mismatch are local guards; missing authentication reaches the TLS registry. The Vault handler only fails on unintended access: this root has no successful Vault read, signed Vault response or rotation scenario.',
    'Resolve receives a Bearer challenge from a real TLS registry; registryTransport rejects the foreign HTTPS URL before delegating to its base transport. The supplied DialContext always dials the original fixture server, so the zero foreign-server counter alone is insufficient to prove routing to the foreign server was impossible. The production host/scheme check plus failed real authentication exchange supports integration; no live registry is involved.',
    'VerifyRegistryTask obtains actual manager GetTask even for forged payload and missing task ID; the nonempty wrong OperationID reaches comparison with fetched service/task annotations. Current/previous task acceptance and mutated floor refusal depend on retained GetNode/GetService/ListConfigs state. Qualification bytes and signatures are generated locally, and executor payload execution is synthetic.',
    'applySignedService reserves Config floors through real manager CAS and retains them across manager restart, then AwaitServiceReady probes actual HTTP and requests/observes manager rollback. Wrong region, corrupt proof bytes and nil probe include local rejection blocks. Allocation HTTP/disk and signed evidence are fixtures, not live OCI or qualification receipts.',
    'Unresolved is retained. runtime_integration_test.go31 sets cfg.Admission.Region="gru"; AdmitNode at46 reaches admission.go15 canonical catalog.IsOCIRegion rejection and t.Fatal at47–48 before service/restart assertions. catalog.CellForOCIRegion compares exact OCIRegion values; the GRU entry is "sa-saopaulo-1". Containerd/manager setup preceding this blocker is incidental and earns no integration credit.',
    'Actual manager service creation/read/update, scheduled task state and stale CAS failures support replica/idempotence/rollback assertions; health callback makes real HTTP requests. serviceExecutor/serviceController fabricate lifecycle transitions, so this proves manager behavior and HTTP observation, not application workload execution.',
    'The actual manager task list shows pending architecture mismatch, assignment after enrolling a matching worker, and placement changes after draining it. Tenant-scoped Wasm node admission is also real manager state. Executor readiness is synthetic; payloads for those architectures are not executed.',
    'Fixture child creates a real writer task and production shim logger, writes/renames signed state caches and reads task/PID/cgroup events after agent exit. Expiry/renewal/tamper cases exercise the guardian; guardian-death explicitly expects the writer still Running and cgroup populated after deadline. It preserves possible-writer risk and does not settle a durable hold.',
    'Controller/BindStateful missing-source/nil/uninitialized denials are local. The final client.Containers readback materially reaches actual containerd and requires no ts task object. That independent absence assertion makes the root mixed; it does not exercise admitted stateful execution.',
    'Manager Config reads/CAS preserve separate architecture floors, sibling family consistency and regression/legacy-floor checks. serviceAllocationStore uses signed SDK requests over local HTTP plus disk immutable reservations read back by verification. Neither architecture payload executes; the qualification evidence is fixture-constructed.',
    'Real manager service/tasks/Config floor and node drain/recovery readbacks support placement, one-slot pending capacity, update/rollback and sequencing. testFunctionCapacityManagerIntegration checks actual pending capacity around manager UpdateNode; revoked current-intent callback and direct VerifyTask/expired proof guards are local. Worker executor and qualification remain synthetic.',
    'startAcceptedWorkerAt reads an exact SDK secret version over fixture HTTP, checks digest/recipient, persists enrollment and joins upstream TLS using the token; actual certificate bytes are read. checkWorkerMembershipIntegration uses real JetStream Claim/Finish/RecordSwarmMembership CAS/reopened reads and manager availability/label readbacks. Parser/signature/transport tampering and ControlClient checks are local; signed enrollment is a test fixture.',
    'New prepares the supplied stateful spec/profile locally and accepts no generic profile for that stateful role. No actual HostView/Writer/Fencer boundary is reached.',
    'Observe walks synthetic HostStatus/Desired values, excludes dedicated records and subtracts system reserve using local arithmetic. No host inventory is fetched.',
    'Tick sees a changed fakeFencer epoch and resets local autoscale history; fakeCell supplies map/slice state. No persisted authority or committed service state is used.',
    'Injected signals and clock drive Collect/Decide and fakeCell desired writes. Assertion target is local replica/window planning, not production metrics acquisition.',
    'Converged synthetic desired/reports result in no fakeCell writes; Observe/CurrentRelease/PlanStep operate in memory.',
    'Synthetic serving stale and starting replicas drive PlanStep to retain the serving stale entry. fakeCell records only in-memory desired changes.',
    'Failure-domain constraints on synthetic hosts block the deterministic local placement plan; no scheduler server is involved.',
    'Local bounds and rollout rules shape additions/withdrawals captured by fakeCell. Both authority and host state are injected.',
    'fakeFencer follower/current/Guard refusals prevent fake writer calls. These are local failure hooks, not actual leader lease expiry.',
    'Observe/CurrentRelease filter synthetic other-environment generations before deriving a plan. No release store is read.',
    'Injected ApplyDesired failure preserves the local release template and avoids withdrawal. The failed writer is an in-memory callback.',
    'Synthetic stale/current/pending assignments preserve the remembered goal through partial rollout; no real manager/persistence is used.',
    'The local planner migrates synthetic allocations past a failure-domain cap using fakeCell read/write state.',
    'A cordoned synthetic host causes replacement/withdrawal entries in fakeCell. No host cordon API or task removal occurs.',
    'Dedicated managed placement/member fields exclude synthetic TerraBase records before local generic placement.',
    'The injected resettable signal source is reset after fake authority epoch change. This is a local callback/window assertion.',
    'An expired injected host session produces a replacement in fakeCell. No actual host disconnect or network timeout is observed.',
    'Synthetic readiness of a new release permits local stale allocation withdrawal; fakeCell is the only write target.',
    'Repeated local planning reaches the synthetic scale-up goal rather than truncating it to one surge. No payload is started.',
    'withCommitted charges one role\'s fake writes before the next role plans against the same synthetic host capacity.',
    'SetServices changes local spec ownership/history and affects subsequent fake writes. No configuration service is updated.',
    'prepareServices rejects invalid bounds/missing profiles without replacing the existing local service snapshot.',
    'Concurrent SetServices/Tick/Owns/Last calls exercise local synchronization with fakeCell/fakeFencer; goroutines do not add an external boundary.',
    'ReplacingWriter coordinates local locks/callbacks while SetServices removes a role, and fakeCell confirms no further writes. Sleep/goroutines are timing mechanisms only.',
    'Missing synthetic release and exhausted generation arithmetic produce local awaiting/hold outcomes; no persisted high-water store is accessed.',
    'ReleaseShape combines generation arithmetic with synthetic observation count and bounds. The function has no I/O.',
    'ReleaseResources callback returns synthetic retained resources, restoring local placement against fakeCell capacity. No retained release is fetched from a service.',
    'New/resourcesFor compares the spec\'s resource values against the supplied profile map and returns a local mismatch error.',
    'ServiceSpec.Validate/ValidateSpecs evaluate table inputs through pure name/bounds/kind/rollout/stateful/resource validators; no workload is installed.',
    'AppSpec.Validate rejects synthetic dependency names, update/placement and quorum combinations using local fields and slices.',
    'Artifact.Driver maps the local artifact enum to a driver; neither a driver process nor runtime is opened.',
    'validImage uses regexp matching and numeric port checks for reference strings. No DNS or registry I/O occurs.',
    'InArtifact checks tarball enum, argv and relativePath lexical normalization. It neither opens an archive nor reads a filesystem.',
    'MachineSpec.Validate applies artifact, lifecycle/entrypoint/path/size checks and JSON encoding to supplied values. No files/processes are created.',
    'Sample workload literals pass MachineSpec/AppSpec local validation. These examples are never deployed by the root.',
    'AppSpec.Strategy and Update.Unavailable derive enum/default values locally, including stateful rolling defaults.',
]
assert len(notes) == len(owner['roots']) == 65
supplemental_pins = json.loads((HERE / 'supplemental-pins.json').read_text())
supplemental_pin = supplemental_pins[0]
supplemental_lines = (HERE / 'source/current' / supplemental_pin['path']).read_text().splitlines()
supplemental_citation_id = 'internal/swarmruntime/function_capacity.go:21:PendingCapacity'
supplemental_citation = dict(path=supplemental_pin['path'], function='PendingCapacity', start_line=21, end_line=77,
    sha256=hashlib.sha256('\n'.join(supplemental_lines[20:77]).encode()).hexdigest(), git_blob=supplemental_pin['git_blob'],
    file_pin=owner['source_commit'] + ':' + supplemental_pin['path'])

roots = []
for ordinal, (root, note) in enumerate(zip(owner['roots'], notes, strict=True), 1):
    reviewed = dict(root)
    reviewed['ordinal'] = ordinal
    reviewed['owner_rationale'] = root['rationale']
    reviewed['rationale'] = note
    reviewed['peer_decision'] = 'CATEGORY_ACCEPTED_EVIDENCE_CORRECTION_REQUIRED' if ordinal == 18 else 'UNRESOLVED_ACCEPTED_NO_CREDIT' if ordinal == 22 else 'ACCEPTED'
    reviewed['category_changed'] = False
    reviewed['assertion_and_citation_verification'] = 'PASS: exact complete numbered assertion body, assertion sites, helper/production span bytes, line numbers and Git pins reconfirmed'
    reviewed['owner_evidence_correction_required'] = ordinal == 18
    if ordinal == 18:
        reviewed['local_only_assertion_blocks'] = 'Wrong image/repository/digest Resolve/Fetcher, Pusher, missing release admission and mismatched certificate node reject locally. Successful registry credentials are literal callback values; the Vault fixture is only a tripwire for unintended requests.'
    if ordinal == 14:
        reviewed['local_only_assertion_blocks'] += ' Missing discovery/admission input rejection is also local before network work.'
    if ordinal == 28:
        reviewed['connected_production_citations'] = root['connected_production_citations'] + [dict(supplemental_citation, citation_id=supplemental_citation_id)]
        reviewed['peer_supplement'] = 'Pinned complete PendingCapacity production path21–77 omitted from owner file set: current intent -> serviceSpec -> manager floor/ListServices/ListTasks -> task verification -> current intent/floor reread. No category change.'
    roots.append(reviewed)

report = {
    'schema': 'ts-source-classification-independent-peer-v1',
    'state': 'ACCEPT_CATEGORIES_WITH_REQUIRED_EVIDENCE_CORRECTION',
    'batch_id': 'CORE65', 'reviewer': '/root/net/service', 'owner': '/root/core/readiness',
    'review_method': 'Independent source reads of all65 actual assertion bodies and connected helper/production paths; immutable byte verification; no Go or runtime execution.',
    'source_commit': owner['source_commit'], 'source_tree': owner['source_tree'], 'baseline_commit': owner['baseline_commit'],
    'owner_packet': {'path': str(OWNER), 'sha256': sha(OWNER), 'checksums_sha256': sha(OWNER.parent / 'SHA256SUMS'), 'unchanged': True},
    'allocation_manifest': owner['allocation_manifest'], 'output_contract': owner['output_contract'],
    'allocation_acceptance': {'path': '/tmp/ts-qa-next300-allocation-independent-2ivixd0j/review.json', 'sha256': '4a1acb09fb4e6ee22f2d9eeb6ea610ed627c7de40851937676dfdc5bc96436a3'},
    'scope': owner['scope'], 'definitions': owner['definitions'],
    'counts': dict(collections.Counter(root['category'] for root in roots)),
    'category_changes': 0, 'required_rationale_corrections': 1,
    'accepted_accounting_unchanged': owner['accepted_accounting_unchanged'],
    'runtime': 'UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION',
    'retirement_authorized': False, 'retirement_delta': 0, 'safety_obligations_retained': True,
    'ledger_promotion_authorized': False, 'current7330_qualification_transfer': False,
    'all_five_parent_categories': 'OPEN', 'net48_packet_modified': False,
    'declaration_reconfirmation': owner['declaration_reconfirmation'],
    'verification': verification,
    'verification_script': {'path': 'verify_inputs.py', 'sha256': sha(HERE / 'verify_inputs.py')},
    'qualification_limits': owner['qualification_limits'] + [
        'Peer accepts source categories and the retained blocker only. Owner root18 rationale must be narrowed as recorded; original sealed owner packet is not edited.',
        'The foreign realm counter in root19 is read alongside the production host/scheme guard; fixture DialContext redirects every permitted transport dial to the original server.',
        'Root12 zero denied-adapter requests does not establish an operating-system egress deny policy; import setup pulls its base image.',
        'Root25 guardian-death leaves a possible writer. No signed stop receipt, durable hold settlement, production workload recovery or live authority is established by source reading.',
    ],
    'findings': [
        {'id': 'CORE65-PEER-001', 'severity': 'REQUIRED_EVIDENCE_WORDING_CORRECTION', 'root_id': roots[17]['root_id'], 'category': 'mixed', 'category_changed': False,
         'problem': 'Owner root18 rationale claims Vault-backed credentials, signed SDK Vault responses and rotation, but the successful path uses literal credentials and contains no rotation.',
         'required_replacement': roots[17]['rationale'],
         'evidence_spans': [
             {'path': roots[17]['path'], 'start_line': 33, 'end_line': 81, 'purpose': 'actual TLS Basic-auth registry exchange and byte/counter assertions'},
             {'path': roots[17]['path'], 'start_line': 58, 'end_line': 64, 'purpose': 'literal callback credentials'},
             {'path': roots[17]['path'], 'start_line': 93, 'end_line': 129, 'purpose': 'real no-auth registry failure followed by Vault tripwire and local pre-Vault guards'},
         ]},
        {'id': 'CORE65-PEER-BLOCKER-001', 'severity': 'UNRESOLVED_RETAINED', 'root_id': roots[21]['root_id'], 'category': 'unresolved',
         'reason': roots[21]['rationale'], 'credit': 0, 'source_fix_authorized': False},
    ],
    'roots': roots, 'source_file_pins': owner['source_file_pins'] + supplemental_pins,
    'owner_source_file_pins_verified': 108, 'peer_supplemental_file_pins': 1,
    'citation_index': dict(owner['citation_index'], **{supplemental_citation_id: dict(supplemental_citation, source_lines=[{'line': n, 'text': supplemental_lines[n-1]} for n in range(21,78)])}),
}
assert report['counts'] == {'integration': 13, 'unit': 36, 'mixed': 15, 'unresolved': 1}
assert sum(report['counts'].values()) == len({r['root_id'] for r in roots}) == 65
assert sum(r['owner_evidence_correction_required'] for r in roots) == 1
write_json('review.json', report)

(HERE / 'README.md').write_text('''# CORE65 independent source peer review

Use `review.json` for the per-root verdicts and exact evidence. Categories are accepted with one required evidence wording correction: **13 integration / 36 unit / 15 mixed / 1 unresolved**. Category changes: zero.

1. Root18 stays mixed. Its actual TLS Basic-auth registry exchange uses literal credential callback values. Remove successful Vault-read, signed Vault-response and rotation claims from its owner rationale.
2. Root22 stays unresolved. `Region="gru"` is rejected by canonical OCI-region admission before its service/restart assertions. Earlier real setup receives no category credit.
3. All65 IDs, 130 raw declarations, 108 owner source pins, 400 owner indexed citation spans, 3,885 owner citation references, 777 assertion-site records and four allocation scope spans passed independent static verification. Peer adds the complete pinned PendingCapacity production path for root28: total109 files/401 indexed spans. All six owner packet files remain sealed and unchanged.
4. Runtime remains UNKNOWN; retirement delta0; no accepted-ledger promotion or current7330 transfer. Existing accepted accounting remains unchanged and all five parent categories stay OPEN. NET48 is untouched.

`source/current` and `source/baseline` contain byte-exact immutable Git copies. `verify_inputs.py` reproduces static input verification; `verification.json` records its result. Every root retains complete numbered assertion source and verified helper/production citations, alongside an independent rationale. `build_review.py` records report construction.

No Go/build/test/gofmt/lint/runtime, project/Git/ledger mutation, cloud operation, listener or lock action ran. External module implementations and environmental Linux/root/containerd/cgroup prerequisites were not executed or qualified. No production authority or genuine qualification receipt follows from these source categories.
''')
print(json.dumps({'report': str(HERE / 'review.json'), 'sha256': sha(HERE / 'review.json'), 'counts': report['counts'], 'required_rationale_corrections': 1}, indent=2))
