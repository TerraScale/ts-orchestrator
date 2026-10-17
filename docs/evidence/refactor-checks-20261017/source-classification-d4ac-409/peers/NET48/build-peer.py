import json,hashlib,subprocess,collections,copy,re
from pathlib import Path
OUT=Path(__file__).parent
OWNER=Path('/tmp/ts-net48-d4ac-source-classification-k9shja9e')
owner=json.loads((OWNER/'classification.json').read_bytes())
sha=lambda b:hashlib.sha256(b).hexdigest()
rationales=dict(line.split('|',1) for line in (OUT/'peer-rationales.txt').read_text().splitlines())
assert len(rationales)==48
roots=[];failure_count=0
for original in owner['roots']:
 r=copy.deepcopy(original)
 r['owner_candidate_category']=r['category']
 r['owner_rationale']=r.pop('rationale')
 r['peer_category']=r['category']
 r['peer_decision']='accept_unresolved' if r['category']=='unresolved' else 'accept'
 r['rationale']=rationales[r['current_name']]
 r['peer_evidence_verification']='Canonical current and baseline full declarations read; hashes, complete numbered source, assertion-site text/conditions and connected spans independently checked against immutable Git.'
 r['classification_credit']='independently_peer_reviewed_source_candidate_only_separate_ledger_promotion_required'
 assert r['baseline']['raw_declaration_sha256']==r['current']['raw_declaration_sha256']
 roots.append(r)
for pin in owner['source_pins']:
 b=subprocess.check_output(['/run/current-system/sw/bin/git','show',pin['commit']+':'+pin['path']])
 assert sha(b)==pin['sha256'] and len(b)==pin['bytes']
 archive=OUT/pin['archived_as'];archive.parent.mkdir(parents=True,exist_ok=True)
 with archive.open('xb') as f:f.write(b)
for r in roots:
 b=(OUT/r['current']['archived_as']).read_text().splitlines()
 reported={s['failure_line'] for s in r['exact_assertion_sites']}
 scanned={i for i in range(r['current']['start_line'],r['current']['end_line']+1) if re.search(r'\bt\.(?:Fatalf?|Errorf?|FailNow|Fail)\s*\(',b[i-1]) or re.match(r'\s*assert\s',b[i-1])}
 assert scanned==reported,(r['root_id'],scanned,reported)
 failure_count+=len(scanned)
counts=dict(collections.Counter(r['peer_category'] for r in roots))
assert counts=={'integration':26,'unit':11,'mixed':9,'unresolved':2}
review={
 'schema':'ts-source-classification-independent-peer-v1',
 'batch':'NET48','reviewer':'/root/data/executor_hooks','dispatched_by':'/root/qa_integrator',
 'review_state':'SEALED_INDEPENDENT_PEER_CANDIDATE_NO_LEDGER_PROMOTION',
 'source_commit':owner['source_commit'],'source_tree':owner['source_tree'],
 'baseline_commit':owner['baseline_commit'],'baseline_tree':owner['baseline_tree'],
 'owner_packet':{'path':str(OWNER/'classification.json'),'sha256':sha((OWNER/'classification.json').read_bytes()),'checksum_manifest_path':str(OWNER/'SHA256SUMS'),'checksum_manifest_sha256':sha((OWNER/'SHA256SUMS').read_bytes())},
 'allocation_manifest':owner['allocation_manifest'],'allocation_acceptance':owner['allocation_acceptance'],
 'output_contract':{'path':'/tmp/ts-d4ac-next300-allocation-proposal-raxuc07l/OUTPUT-CONTRACT.md','sha256':'83ddfcf95cb31877ab2c40cab8ee8963e7491287e4780f29d9d6fcefabcd852b'},
 'counts':{'allocated_original_roots':48,'peer_accepted_entries':48,'category_corrections':0,'candidates_by_category':counts,'resolved_source_candidates':46,'reviewed_unresolved_candidates':2,'retirement_delta':0,'ledger_promotion_delta':0},
 'definitions':owner['definitions'],
 'protocol_boundary_decision':'A direct synthetic Go API/feed remains unit. These accepted loopback-client paths invoke production API.do/http.Transport and consume an actual encoded HTTP response or handler-side committed write that materially supports the asserted refusal/warning/convergence. Accept only that protocol/client/serialization/control-flow scope. Synthetic NetBird/OCI/Dex semantics are not validated. A setup server, pre-I/O guard, or local snapshot alone earns no integration credit.',
 'review_method':{'source':'All 48 complete current declarations read from canonical git show; all baseline/current raw declarations independently hashed. Connected production/helper paths read to determine real boundary versus incidental setup; blocked Podman downstream helpers confer no credit.','integrity':'verify.py reproduces independent full-file bytes/SHA256/Git blob hash, archive equality, 96 declaration hashes, 262 assertion texts/conditions, 755 connected spans, six bounded spans, exact ordered allocation and checksum entries. A separate scan finds exactly the same 262 t.Fatal/Error/Fail and embedded Python assert sites.','git_modes':'Source mode fields are retained from the sealed owner pin set. Content bytes, length and Git blob identities were independently rederived; Git modes were not independently rederived.','execution':'Only read-only Git and Python static report/hash work. No Go/build/test/lint/format/runtime, application/test child, process/listener/lock/cloud action, source/worktree/Git/ledger mutation or agent spawn.'},
 'verification':json.loads((OUT/'integrity-verification.json').read_bytes()),
 'independent_failure_site_scan':{'sites':failure_count,'omitted_or_extra_sites':0,'scope':'All allocated current root declarations; helper assertions retained in connected full-file archives.'},
 'roots':roots,'source_pins':owner['source_pins'],'allocated_bounded_scope_reads':owner['allocated_bounded_scope_reads'],
 'findings':copy.deepcopy(owner['findings']),
 'qualification_limits':owner['qualification_limits']+['No package buildability, actual runtime result or current7330 qualification is inferred from body-path source categories.','Source modes are sealed-owner metadata; peer content identity is independently verified.'],
 'runtime_result':'UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION','retirement_authorized':False,'retirement_delta':0,
 'ledger_promotion_authorized':False,'qualification_7330_transfer':False,
 'accepted_global_counts_unchanged':True,'all_five_categories':'OPEN',
 'safety_obligations':'All 48 original roots and every original assertion remain retained exactly. No assertion was removed, weakened, executed, retired or credited as runtime evidence.'
}
(OUT/'review.json').write_text(json.dumps(review,indent=2,sort_keys=True)+'\n')
(OUT/'README.md').write_text("""NET48 independent peer review: 48 entries accepted; no category corrections.

Counts: 26 integration, 11 unit, 9 mixed, 2 unresolved. These are source candidates only. Accepted ledger counts are unchanged; runtime UNKNOWN; retirement 0; current7330 transfer false.

The unresolved Podman root retains GRU's cell while using an SFO-reserved subnet; Desired.Validate rejects before its intended assertions. The unresolved TestHelperNetBird root has no independent product assertion. Both obligations remain retained.

Actual HTTP response/write paths qualify only the production client/protocol/control-flow boundary. Synthetic NetBird/OCI/Dex semantics, direct Go callbacks, incidental servers, authority local snapshots and pre-I/O guards receive no broader credit. Real file/process paths have explicit effect/readback traces in each root. No package build or test result is inferred.

review.json contains literal IDs, independent per-root decisions/rationales, verified owner evidence, exact assertions and connected citations. source/ contains fresh canonical Git copies of all 50 pinned files. integrity-verification.json records 96 root declarations, 262 assertion text/condition pairs, 755 connected spans, six bounded spans and ordered 48-ID verification. Independent failure-site scanning found exactly the same 262 sites, with none omitted. verify.py and build-peer.py preserve the static reproduction method. Git mode values are retained sealed-owner metadata; content SHA256/bytes/Git blob identities were independently rederived.

Only read-only Git and Python static report/hash operations were performed. No source/Git/ledger changes, Go/build/test/lint/format/runtime, application/test child execution, process/listener/lock/cloud action or new agent. Files 0444 and directories 0555; SHA256SUMS covers every other report file.
""")
print(json.dumps({'roots':len(roots),'counts':counts,'failure_sites':failure_count,'report_sha256':sha((OUT/'review.json').read_bytes())},indent=2))
