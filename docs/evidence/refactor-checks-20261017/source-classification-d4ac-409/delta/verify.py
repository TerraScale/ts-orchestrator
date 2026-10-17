import collections, csv, hashlib, json, subprocess, sys
from pathlib import Path

packet = Path(sys.argv[1])
repo = '/tmp/ts-refactor-main-union-3d9a933e'
sha = lambda b: hashlib.sha256(b).hexdigest()
proposal = json.loads((packet / 'proposal.json').read_bytes())
manifest = json.loads((packet / 'inputs-manifest.json').read_bytes())
objects = {}
for entry in manifest['inputs']:
    path = Path(entry['path'])
    data = path.read_bytes()
    assert sha(data) == entry['sha256'] and len(data) == entry['bytes'], str(path)
    if path.suffix == '.json': objects[str(path)] = json.loads(data)
allocation = objects[manifest['allocation_path']]
prior = objects[manifest['prior_accepted_delta_path']]
rootid = lambda r: r['path'] + '::' + r['original_name']
excluded = {
    'accepted102': {rootid(r) for r in prior['preexisting_classified102_roots']},
    'accepted69': {r['root_id'] for r in prior['proposed_classified_roots']},
    'retired19': {rootid(r) for r in prior['prior_retired19_roots']},
    'reviewed_unresolved10': {r['root_id'] for r in prior['reviewed_unresolved_roots']},
}
assert {k: sorted(v) for k, v in excluded.items()} == proposal['excluded_sets']
assert excluded == {k: set(v) for k, v in allocation['excluded_original_root_ids'].items()}
assert sorted(map(len, excluded.values())) == [10, 19, 69, 102]
ex = set().union(*excluded.values())
assert len(ex) == 200
inventory = {rootid(r): r for r in csv.DictReader(Path(manifest['inventory_path']).read_text().splitlines(), delimiter='\t') if r['kind'] == 'test'}
assert len(inventory) == 4319
assert {k for k, r in inventory.items() if r['state'] == 'qualified_retired'} == excluded['retired19']
cache = {}
def source(commit, path):
    key = (commit, path)
    if key not in cache:
        cache[key] = subprocess.check_output(['git', '--no-optional-locks', '-C', repo, 'show', commit + ':' + path])
    return cache[key]
def declaration_hash(record, which, commit):
    span = record[which]
    raw = b'\n'.join(source(commit, record['path']).split(b'\n')[span['start_line'] - 1:span['end_line']])
    assert sha(raw) == span['sha256'], record['root_id']
    return sha(raw)
def peer_hashes(r):
    if 'original_declaration_sha256' in r: return r['original_declaration_sha256'], r['current_declaration_sha256']
    if 'baseline' in r: return r['baseline']['raw_declaration_sha256'], r['current']['raw_declaration_sha256']
    return r['baseline_declaration']['span_sha256'], r['current_declaration']['span_sha256']
seen = set()
actual = collections.Counter()
changes = []
for batch in proposal['batches']:
    author = objects[batch['candidate_input']]
    peer = objects[batch['peer_input']]
    candidate_sha = next(e['sha256'] for e in manifest['inputs'] if e['path'] == batch['candidate_input'])
    owner_pin = peer.get('owner_packet', peer.get('owner_report', peer.get('candidate')))
    assert owner_pin.get('sha256', owner_pin.get('classification_sha256')) == candidate_sha
    assert author['source_commit'] == peer['source_commit'] == allocation['source_commit'] == proposal['source_commit']
    assert author['source_tree'] == peer['source_tree'] == allocation['source_tree'] == proposal['source_tree']
    ars = author.get('roots', author.get('originals'))
    prs = peer.get('roots', peer.get('originals'))
    amap = {r['root_id']: r for r in ars}
    pmap = {r['root_id']: r for r in prs}
    allocated = next(b for b in allocation['batches'] if b['batch_id'] == batch['batch_id'])
    allocated_map = {r['root_id']: r for r in allocated['roots']}
    selected = [r for r in proposal['roots'] if r['batch_id'] == batch['batch_id']]
    assert len(ars) == len(prs) == len(selected) == len(amap) == len(pmap) == allocated['root_count']
    assert set(amap) == set(pmap) == set(allocated_map) == {r['root_id'] for r in selected}
    assert not seen & set(amap) and not ex & set(amap)
    seen.update(amap)
    counts = collections.Counter()
    for r in selected:
        rid = r['root_id']; a = amap[rid]; p = pmap[rid]; frozen = allocated_map[rid]
        assert rid == rootid(a) == rootid(p)
        old = declaration_hash(frozen, 'baseline_declaration', allocation['baseline_commit'])
        new = declaration_hash(frozen, 'source_declaration', allocation['source_commit'])
        assert (old, new) == peer_hashes(p) == peer_hashes(a)
        assert old == inventory[rid]['original_declaration_sha256'] == r['original_declaration_sha256']
        assert new == inventory[rid]['current_declaration_sha256'] == r['current_declaration_sha256']
        cat = p.get('peer_category', p.get('category'))
        assert cat == r['proposed_classification'] and a['category'] == r['author_classification']
        assert cat in {'integration', 'unit', 'mixed', 'unresolved'}
        assert r['classification_credit_if_promoted'] == (0 if cat == 'unresolved' else 1)
        assert r['runtime_qualification'] == 'UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION'
        assert not a['retirement_authorized'] and not p['retirement_authorized'] and not r['retirement_authorized']
        assert r['safety_obligations_retained'] is True
        if cat != a['category']: changes.append((rid, a['category'], cat))
        counts[cat] += 1
    assert dict(counts) == batch['proposed_counts']
    actual.update(counts)
assert len(seen) == 300 and len(proposal['roots']) == 300
assert actual == {'integration':84, 'unit':117, 'mixed':37, 'unresolved':62}
assert changes == [('internal/capacity/usage_test.go::TestAuthenticatedAPIAndRegionalClient', 'mixed', 'integration')]
assert len(proposal['controlling_corrections']) == 3
for correction in proposal['controlling_corrections']:
    assert correction['adjudication'] == 'ACCEPTED_REQUIRED_BY_QA_PARENT'
    assert correction['root_id'] in seen
    peer = objects[correction['peer_input']]
    finding = peer['findings'][correction['finding_index']]
    assert correction['peer_finding'] == finding and finding['root_id'] == correction['root_id']
    for span in correction['source_spans']:
        raw = b'\n'.join(source(proposal['source_commit'], span['path']).split(b'\n')[span['start_line']-1:span['end_line']])
        assert sha(raw) == span['sha256'] and len(raw) == span['bytes']
assert proposal['before_counts'] == {'originals':4319,'retired':19,'retained':4300,'classified':171,'integration':100,'unit':43,'mixed':28,'unadjudicated':4129,'reviewed_unresolved_included':10}
assert proposal['proposed_delta'] == {'classified':238,'integration':84,'unit':117,'mixed':37,'reviewed_unresolved_separate':62,'retirement':0,'runtime':0}
assert proposal['proposed_after_counts'] == {'originals':4319,'retired':19,'retained':4300,'classified':409,'integration':184,'unit':160,'mixed':65,'unadjudicated':3891,'reviewed_unresolved_included':72,'other_unadjudicated':3819}
after = proposal['proposed_after_counts']; before = proposal['before_counts']
for key in ['classified','integration','unit','mixed']: assert after[key] == before[key] + proposal['proposed_delta'][key]
assert 184 + 160 + 65 == 409 and 409 + 3891 == 4300 and 72 + 3819 == 3891
assert proposal['state'] == 'FINAL_SOURCE_DELTA_PROPOSAL_NOT_ACCEPTED_NOT_APPLIED'
assert not proposal['complete'] and proposal['all_five_categories'] == 'OPEN'
assert not any(proposal['actual_mutations'].values())
assert proposal['source_qualification_transfer'] is False
for entry in manifest['inputs']: assert sha(Path(entry['path']).read_bytes()) == entry['sha256']
print(json.dumps({'status':'PASS_SOURCE_PROPOSAL_STRUCTURAL_AND_DECLARATION_VERIFICATION_ONLY','literal_roots':len(seen),'source_declaration_hashes_verified':600,'peer_category_changes':len(changes),'controlling_corrections':3,'proposed_classified':238,'reviewed_unresolved':62,'runtime':'UNKNOWN','shared_mutation':False},sort_keys=True))
