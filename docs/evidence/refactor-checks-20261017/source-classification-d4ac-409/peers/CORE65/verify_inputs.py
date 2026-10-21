import collections
import hashlib
import json
from pathlib import Path
import stat
import subprocess

HERE = Path(__file__).resolve().parent
OWNER = Path('/tmp/ts-core65-d4ac-source-classification-Yz6avQIW')
GIT = '/run/current-system/sw/bin/git'
REPO = '/home/mariogk/Projects/TerraScale/ts-orchestrator'
CURRENT = 'd4ac68882716e7cfb14afca2f88ad596a38041af'
BASE = 'bfca60368f60d2da67f9016d1d489317ae8749c8'

def digest(data):
    return hashlib.sha256(data).hexdigest()

def git(*args):
    return subprocess.check_output([GIT, '-C', REPO, *args])

def pinned(path, expected):
    data = Path(path).read_bytes()
    assert digest(data) == expected, path
    return data

owner_data = pinned(OWNER / 'classification.json', '0639658db2c0974d670483f31a4a644f7de32c97f7bb574f08d661975577612f')
owner = json.loads(owner_data)
allocation = json.loads(pinned('/tmp/ts-d4ac-next300-allocation-proposal-raxuc07l/allocation.json', '032cb201e692326da7274b12d7dfd15512b1befd325cce375188ae0447ca2523'))
pinned('/tmp/ts-d4ac-next300-allocation-proposal-raxuc07l/OUTPUT-CONTRACT.md', '83ddfcf95cb31877ab2c40cab8ee8963e7491287e4780f29d9d6fcefabcd852b')
pinned('/tmp/ts-qa-next300-allocation-independent-2ivixd0j/review.json', '4a1acb09fb4e6ee22f2d9eeb6ea610ed627c7de40851937676dfdc5bc96436a3')
pinned(OWNER / 'SHA256SUMS', 'f7703365046eea86107dcda0ec2ecd27f82f07c54324782df4b3b3335d1ec92f')
assert git('rev-parse', CURRENT + '^{tree}').decode().strip() == '3b73a410a025bd8050ad1d42e54acc7d5eda4b82'
assert owner['source_commit'] == CURRENT and owner['baseline_commit'] == BASE
batch = next(b for b in allocation['batches'] if b['batch_id'] == 'CORE65')
allocated = {r['root_id']: r for r in batch['roots']}
roots = {r['root_id']: r for r in owner['roots']}
assert len(allocated) == len(roots) == len(owner['roots']) == 65
assert allocated.keys() == roots.keys()

tree_entries = {}
for commit in (CURRENT, BASE):
    tree_entries[commit] = {}
    for entry in git('ls-tree', '-rz', commit).split(b'\0'):
        if not entry:
            continue
        meta, path = entry.split(b'\t', 1)
        mode, kind, blob = meta.decode().split()
        tree_entries[commit][path.decode()] = (mode, kind, blob)

files = {}
for pin in owner['source_file_pins']:
    commit, path = pin['commit'], pin['path']
    mode, kind, blob = tree_entries[commit][path]
    assert (mode, kind, blob) == (pin['git_mode'], 'blob', pin['git_blob']), pin
    data = git('show', commit + ':' + path)
    assert digest(data) == pin['sha256'] and len(data) == pin['bytes'], pin
    assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == blob
    local = HERE / 'source' / ('current' if commit == CURRENT else 'baseline') / path
    assert local.read_bytes() == data, local
    files[commit + ':' + path] = (pin, data.splitlines())
assert len(files) == len(owner['source_file_pins']) == 108
supplemental = json.loads((HERE / 'supplemental-pins.json').read_text())
assert len(supplemental) == 1
for pin in supplemental:
    commit, path = pin['commit'], pin['path']
    assert tree_entries[commit][path] == (pin['git_mode'], 'blob', pin['git_blob'])
    data = git('show', commit + ':' + path)
    assert digest(data) == pin['sha256'] and len(data) == pin['bytes']
    assert (HERE / 'source/current' / path).read_bytes() == data
    files[commit + ':' + path] = (pin, data.splitlines())

def check_span(citation, numbered=None, declaration=False):
    pin, lines = files[citation['file_pin']]
    assert pin['path'] == citation['path'] and pin['git_blob'] == citation['git_blob']
    start, end = citation['start_line'], citation['end_line']
    assert 1 <= start <= end <= len(lines)
    selected = lines[start-1:end]
    assert digest(b'\n'.join(selected)) == citation['sha256'], citation
    if declaration:
        assert selected[0].startswith(b'func ')
        assert selected[-1] == b'}' or len(selected) == 1
    if numbered is not None:
        assert numbered == [{'line': n, 'text': lines[n-1].decode()} for n in range(start, end+1)], citation

for root_id, root in roots.items():
    original = allocated[root_id]
    for key in ('path', 'original_name', 'current_name', 'original_declaration_sha256', 'current_declaration_sha256', 'baseline_declaration', 'source_declaration', 'state', 'kind'):
        assert root[key] == original[key], (root_id, key)
    check_span(root['current_declaration'], root['assertion_source'], True)
    check_span(root['baseline_declaration_reconfirmed'], declaration=True)
    assert root['current_declaration']['sha256'] == root['current_declaration_sha256'] == root['current_raw_declaration_sha256_reconfirmed']
    assert root['baseline_declaration_reconfirmed']['sha256'] == root['original_declaration_sha256'] == root['baseline_raw_declaration_sha256_reconfirmed']
    assert root['current_declaration']['git_blob'] == root['current_test_git_blob']
    assert root['baseline_declaration_reconfirmed']['git_blob'] == root['baseline_test_git_blob']
    assert root['runtime'] == 'UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION'
    assert root['retirement_authorized'] is False and root['safety_obligations_retained'] is True
    _, lines = files[root['current_declaration']['file_pin']]
    for site in root['assertion_sites']:
        assert lines[site['line']-1].decode().strip() == site['text']
        assert root['current_declaration']['start_line'] <= site['condition_context_start'] <= site['line'] <= site['condition_context_end'] <= root['current_declaration']['end_line']
    for key in ('setup_helper_citations', 'connected_production_citations'):
        for citation in root[key]:
            check_span(citation, declaration=True)
            indexed = owner['citation_index'][citation['citation_id']]
            assert {k: v for k, v in citation.items() if k != 'citation_id'} == {k: v for k, v in indexed.items() if k != 'source_lines'}

for citation in owner['citation_index'].values():
    check_span(citation, citation['source_lines'], True)
supplemental_lines = files[CURRENT + ':internal/swarmruntime/function_capacity.go'][1]
assert supplemental_lines[20].startswith(b'func (i FunctionServiceIntent) PendingCapacity(')
assert supplemental_lines[76] == b'}'

bounded = 0
for span in batch['bounded_scope_reads']:
    lines = files[CURRENT + ':' + span['path']][1]
    assert digest(b'\n'.join(lines[span['start_line']-1:span['end_line']])) == span['span_sha256']
    bounded += 1

checked = set()
for line in (OWNER / 'SHA256SUMS').read_text().splitlines():
    expected, path = line.split('  ', 1)
    member = OWNER / path
    assert member.resolve().is_relative_to(OWNER)
    assert digest(member.read_bytes()) == expected, member
    checked.add(member)
owner_files = {p for p in OWNER.rglob('*') if p.is_file()}
assert owner_files == checked | {OWNER / 'SHA256SUMS'}
assert stat.S_IMODE(OWNER.stat().st_mode) == 0o555
for p in OWNER.rglob('*'):
    assert stat.S_IMODE(p.stat().st_mode) == (0o555 if p.is_dir() else 0o444), p
counts = dict(collections.Counter(r['category'] for r in roots.values()))
assert counts == owner['counts'] == {'integration': 13, 'unit': 36, 'mixed': 15, 'unresolved': 1}
result = dict(state='PASS', roots=65, declaration_pins=130, source_file_pins=108,
    supplemental_source_file_pins=1, total_peer_source_file_pins=109, supplemental_citation_spans=1, total_peer_citation_spans=401,
    citation_index_spans=len(owner['citation_index']), assertion_sites=sum(len(r['assertion_sites']) for r in roots.values()),
    referenced_citation_occurrences=sum(len(r[k]) for r in roots.values() for k in ('setup_helper_citations','connected_production_citations')),
    allocation_bounded_spans=bounded, owner_checksummed_files=len(checked), owner_sealed_files=len(owner_files),
    owner_packet_seal='0444 files / 0555 directories', counts=counts,
    git_objects='blob IDs, modes, bytes and SHA256 verified from immutable Git objects',
    runtime='UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION', execution=False, retirement_delta=0)
print(json.dumps(result, indent=2))
