import collections
import hashlib
import json
from pathlib import Path
import stat

HERE = Path(__file__).resolve().parent
report = json.loads((HERE / 'review.json').read_text())
owner = json.loads(Path(report['owner_packet']['path']).read_text())
assert hashlib.sha256(Path(report['owner_packet']['path']).read_bytes()).hexdigest() == report['owner_packet']['sha256']
assert len(report['roots']) == len({r['root_id'] for r in report['roots']}) == 65
assert {r['root_id'] for r in report['roots']} == {r['root_id'] for r in owner['roots']}
assert dict(collections.Counter(r['category'] for r in report['roots'])) == report['counts'] == owner['counts']
assert report['category_changes'] == report['retirement_delta'] == 0
assert report['retirement_authorized'] is False and report['ledger_promotion_authorized'] is False
assert report['current7330_qualification_transfer'] is False and report['net48_packet_modified'] is False
assert len(report['source_file_pins']) == 109 and len(report['citation_index']) == 401
assert report['required_rationale_corrections'] == sum(r['owner_evidence_correction_required'] for r in report['roots']) == 1

files = {}
for pin in report['source_file_pins']:
    phase = 'current' if pin['commit'] == report['source_commit'] else 'baseline'
    data = (HERE / 'source' / phase / pin['path']).read_bytes()
    assert len(data) == pin['bytes'] and hashlib.sha256(data).hexdigest() == pin['sha256']
    assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == pin['git_blob']
    files[pin['commit'] + ':' + pin['path']] = (pin, data.splitlines())

def citation_check(citation, numbered=None):
    pin, lines = files[citation['file_pin']]
    start, end = citation['start_line'], citation['end_line']
    assert pin['path'] == citation['path'] and pin['git_blob'] == citation['git_blob']
    assert hashlib.sha256(b'\n'.join(lines[start-1:end])).hexdigest() == citation['sha256']
    if numbered is not None:
        assert numbered == [{'line': n, 'text': lines[n-1].decode()} for n in range(start,end+1)]

for citation in report['citation_index'].values():
    citation_check(citation, citation['source_lines'])
for root, original in zip(report['roots'], owner['roots'], strict=True):
    assert root['root_id'] == original['root_id'] and root['category'] == original['category']
    assert root['runtime'] == report['runtime'] == 'UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION'
    assert root['safety_obligations_retained'] is True and root['retirement_authorized'] is False
    assert root['rationale'] != root['owner_rationale'] and root['category_changed'] is False
    citation_check(root['current_declaration'], root['assertion_source'])
    citation_check(root['baseline_declaration_reconfirmed'])
    for key in ('setup_helper_citations', 'connected_production_citations'):
        for citation in root[key]:
            citation_check(citation)
            indexed = report['citation_index'][citation['citation_id']]
            assert {k:v for k,v in citation.items() if k != 'citation_id'} == {k:v for k,v in indexed.items() if k != 'source_lines'}

sums = HERE / 'SHA256SUMS'
if sums.exists():
    members = set()
    for line in sums.read_text().splitlines():
        expected, relative = line.split('  ', 1)
        member = HERE / relative
        assert member.resolve().is_relative_to(HERE)
        assert hashlib.sha256(member.read_bytes()).hexdigest() == expected
        members.add(member)
    actual = {p for p in HERE.rglob('*') if p.is_file()}
    assert actual == members | {sums}
    assert stat.S_IMODE(HERE.stat().st_mode) == 0o555
    for path in HERE.rglob('*'):
        assert stat.S_IMODE(path.stat().st_mode) == (0o555 if path.is_dir() else 0o444)
    print(json.dumps({'state':'PASS_SEALED', 'checksummed_files':len(members), 'sealed_files':len(actual), 'review_sha256':hashlib.sha256((HERE/'review.json').read_bytes()).hexdigest(), 'checksums_sha256':hashlib.sha256(sums.read_bytes()).hexdigest()}))
else:
    print('PASS_UNSEALED: 65 roots / 130 declarations / 109 source pins / 401 spans; one rationale correction, zero category changes')
