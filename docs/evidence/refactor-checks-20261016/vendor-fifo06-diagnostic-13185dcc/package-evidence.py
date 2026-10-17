"""Metadata-only deterministic publication packaging; no subprocess or candidate invocation."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile

ROOT = Path('/tmp/ts-vendor-diagnostic-evidence-13185dcc-fifo06-v1')
PACKET = ROOT / 'packet'
DOCS = ROOT / 'docs' / 'vendor-fifo06-diagnostic-13185dcc'
SOURCE = Path('/tmp/ts-nats-vendor-migration-20261016/fifo06-diagnostic-dd038410')
DISPATCH = Path('/tmp/ts-nats-vendor-migration-20261016/fifo06-diagnostic-dispatch-13185dcc-v3')
PARSER = Path('/tmp/ts-nats-vendor-migration-20261016/fifo06-diagnostic-parser-selfcheck-13185dcc-v1')
PYTHON = '/home/mariogk/.local/share/mise/installs/python/3.15.0/bin/python3.15'
REVISION = '13185dcce9ef94f66359f0c5f740db93d5a5cb7e'
TREE = '223a8f501d826e6c02d81361ec28724f361b7d07'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return digest(Path(path).read_bytes())


def write_bytes(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def write_json(path, value):
    write_bytes(path, (json.dumps(value, indent=2, allow_nan=False) + '\n').encode())


assert os.getpriority(os.PRIO_PROCESS, 0) == 19
assert str(Path('/proc/self/exe').resolve()) == PYTHON
assert sha(PYTHON) == '71c06b34ffee909d39e88c70c317e7e4f02dd43a491932d1ce165c0b291f433f'
assert sys.dont_write_bytecode and sys.flags.isolated
blocked_attempts = []


def audit(event, args):
    if event in ('subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.fork',
                 'os.forkpty', 'os.exec', 'socket.__new__', 'socket.connect'):
        blocked_attempts.append(event)
        raise RuntimeError('Forbidden process/network action: ' + event)


sys.addaudithook(audit)
PACKET.mkdir()
DOCS.mkdir(parents=True)
plan = json.loads((DISPATCH / 'dispatch.json').read_text())
assert sha(DISPATCH / 'dispatch.json') == 'dc6df398ba3b0a54c8e3a07985563da012fce2b2429d19435e36cfdbde731237'
origins, groups = {}, {}


def add_tree(directory, group, expected_count):
    paths = sorted(path for path in directory.rglob('*') if path.is_file())
    assert len(paths) == expected_count, str(directory)
    for path in paths:
        assert not path.is_symlink()
        member = group + '/' + str(path.relative_to(directory))
        assert member not in origins
        origins[member] = path
    groups[group] = len(paths)


add_tree(SOURCE, 'diagnostic-source-only', 17)
add_tree(DISPATCH, 'dispatch-v3', 12)
add_tree(PARSER, 'parser-selfcheck', 47)
for key, path in plan['outputs'].items():
    origins['runtime/' + key + '/' + Path(path).name] = Path(path)
groups['runtime'] = 6
reviews = {
    '/tmp/ts-qa-fifo06-diagnostic-dispatch-review-13185dcc-a9da3336.json':
        'bf47d7f3875df566c84e6f735e6f623c2079746e538067c24e872b36c87fc7c6',
    '/tmp/ts-qa-fifo06-diagnostic-runtime-review-13185dcc-4099c6df.json':
        'e32dd10f548aa0ade995cfe9d29c7b38a26ca09b40243cdc7b489fcbf4cd386e',
}
for path, expected in reviews.items():
    assert sha(path) == expected
    origins['qa-reviews/' + Path(path).name] = Path(path)
groups['qa-reviews'] = 2
for suffix in ('json', 'md'):
    path = Path('/tmp/ts-vendor-union-dd038410-fifo06-source-diagnosis.' + suffix)
    origins['original-source-diagnosis/' + path.name] = path
groups['original-source-diagnosis'] = 2
for suffix in ('-receipt.json', '.jsonl'):
    path = Path('/tmp/ts-vendor-union-dd038410-fifo06-service-removal-refresh' + suffix)
    origins['original-fifo06-failure/' + path.name] = path
groups['original-fifo06-failure'] = 2
path = Path('/tmp/ts-nats-vendor-migration-20261016/remaining-fifo-source-dd038410/dispatch/receipt-recorder.py')
origins['prior-script-provenance/original-dd-receipt-recorder.py'] = path
for version in ('v1', 'v2'):
    paths = sorted(Path(str(DISPATCH).replace('-v3', '-' + version)).iterdir())
    assert len(paths) == 2
    for path in paths:
        origins['prior-script-provenance/' + version + '/' + path.name] = path
groups['prior-script-provenance'] = 5
origins['packaging/package-evidence.py'] = Path(__file__)
groups['packaging'] = 1
runtime_hashes = {
    'before': 'd2543f06afa1872e1ac7a09e4acb305ef4b55f9fd4b5e958c3791b7b7fc06140',
    'launch': '8165087a2a3129d6fd98696b718260b72c65d0c63cb799ee093589d1041c5ba9',
    'raw': '48e9052d62c66bfadfa0176093e45e624507e3df85cf2a59b5839b2b941777e4',
    'terminal': 'b2f5d0ab4ec5373f18556cada2ca3ce14b7ca54c206bc04846a2d6f575d93f06',
    'receipt': 'ddefd18a229489fbd1e120563508370fddf3790364635019d0b836c18e392ea2',
    'summary': '753c9a133331a2d8e1adf9262f9913a9755984286caa7ee3a465bd14424381f5',
}
for key, expected in runtime_hashes.items():
    assert sha(plan['outputs'][key]) == expected
receipt = json.loads(Path(plan['outputs']['receipt']).read_text())
assert receipt['session'] == 57605 and receipt['exit'] == 1
assert receipt['result']['scope_ok'] and not receipt['result']['passed']
assert not receipt['errors'] and receipt['released'] and not receipt['scoped_diagnostic_pass']
assert receipt['original_failure_disposition'] == 'RETAINED_FAIL_OPEN'
parser_receipt = json.loads((PARSER / 'selfcheck-receipt.json').read_text())
assert parser_receipt['status'] == 'PASS' and parser_receipt['case_count'] == parser_receipt['passed_cases'] == 40
assert sha(PARSER / 'SHA256SUMS') == '439809667d83bcf7baaf9bff564480524f0f5522e1fea9bc35431a6ef1c1210a'
for line in (PARSER / 'SHA256SUMS').read_text().splitlines():
    expected, member = line.split('  ', 1)
    assert sha(PARSER / member) == expected
watched = json.loads((PARSER / 'before-bindings.json').read_text())['sha256']
assert len(watched) == 522 and len(plan['preserved_sha256']) == 292
for path in origins.values():
    actual = sha(path)
    if str(path) in watched:
        assert actual == watched[str(path)], str(path)
    else:
        watched[str(path)] = actual
for path, expected in watched.items():
    assert sha(path) == expected, path
copies = []
for member, path in sorted(origins.items()):
    data = path.read_bytes()
    assert not data.startswith((b'\x7fELF', b'MZ')), 'Executable bytes forbidden: ' + str(path)
    write_bytes(PACKET / member, data)
    copies.append({'member': member, 'source_path': str(path), 'sha256': digest(data), 'bytes': len(data)})
assert len(copies) == 94
retained = plan['preserved_sha256']
retained_after = {path: sha(path) for path in retained}
assert retained_after == retained
write_json(PACKET / 'retained-original-bindings.json', {
    'count': 292, 'expected_sha256': retained, 'packaging_before_sha256': dict(retained),
    'packaging_after_copy_sha256': retained_after, 'all_unchanged': True,
    'copy_policy': 'All original292 bindings retained; original files never rewritten. Only explicitly listed inputs copied.',
})
provenance = {
    'operation': 'METADATA_EVIDENCE_PACKAGING_ONLY', 'revision': REVISION, 'tree': TREE,
    'base_revision': 'dd03841025c65c0a6c3350b3e8ad7c4d27eea77d',
    'input_groups': groups, 'exact_original_copy_count': len(copies), 'source_artifacts': copies,
    'watched_before_sha256': watched,
    'script_provenance': [{'member': item['member'], 'source_path': item['source_path'], 'sha256': item['sha256']}
                          for item in copies if item['member'].endswith('.py')],
    'interpreter': PYTHON, 'interpreter_sha256': sha(PYTHON), 'niceness': 19,
    'source_context': 'Accepted QA bindings retained byte-exact; packaging invokes no Go, Git, candidate scripts or runner.',
    'qualification': 'Diagnostic FAIL only; no passing credit or closed row; original FAIL OPEN; private source cause/interleaving/equivalence/removal/live/production unproved. No FIFO7/retry/extra runner authorization.',
    'binary_policy': 'No executable bytes included; paths/hashes remain references in original receipts.',
}
write_json(PACKET / 'provenance.json', provenance)
readme = """# FIFO6 diagnostic failure: sealed evidence

Frozen diagnostic source `13185dcce9ef94f66359f0c5f740db93d5a5cb7e`, tree `223a8f501d826e6c02d81361ec28724f361b7d07`, parent `dd03841025c65c0a6c3350b3e8ad7c4d27eea77d`. The 27 added diagnostic lines preserve all original workload/assertions and every other Go byte. The original failure remains retained and OPEN.

The single granted diagnostic run FAILED: broker session 57605, exit 1, exact root 2.51s/package 2.524s, wrapper 51.69544051698176s. All 140 raw JSON events retain exactly the granted root, no skips/extras; source/map/executable/environment/argv/cwd/wrapper/raw bindings are clean and Short-A was released. At index 1, expected svc.1 subject/payload but received svc.0/svc.0; mapped reply differs from the accepted i0 reply. Both public HTTP snapshots succeeded and each shows six subscriptions across CIDs 14,17,22,36,59,62 with one message apiece. This observes duplicate delivery and multiple subscriptions; it does not prove the specific private cleanup interleaving or SID ownership cause. Original source-diagnosis reports retain their historical uncertainty byte-exact.

This failure earns NO passing credit and closes NO inventory row. Private 2000-trial/SID/interleaving/race/equivalence/removal gaps stay open. No live cloud/production acceptance, FIFO7, retry, additional compile or runner is authorized. STOP/HOLD after failure. No fixture weakening, production correction or central closure is claimed.

The archive contains all 17 diagnostic source-only files, 12 immutable v3 dispatch files, 47 parser-check files with 40 accepted synthetic checks, all six actual runtime outputs, both independent QA review receipts, both original source-diagnosis files, exact copies of the original failed broker receipt/raw, original recorder and v1/v2 source-only draft scripts. All 292 original bindings are retained and rehashed without rewriting original evidence. Historical proposal and author-static-review statuses remain historical records, not current qualification claims. Script sources and origin/hash provenance are included; no binary executable bytes are packaged.

Packaging is metadata only, outside the repository. No Go/build/test/server/runner/lease/cloud/Git/source/integration/commit/push or new agent operation occurs. Source 155+155 and accepted watched bindings remain exact. Parent independently verifies this packet and copies this exact docs directory into the feature only after NSG publication.

MEMBERS.json lists payload hashes, excluding itself and root SHA256SUMS to avoid recursive hashing. Root SHA256SUMS also binds MEMBERS. External package.json/archive-verification.json list every archive member, including MEMBERS and SHA256SUMS. Sorted regular PAX members use mode0644, uid/gid/mtime0 and empty owners; gzip mtime0 level9. Independent in-memory second builds and complete tar/gzip rereads must be byte-identical. Archive checksums and script provenance are in package.json; local docs SHA256SUMS binds every docs file except itself.
"""
write_bytes(PACKET / 'README.md', readme.encode())
members = [{'member': str(path.relative_to(PACKET)), 'sha256': sha(path), 'bytes': path.stat().st_size}
           for path in sorted(PACKET.rglob('*')) if path.is_file()]
write_json(PACKET / 'MEMBERS.json', {'members': members, 'excludes': ['MEMBERS.json', 'SHA256SUMS']})
write_bytes(PACKET / 'SHA256SUMS', ''.join(sha(path) + '  ' + str(path.relative_to(PACKET)) + '\n'
                                        for path in sorted(PACKET.rglob('*')) if path.is_file()).encode())


def build_tar():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(PACKET.rglob('*')):
            if not path.is_file():
                continue
            assert not path.is_symlink()
            data = path.read_bytes()
            info = tarfile.TarInfo('packet/' + str(path.relative_to(PACKET)))
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def compress(data):
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode='wb', filename='', mtime=0, compresslevel=9) as archive:
        archive.write(data)
    return buffer.getvalue()


tar_bytes = build_tar()
archive_bytes = compress(tar_bytes)
assert build_tar() == tar_bytes and compress(build_tar()) == archive_bytes
assert gzip.decompress(archive_bytes) == tar_bytes and archive_bytes[4:8] == b'\0\0\0\0'
write_bytes(ROOT / 'packet.tar.gz', archive_bytes)
archive_members = []
with tarfile.open(fileobj=io.BytesIO(gzip.decompress((ROOT / 'packet.tar.gz').read_bytes())), mode='r:') as archive:
    for info in archive.getmembers():
        assert info.isfile() and info.name.startswith('packet/') and '..' not in Path(info.name).parts
        assert (info.mode, info.uid, info.gid, info.mtime, info.uname, info.gname) == (0o644, 0, 0, 0, '', '')
        data = archive.extractfile(info).read()
        relative = Path(info.name).relative_to('packet')
        assert data == (PACKET / relative).read_bytes()
        archive_members.append({'name': info.name, 'sha256': digest(data), 'bytes': len(data),
                                'mode': info.mode, 'mtime': info.mtime, 'uid': info.uid, 'gid': info.gid,
                                'uname': info.uname, 'gname': info.gname})
assert len(archive_members) == 99
assert [item['name'] for item in archive_members] == sorted(item['name'] for item in archive_members)
for line in (PACKET / 'SHA256SUMS').read_text().splitlines():
    expected, member = line.split('  ', 1)
    assert sha(PACKET / member) == expected
for path, expected in watched.items():
    assert sha(path) == expected, path
assert not blocked_attempts
verification = {
    'archive_path': str(ROOT / 'packet.tar.gz'), 'archive_sha256': digest(archive_bytes),
    'archive_bytes': len(archive_bytes), 'uncompressed_tar_sha256': digest(tar_bytes),
    'uncompressed_tar_bytes': len(tar_bytes), 'archive_member_count': len(archive_members),
    'archive_members': archive_members, 'deterministic_tar_rebuild_byte_equal': True,
    'deterministic_gzip_rebuild_byte_equal': True, 'gzip_roundtrip_exact_bytes': True,
    'safe_regular_members_only': True, 'all_members_match_packet': True,
    'all_input_hashes_unchanged': True, 'retained_original_bindings': 292,
    'watched_bindings_unchanged': len(watched), 'no_binary_executable_bytes': True,
    'blocked_process_network_attempts': blocked_attempts,
}
write_json(ROOT / 'archive-verification.json', verification)
write_bytes(DOCS / 'README.md', readme.encode())
write_bytes(DOCS / 'evidence.tar.gz', archive_bytes)
write_bytes(DOCS / 'package-evidence.py', Path(__file__).read_bytes())
write_bytes(DOCS / 'provenance.json', (PACKET / 'provenance.json').read_bytes())
write_bytes(DOCS / 'archive-verification.json', (ROOT / 'archive-verification.json').read_bytes())
write_json(DOCS / 'package.json', {
    'schema': 1, 'purpose': 'Accepted exact-scope FIFO6 diagnostic FAIL; no passing credit or closure',
    'candidate': REVISION, 'qualified_commit': None, 'diagnostic_commit': REVISION, 'diagnostic_tree': TREE,
    'sole_parent': 'dd03841025c65c0a6c3350b3e8ad7c4d27eea77d',
    **verification, 'input_groups': groups, 'source_artifact_count': 94,
    'session': 57605, 'exit': 1, 'diagnostic_outcome': 'FAIL', 'original_failure': 'RETAINED_FAIL_OPEN',
    'passing_coverage_credit': 0, 'closed_inventory_rows': 0, 'central_closures': 0,
    'private_source_cause': 'Unproved; public duplicate-delivery/multiple-subscription observations only',
    'selfcheck_cases_passed': 40, 'raw_runtime_jsonl_sha256': sha(plan['outputs']['raw']),
    'runtime_receipt_sha256': sha(plan['outputs']['receipt']), 'qa_reviews': reviews,
    'root_SHA256SUMS_sha256': sha(PACKET / 'SHA256SUMS'), 'MEMBERS_json_sha256': sha(PACKET / 'MEMBERS.json'),
    'packaging_script': {'path': str(Path(__file__)), 'sha256': sha(__file__), 'bytes': Path(__file__).stat().st_size},
    'docs_destination_relative': 'docs/evidence/refactor-checks-20261016/vendor-fifo06-diagnostic-13185dcc',
    'operations': 'Metadata packaging only; no Go/runner/source/Git/integration/commit/push/cloud/new agent.',
    'authorization_limit': 'No FIFO7, rerun, extra compile, cause/equivalence/removal/live/production proof or closure; HOLD.',
    'publication_state': 'Outside repo; parent verification and exact docs copy pending after NSG publication.',
})
write_bytes(DOCS / 'SHA256SUMS', ''.join(sha(path) + '  ' + path.name + '\n'
                                      for path in sorted(DOCS.iterdir()) if path.is_file()).encode())
for line in (DOCS / 'SHA256SUMS').read_text().splitlines():
    expected, member = line.split('  ', 1)
    assert sha(DOCS / member) == expected
assert (DOCS / 'evidence.tar.gz').read_bytes() == (ROOT / 'packet.tar.gz').read_bytes()
print(json.dumps({'docs': str(DOCS), 'archive': str(ROOT / 'packet.tar.gz'),
                  'archive_sha256': digest(archive_bytes), 'archive_bytes': len(archive_bytes),
                  'archive_members': len(archive_members), 'input_groups': groups,
                  'retained_original_bindings': 292, 'watched_bindings': len(watched),
                  'verification_sha256': sha(ROOT / 'archive-verification.json'),
                  'docs_package_sha256': sha(DOCS / 'package.json'),
                  'docs_SHA256SUMS_sha256': sha(DOCS / 'SHA256SUMS'), 'disposition': 'HOLD'}))
