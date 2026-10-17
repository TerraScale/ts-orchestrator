from pathlib import Path,PurePosixPath
import subprocess,hashlib,json,io,tarfile,gzip
D=Path(__file__).resolve().parent;W=Path('/tmp/ts-nsg-retirement-c3e6ff75-u6pxzh0x');REL='docs/evidence/refactor-checks-20261016/nsg-retirement-c63524c7';DOC=W/REL;PACKET=D/'packet'
HEAD='c63524c786521aba2ef5d5d68505d7165b32b4e8';TREE='b13a0feed004969d4ab07cb55e4cc9b7544f3056';PARENT='c3e6ff7510f1233b3973bb266da4c0f138a67f90'
ROOTS={'source-proof':Path('/tmp/ts-nsg-retirement-source-c3e6ff75-u6pxzh0x'),'compile':Path('/tmp/ts-nsg-retirement-compile-request-c63524c7-kq0mqay6'),'broker':Path('/tmp/ts-nsg-retirement-compile-broker-c63524c7-qj9g3h4s')}
QAS={'source-review':('/tmp/ts-qa-nsg-retirement-source-review-c63524c7-021bc540.json','2b10044aa279caa9d8bc4722403b96f7199467a41c171a012c42f5a52292b47a'),'request-review':('/tmp/ts-qa-nsg-retirement-compile-request-review-c63524c7-1a57eb61.json','c294c03ff73606a252333f933ec370fadcf17b806a27989be5ad1007453ac312'),'compile-review':('/tmp/ts-qa-nsg-retirement-compile-review-c63524c7-21655e61.json','6375918a20b227eb5db701ca8026ea2bcfbcb3f00d1d66e7fd1aeb2f875f1aed')}
KNOWN={ROOTS['source-proof']/'artifact-manifest.json':'810f68b894c7ff2f5ffe6cfccb91e08e71bb023fdf59947dc3f9ebfdf6c5cdaf',ROOTS['compile']/'artifact-manifest.json':'2accff7f689e267aa2c8303780da11ef3fe5e940b9ee714112300d3835ac5081',ROOTS['compile']/'output/artifact-manifest.json':'6c410cf51068b5f085c3ba2511e02fcee2349838e7e28a511ec27be179eafe50',ROOTS['broker']/'artifact-manifest.json':'56d846ca395a139bf04744dbc0f62645e11cadaf6a875ee1e3a95503c3152527'}
OMIT=ROOTS['compile']/'output/terrabase-default.test';UPSTREAM=W/'docs/evidence/refactor-checks-20261016/nsg-sdk-socket-e502eed6/evidence.tar.gz'
def sha(b):return hashlib.sha256(b).hexdigest()
def jb(x):return (json.dumps(x,indent=2)+'\n').encode()
def write(p,b):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('xb') as f:f.write(b)
def fi(p,metadata=False):
 p=Path(p);st=p.stat();d={'path':str(p),'size':st.st_size,'sha256':sha(p.read_bytes())}
 if metadata:d.update(mode=st.st_mode,mtime_ns=st.st_mtime_ns)
 return d
def git(*a):return subprocess.check_output(['git',*a],cwd=W)
def identity():
 assert git('rev-parse','HEAD').decode().strip()==HEAD and git('rev-parse','HEAD^{tree}').decode().strip()==TREE and git('show','-s','--format=%P','HEAD').decode().strip()==PARENT
 assert git('diff','--binary')==b'' and git('diff','--cached','--binary')==b''
 proof=json.loads((ROOTS['source-proof']/'commit-proof.json').read_text())
 assert sha((W/'internal/terrabase/oci_live_test.go').read_bytes())=='4ec96b458d4119605d24e1e04d1ef15da8e2ca9ec9fd22e21b54fe1a47e3f068'
 for b in proof['all_12_bound_files_unchanged']:assert sha((W/b['path']).read_bytes())==b['sha256'] and git('rev-parse',HEAD+':'+b['path']).decode().strip()==b['git_blob']
 return {'commit':HEAD,'tree':TREE,'parent':PARENT,'source_sha256':'4ec96b458d4119605d24e1e04d1ef15da8e2ca9ec9fd22e21b54fe1a47e3f068','index_entries_sha256':sha(git('ls-files','--stage')),'tracked_diff_empty':True,'staged_diff_empty':True,'bound_files':proof['all_12_bound_files_unchanged']}
assert not DOC.exists() and not PACKET.exists() and git('status','--porcelain=v1')==b''
pre=identity()
for path,expected in KNOWN.items():
 assert sha(path.read_bytes())==expected
 for item in json.loads(path.read_text())['artifacts']:
  b=Path(item['path']).read_bytes();assert sha(b)==item['sha256'] and len(b)==item.get('size',item.get('bytes'))
inputs=[]
for prefix,root in ROOTS.items():
 for q in sorted(root.rglob('*')):
  if q.is_dir():continue
  assert q.is_file() and not q.is_symlink();inputs.append({'archive_relative_path':prefix+'/'+q.relative_to(root).as_posix(),'original':fi(q,True),'omit_binary':q==OMIT})
for name,(location,expected) in QAS.items():
 q=Path(location);assert sha(q.read_bytes())==expected;inputs.append({'archive_relative_path':'qa/'+name+'.json','original':fi(q,True),'omit_binary':False})
assert len(inputs)==53 and sum(i['omit_binary'] for i in inputs)==1
binary=fi(OMIT,True);assert binary['size']==18851569 and binary['sha256']=='a2e4d0db9ece0ca44d09a5876ec6998bf2ffc4188ac443f57919297c515cb6c9'
upstream=fi(UPSTREAM,True);assert upstream['sha256']=='3b929a819dc0f28bdf0cd375a077007ef02278edfd27d81a4199fd9fbf3390c9'
PACKET.mkdir()
for item in inputs:
 if not item['omit_binary']:write(PACKET/item['archive_relative_path'],Path(item['original']['path']).read_bytes())
assert len([q for q in PACKET.rglob('*') if q.is_file()])==52
omission={'original_binary_location':str(OMIT),'size':18851569,'sha256':binary['sha256'],'binary_bytes_omitted':True,'original_binary_retained':True,'binary_ever_executed':False,'original_manifest_member':'packet/compile/output/artifact-manifest.json','original_manifest_sha256':KNOWN[ROOTS['compile']/'output/artifact-manifest.json'],'original_receipt_member':'packet/compile/output/broker-receipt.json','reason':'Only compiled executable bytes are omitted. All original manifests and receipts retain untouched historical bytes, including the original binary entry.'}
references={'qualified_upstream_commit':'e502eed69cd2c020448b94c6970d9bacd8942cd8','archive':upstream,'published_archive_repo_relative_path':'docs/evidence/refactor-checks-20261016/nsg-sdk-socket-e502eed6/evidence.tar.gz','full_upstream_archive_duplicated':False,'selective_upstream_copies':'Already-retained source proof includes selected unchanged earlier source/compile/runtime/raw/QA evidence; preserved exactly.','runtime_receipt_sha256':'628c0800ba1c6ddcdea73bbe46ea1ff6ad44eda712f37849727fc6265976ae66','runtime_raw_sha256':'c9487c0dfa9b64f95bd6a0bdb30565558ffdd19424beab1371f5c4c163d64fea','runtime_QA_sha256':'fc3131b7428c6b37225a91e3a5ccaa529118bde9888b03598165d5829776e009','root':'TestPeerPortOpenThroughSDKObservedHosts','leaves':['cidr','nsg','destination_miss','sender_nsg_miss','sender_cidr_miss'],'successful_GETs':35,'ordered_assessments':10,'run_repeated':False,'source_declaration_preserved_byte_identical':True,'literal_nil_sender_groups_note':'Original CIDR denial supplied nil groups; accepted SDK sender_cidr_miss supplies groupB. CIDR branch ignores sender groups, so the rejection semantic is covered; literal nil-input runtime execution is not proved.'}
README='''# Isolated NSG declaration retirement

Qualified retirement source `c63524c786521aba2ef5d5d68505d7165b32b4e8`, tree `b13a0feed004969d4ab07cb55e4cc9b7544f3056`, sole parent `c3e6ff7510f1233b3973bb266da4c0f138a67f90`. The sole source change removes `TestPeerPortOpen` and its following blank: 24 lines / 1,224 bytes, zero additions. Every remaining byte in `internal/terrabase/oci_live_test.go` matches parent, including imports/types, live regional and lifecycle logic, `peerPortOpen`, `liveEnv`, `observePeerIngress`, and the complete five-case SDK root. Every other tracked source entry is unchanged.

The one granted default terrabase compile passed (exit 0, 38.275882 seconds). Exact pins, six-key isolated environment, direct Python3.15 -I -B, low CPU priority, nonblocking gate, timeout and source/executable prepost checks are retained. Actual broker tool launch/ongoing/terminal observations were written immediately. The 18,851,569-byte compiled binary was never executed and its bytes are omitted; its exact SHA256, original location, receipt and untouched original manifest binary entry remain.

All five retired semantic invariants map to the previously accepted `e502eed6` SDK runtime: five serial leaves, 35 successful local HTTP GET exchanges and ten ordered allow/deny assessments. That runtime was not repeated. The published e502 archive is referenced by exact SHA256, not duplicated in full; selected earlier evidence already present in the original source proof is retained unchanged. The original CIDR-denial call used nil sender groups, whereas SDK `sender_cidr_miss` uses groupB. The CIDR branch does not read groups: semantic rejection coverage is retained, literal nil-input runtime execution is not proved. NSG token equality/mismatch semantics use OCI-like identities in the retained cases.

This permits retirement of this isolated declaration only. SDK signature header structure is covered, not cryptographic verification. Local static ingress observation does not qualify live OCI/real-host acceptance, actual peer TCP/egress/routes/security lists/listeners, replication or F3. One-page list traversal and source-port/Direction/IsValid/IsStateless limitations remain. Short/tagged/race/full-package execution and global/central migration closure remain OPEN.

The archive preserves original source/proposal/mapping/preservation proofs, sealed request/wrapper/HOLD snapshot, compile log/prepost/receipt/manifests, actual broker observations and source/request/compile QA reviews. Historical HOLD/source-only records retain their original bytes; later compile QA supplies acceptance without rewriting them. Only retained binary bytes are omitted. All original packets remain untouched. Archive members are safe sorted regular files with normalized metadata, per-member SHA256 and deterministic tar/gzip rebuilds (gzip mtime 0, level 9). Packaging creates only these untracked docs; no Go/runtime, source/index edit, stage, commit, integration, push, host or cloud operation occurs.
'''
write(PACKET/'README.md',README.encode());write(PACKET/'omitted-binary.json',jb(omission));write(PACKET/'upstream-references.json',jb(references));write(PACKET/'packaging/package-evidence.py',Path(__file__).read_bytes())
prov={'candidate':HEAD,'tree':TREE,'parent':PARENT,'original_input_count_including_binary':53,'original_files_archived':52,'inputs':inputs,'omitted_binary':omission,'published_upstream':references,'packaging_script':fi(__file__),'operation_scope':'Docs-only; all prior inputs preserved; no Go/runtime/source/index/stage/commit/integration/push/host/cloud/new agents.','tar_policy':{'format':'USTAR','sorted':True,'regular_files_only':True,'mode':'0644','uid':0,'gid':0,'uname':'','gname':'','mtime':0},'gzip_policy':{'filename':'','mtime':0,'compresslevel':9},'manifest_policy':'MEMBERS describes all payload excluding itself and SHA256SUMS. SHA256SUMS covers every member except itself, including MEMBERS. External package.json enumerates every archive member.'}
write(PACKET/'provenance.json',jb(prov))
payload=sorted(q for q in PACKET.rglob('*') if q.is_file());assert len(payload)==57
write(PACKET/'MEMBERS.json',jb({'members':[{'path':q.relative_to(PACKET).as_posix(),'size':q.stat().st_size,'sha256':sha(q.read_bytes())} for q in payload],'excludes':['MEMBERS.json','SHA256SUMS']}))
write(PACKET/'SHA256SUMS',''.join(sha(q.read_bytes())+'  '+q.relative_to(PACKET).as_posix()+'\n' for q in sorted(PACKET.rglob('*')) if q.is_file()).encode())
files=sorted(q for q in PACKET.rglob('*') if q.is_file());assert len(files)==59

def tarbytes():
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode='w',format=tarfile.USTAR_FORMAT) as tf:
  for q in files:
   data=q.read_bytes();t=tarfile.TarInfo('packet/'+q.relative_to(PACKET).as_posix());t.size=len(data);t.mode=0o644;t.uid=t.gid=t.mtime=0;t.uname=t.gname='';tf.addfile(t,io.BytesIO(data))
 return out.getvalue()
def gzbytes(tar):
 out=io.BytesIO()
 with gzip.GzipFile(fileobj=out,mode='wb',filename='',compresslevel=9,mtime=0) as g:g.write(tar)
 return out.getvalue()
tar=tarbytes();gz=gzbytes(tar);assert tarbytes()==tar and gzbytes(tar)==gz and gzip.decompress(gz)==tar and gz[4:8]==b'\0\0\0\0' and gz[8]==2
write(D/'packet.tar',tar);write(D/'packet.tar.gz',gz);inventory=[]
with tarfile.open(fileobj=io.BytesIO(gz),mode='r:gz') as tf:
 assert len(tf.getmembers())==59
 for t in tf.getmembers():
  path=PurePosixPath(t.name);assert t.isfile() and not path.is_absolute() and '..' not in path.parts and path.parts[0]=='packet'
  assert (t.mode,t.uid,t.gid,t.mtime,t.uname,t.gname)==(0o644,0,0,0,'','')
  data=tf.extractfile(t).read();assert data==(D/t.name).read_bytes();inventory.append({'name':t.name,'size':len(data),'sha256':sha(data),'mode':t.mode,'uid':t.uid,'gid':t.gid,'mtime':t.mtime,'uname':t.uname,'gname':t.gname})
assert all(not t['name'].endswith('terrabase-default.test') for t in inventory)
for item in inputs:assert fi(item['original']['path'],True)==item['original']
assert fi(UPSTREAM,True)==upstream and identity()==pre
package={'candidate':HEAD,'qualified_commit':HEAD,'qualified_tree':TREE,'sole_parent':PARENT,'archive_path':str(D/'packet.tar.gz'),'archive_sha256':sha(gz),'archive_bytes':len(gz),'uncompressed_tar_sha256':sha(tar),'uncompressed_tar_bytes':len(tar),'archive_member_count':59,'archive_members':inventory,'deterministic_tar_rebuild_byte_equal':True,'deterministic_gzip_rebuild_byte_equal':True,'gzip_roundtrip_exact_bytes':True,'every_member_matches_original_or_new_packet':True,'safe_regular_members_only':True,'MEMBERS_sha256':sha((PACKET/'MEMBERS.json').read_bytes()),'root_SHA256SUMS_sha256':sha((PACKET/'SHA256SUMS').read_bytes()),'input_inventory':inputs,'original_inputs_53_unchanged':True,'original_files_archived':52,'omitted_binary':omission,'original_binary_untouched':binary,'upstream_references':references,'QA_reviews':{k:{'path':v[0],'sha256':v[1]} for k,v in QAS.items()},'pre_identity':pre,'post_identity':identity(),'packaging_script':fi(__file__),'publication_state':'Untracked docs only; parent QA/publication pending.','no_Go_runtime_source_index_stage_commit_integration_push_host_cloud_new_agents':True}
write(D/'PACKAGE.json',jb(package));DOC.mkdir()
for name,data in {'README.md':README.encode(),'evidence.tar.gz':gz,'package.json':jb(package),'provenance.json':jb(prov),'package-evidence.py':Path(__file__).read_bytes()}.items():write(DOC/name,data)
write(DOC/'SHA256SUMS',''.join(sha(q.read_bytes())+'  '+q.name+'\n' for q in sorted(DOC.iterdir()) if q.is_file()).encode())
expected=[REL+'/'+n for n in sorted(['README.md','SHA256SUMS','evidence.tar.gz','package-evidence.py','package.json','provenance.json'])];actual=git('ls-files','--others','--exclude-standard').decode().splitlines();assert actual==expected and identity()==pre
for item in inputs:assert fi(item['original']['path'],True)==item['original']
assert fi(UPSTREAM,True)==upstream
report={'state':'DOCS_PACKAGED_UNTRACKED_HOLD','evidence_directory':str(D),'docs_directory':str(DOC),'head':HEAD,'tree':TREE,'parent':PARENT,'archive_sha256':sha(gz),'archive_bytes':len(gz),'uncompressed_tar_sha256':sha(tar),'uncompressed_tar_bytes':len(tar),'archive_member_count':59,'archived_original_files':52,'input_count_with_omitted_binary':53,'all_inputs_and_upstream_preserved':True,'binary_bytes_omitted_only':True,'staged_files':[],'untracked_files':expected,'packaging_script':fi(__file__),'docs_files':[fi(q) for q in sorted(DOC.iterdir())],'tracked_source_and_index_unchanged':True,'no_runner_or_commit':True}
write(D/'PACKAGING-REPORT.json',jb(report));print(json.dumps(report,indent=2))
