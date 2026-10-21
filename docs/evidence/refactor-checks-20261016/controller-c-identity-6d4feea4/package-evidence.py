from pathlib import Path, PurePosixPath
import subprocess, hashlib, json, io, tarfile, gzip
D=Path(__file__).resolve().parent
W=Path('/tmp/ts-refactor-controller-c-identity-6ba')
REL='docs/evidence/refactor-checks-20261016/controller-c-identity-6d4feea4'
DOC=W/REL
DONOR='dbe85687fea737bfe3ea34686f94a677e92d50f7'
TREE='629a72fad5e642c29f62f6cf351f560fd0674073'
PARENT='6ba1a3108750f984ab4b01eaa485fea71cccb490'
QUALIFIED='6d4feea434d74e0f344fc7f9ab9bba9ed1e15080'
ROOTS={
 'plan/identity-supplement-v2':Path('/tmp/ts-app-controller-c-identity-supplement-ba75-v2'),
 'source/original-71d':Path('/tmp/ts-controller-c-identity-source-71d57d85'),
 'source/adopted-2eb':Path('/tmp/ts-controller-c-identity-source-2eb98358'),
 'source/adopted-6d-draft':Path('/tmp/ts-controller-c-identity-source-6d4feea4'),
 'source/adopted-6d-v2':Path('/tmp/ts-controller-c-identity-source-6d4feea4-v2'),
 'source/adopted-dbe':Path('/tmp/ts-controller-c-identity-adoption-6ba-dbe85687'),
 'compile/v3-request':Path('/tmp/ts-controller-c-identity-compile-request-6d4feea4-v3'),
 'compile/v3-zero-Go-setup-failure':Path('/tmp/ts-controller-c-identity-default-compile-stop-6d4feea4-v3'),
 'compile/v4-request':Path('/tmp/ts-controller-c-identity-compile-request-6d4feea4-v4'),
 'compile/v4-PASS':Path('/tmp/ts-controller-c-identity-default-compile-6d4feea4-v4'),
 'runtime/default-request':Path('/tmp/ts-controller-c-identity-default-runtime-request-6d4feea4-v1'),
 'runtime/default-PASS':Path('/tmp/ts-controller-c-identity-default-runtime-6d4feea4-v1'),
 'runtime/driver-request':Path('/tmp/ts-controller-c-identity-driver-runtime-request-6d4feea4-v1'),
 'runtime/driver-PASS':Path('/tmp/ts-controller-c-identity-driver-runtime-6d4feea4-v1'),
 'runtime/tagged-request':Path('/tmp/ts-controller-c-identity-tagged-owner-request-6d4feea4-v1'),
 'runtime/tagged-PASS':Path('/tmp/ts-controller-c-identity-tagged-owner-6d4feea4-v1')}
QAS={
 '/tmp/ts-qa-controller-c-adoption-review-6d4feea4-c9216570.json':'991cc4f76bbc883a2371628c647b66a37f6c0a945d60e539ac3bc32dbdde4630',
 '/tmp/ts-qa-controller-c-compile-request-review-6d4feea4-d3e2e2b4.json':'40e2f811a41bff54b8282a141085d615845045fcf0ed1fe47498e203bd8c0401',
 '/tmp/ts-qa-controller-c-compile-request-review-v4-6d4feea4-93200d38.json':'bd847c5d13e8b9d06a68e638c7ba085585da3530a7b97ba3f7c5792b70d380b8',
 '/tmp/ts-qa-controller-c-default-compile-review-6d4feea4-491ec1c3.json':'b2699b2702c0c325149cfc767e843b5e71818b462106dd519489403013fd015f',
 '/tmp/ts-qa-controller-c-default-runtime-request-review-6d4feea4-e49bd5ae.json':'3e0c274c7d0441410703380e9d8a79f287d4915b16d76de619ffdb8c38f625d8',
 '/tmp/ts-qa-controller-c-default-runtime-review-6d4feea4-a2250bbc.json':'227dd60507e81340eaae6e244e57c8b965ed92218169ee3037eb6c1e97c19bc7',
 '/tmp/ts-qa-controller-c-driver-runtime-request-review-6d4feea4-e1d550b6.json':'63a99954b42628604279cd1e88931a9af471a70bd9000b44f5cd9425517324cf',
 '/tmp/ts-qa-controller-c-driver-runtime-review-6d4feea4-c67a996c.json':'1f7d2eaf79af18f5b24fc132b2975c9e611a6932985d58e0a72459fc4a895eee',
 '/tmp/ts-qa-controller-c-tagged-owner-request-review-6d4feea4-6cafdeb0.json':'56ba08cfdca4c46c55ce62b466eb5f5b1348655757f15db22b3ad71a75492515',
 '/tmp/ts-qa-controller-c-tagged-owner-runtime-review-6d4feea4-d402c4d9.json':'d40f15237dc01148e8870e344b3da2f00a2c41b5d68406e769145e5bf8e3d96c',
 '/tmp/ts-qa-controller-c-adoption-review-dbe85687-060107db.json':'18ecd76c8c234f1fd43af49f7898904a52aa8d10465addbe1608ce48c8b7d2b2'}
SOURCE_REVIEW=Path('/tmp/ts-qa-controller-c-source-review-2eb98358-20261017T003633Z-4763d377.json')
OMIT=ROOTS['compile/v4-PASS']/'fixturegen.test'

def sha(data): return hashlib.sha256(data).hexdigest()
def jb(obj): return (json.dumps(obj,indent=2)+'\n').encode()
def write(path,data):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('xb') as f: f.write(data)
def info(path):
 s=path.stat();return {'path':str(path),'sha256':sha(path.read_bytes()),'bytes':s.st_size,'mode':s.st_mode,'mtime_ns':s.st_mtime_ns}
def git(*args): return subprocess.check_output(['/run/current-system/sw/bin/git','-C',str(W),*args])
def identity():
 assert git('rev-parse','HEAD').decode().strip()==DONOR
 assert git('rev-parse','HEAD^{tree}').decode().strip()==TREE
 assert git('rev-parse','HEAD^').decode().strip()==PARENT
 assert not git('diff','--binary') and not git('diff','--cached','--binary')
 claims=json.loads((ROOTS['source/adopted-dbe']/'adoption-proof.json').read_text())['exact_eighteen_source_bindings']
 for row in claims: assert sha((W/row['path']).read_bytes())==row['sha256']
 return {'head':DONOR,'tree':TREE,'parent':PARENT,'index_sha256':sha(git('ls-files','--stage')),'claimed_eighteen':claims,'tracked_diff_empty':True,'staged_diff_empty':True}
assert not DOC.exists() and not (D/'packet').exists() and not git('status','--porcelain')
pre=identity();inputs=[]
for prefix,root in ROOTS.items():
 for path in sorted(root.rglob('*')):
  if path.is_dir():continue
  assert path.is_file() and not path.is_symlink()
  inputs.append({'archive_relative_path':prefix+'/'+path.relative_to(root).as_posix(),'original':info(path),'omit_binary':path==OMIT})
 if (root/'SHA256SUMS').is_file():
  for line in (root/'SHA256SUMS').read_text().splitlines():
   h,n=line.split('  ',1);assert sha((root/n).read_bytes())==h
for filename,expected in QAS.items():
 path=Path(filename);assert sha(path.read_bytes())==expected
 inputs.append({'archive_relative_path':'qa/'+path.name,'original':info(path),'omit_binary':False})
for name,path in [('qa/'+SOURCE_REVIEW.name,SOURCE_REVIEW),('probe/standalone-key-only-probe.json',Path('/tmp/ts-controller-c-identity-python-env-probe-6d4feea4-v3.json'))]:
 inputs.append({'archive_relative_path':name,'original':info(path),'omit_binary':False})
assert sum(i['omit_binary'] for i in inputs)==1
binary=info(OMIT);assert binary['sha256']=='dabff8a3328ce8211874b17d1d48286eca33df1909604957486f6ca069727535' and binary['bytes']==73433201
PACKET=D/'packet';PACKET.mkdir()
for item in inputs:
 if not item['omit_binary']:write(PACKET/item['archive_relative_path'],Path(item['original']['path']).read_bytes())
for prefix in ['source/original-71d','source/adopted-2eb','source/adopted-6d-draft','source/adopted-6d-v2']:
 assert sha((PACKET/prefix/'patch.diff').read_bytes())=='d39bc272e6d7aeb4ea570ef920353f37b2151dd0fdb6b0ec4dbedec83024c65d'
assert sha((PACKET/'source/adopted-6d-v2/patch-full-index.diff').read_bytes())=='b68e9834a2d26af58ecd0a02bd706e4d67820e77f2b8aed8683a147a9893969f'
omission={'original_binary':binary,'compiled_binary_invoked':False,'bytes_intentionally_omitted':True,'original_retained':True,'reason':'Archive excludes compiled binary bytes only. Original compile manifests/receipts/SHA256SUMS remain byte-for-byte, including their binary hash and size. Runtime go test generated/executed its own temporary binaries.','original_manifest_archive_member':'packet/compile/v4-PASS/manifest.json','original_receipt_archive_member':'packet/compile/v4-PASS/receipt.json'}
write(PACKET/'omitted-binary.json',jb(omission))
README=f'''# Controller-c external-seed packet identity

Qualified source `{QUALIFIED}`, tree `02bf1ec703c2591b37f7b0be99d6e71256a3e2f3`, parent `cc09b45a359812136c737682bc1fbe923c724c1f`. Source donor `{DONOR}`, tree `{TREE}`, parent `{PARENT}`, mechanically adopts exactly the same eighteen files after eight vendor evidence docs. All eighteen modes/blobs/bytes and all 2,420 Go/module entries equal the qualified source. Receipts retain their original qualified identity; no rerun on the donor is claimed.

The fixed signed packet is controller-a/controller-b/controller-c. Controller-c is the sole external seed at 10.44.0.10; controller-a/b remain managed peers at .11/.12. Production naming maps c to gru-1-ctl-3 while logical broker identity stays controller-c. Existing public signed ledger/plan/receipt/floor producers regenerate the packet. Extracted accepted markers, scoped broker credentials, simulator identities and exact SDK socket responses are checked. Generic seed-a fixtures remain generic; SDK and both observer helper blobs remain equal to exact F2ba75. Nine non-test changes are identity substitutions only.

One compile-only PASS on qualified6d took131.653s. Its 73,433,201-byte binary, SHA256 dabff8a3328ce8211874b17d1d48286eca33df1909604957486f6ca069727535, was never invoked; bytes are omitted with original manifests/hash/size retained. Before that, v3 stopped at the wrapper environment assertion with zero Go: system Python is a mise launcher that added13 environment keys including GOROOT and changed PATH. The permitted harmless key-only probe showed direct Python3.15.0-I-B preserved the exact six-key environment. The failed wrapper, raw terminal, probe and corrected v4 request remain unchanged.

Independent QA accepted all three exact runtime lanes once: default fixturegen sixteen roots/eighteen subcases (34 unique named passes,11.374s, twelve fresh SDK response-hash witnesses and three controller marker/JWT/simulator messages); qualification driver six roots/fourteen subcases (20 named passes,3.340s, fake system commands and one loopback UDP cleanup-counter socket); fixturetest owner one root/ten existing subcases (11 named passes,60.331s). The tagged raw JSON contains59 fresh socket response-hash records:24 on the owning path (eight per slot for SDK and production observer) plus35 across ten subcases; nine are independent rejections and one checks observational create-key behavior. All three positive slot observers remain. There were no skipped, extra, missing or failed named cases. Counts are from the new raw JSON and pinned source assertions; historical F2ba75/lower582/92e receipts remain separate.

Every actual lane used direct pinned Go1.27.1 and Python3.15.0-I-B, env-i with HOME/LANG/PATH/GOMAXPROCS/GOFLAGS/GOTOOLCHAIN only, nice19, a nonblocking shared gate lock, outer180s TERM/kill-after5s and test120s. Default and tagged owning calls statically select two and one nested jwtsetup go runs respectively, inheriting pinned PATH and priority; child process counts were not independently instrumented. The offline issuer was excluded. Compile binary bytes were never directly executed. Raw JSON, stderr, actual broker sessions/terminal exits, wrappers/argv/env, pre/post source/executable/predecessor hashes, requests, receipts and all twelve original QA reviews are archived without editing.

This qualifies the synthetic signed-packet/SDK-custom-transport/observer and unit-driver identity contract. It does not qualify the production default SDK constructor, Oracle-issued JWT authority, private IAM/current Foundation/HomeIAM, live Vault/material/ownhost enrollment, native VM/systemd/containerd/registry paths or full ownhost service activation. No-task/no-pull under always-on reconciliation remains UNPROVEN: real signed spec/current allocation/DATA-hold evidence and a measured native observation window are still required. No features/reconcilers were disabled. Full global migration closure, race/full-package/short variants and unrelated tests remain unqualified.

The deterministic archive retains all original source/adoption packets (including superseded drafts), both patch formats distinctly (original abbreviated-index binary patch d39bc272…48114bytes; full-index binary patch b68e9834…49230bytes), source hashes and copied eighteen donor files, setup failure/key-only probe, compile and three runtime requests/receipts/raw events/broker records, before/after proofs and QA reviews. Original manifests remain historical, including the deliberately omitted binary entry. Packaging adds docs only; it does not stage/commit docs, change source/index, invoke Go, integrate/push, touch main/shared feature, or run cloud/native/host services. QA owns publication.
'''
write(PACKET/'README.md',README.encode());write(PACKET/'packaging/package-evidence.py',Path(__file__).read_bytes())
provenance={'qualified_source':QUALIFIED,'qualified_tree':'02bf1ec703c2591b37f7b0be99d6e71256a3e2f3','qualified_parent':'cc09b45a359812136c737682bc1fbe923c724c1f','source_donor':DONOR,'source_donor_tree':TREE,'source_donor_parent':PARENT,'adoption_proof_sha256':sha((ROOTS['source/adopted-dbe']/'adoption-proof.json').read_bytes()),'original_inputs':inputs,'original_input_count':len(inputs),'original_files_archived':len(inputs)-1,'omitted_binary':omission,'QA_review_count':12,'patches':{'original_abbreviated_binary_patch':{'sha256':'d39bc272e6d7aeb4ea570ef920353f37b2151dd0fdb6b0ec4dbedec83024c65d','bytes':48114},'full_index_binary_patch':{'sha256':'b68e9834a2d26af58ecd0a02bd706e4d67820e77f2b8aed8683a147a9893969f','bytes':49230}},'tar_policy':{'format':'USTAR','sorted_names':True,'regular_only':True,'mode':'0644','uid':0,'gid':0,'uname':'','gname':'','mtime':0},'gzip_policy':{'filename':'','mtime':0,'compresslevel':9},'manifest_policy':'MEMBERS excludes itself and SHA256SUMS; internal SHA256SUMS covers all other members including MEMBERS; external package.json inventories every archive member. No circular hashes.','packaging_script':info(Path(__file__)),'scope':'Docs-only after authorized mechanical donor source commit; no new Go/runtime/source/index/sharedbranch/push/cloud/host actions; docs untracked'}
write(PACKET/'provenance.json',jb(provenance))
payload=sorted(p for p in PACKET.rglob('*') if p.is_file());write(PACKET/'MEMBERS.json',jb({'members':[{'name':p.relative_to(PACKET).as_posix(),'sha256':sha(p.read_bytes()),'bytes':p.stat().st_size} for p in payload],'excludes':['MEMBERS.json','SHA256SUMS']}))
write(PACKET/'SHA256SUMS',''.join(sha(p.read_bytes())+'  '+p.relative_to(PACKET).as_posix()+'\n' for p in sorted(PACKET.rglob('*')) if p.is_file()).encode())
files=sorted(p for p in PACKET.rglob('*') if p.is_file())
def tar_bytes():
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode='w',format=tarfile.USTAR_FORMAT) as tf:
  for p in files:
   data=p.read_bytes();m=tarfile.TarInfo('packet/'+p.relative_to(PACKET).as_posix());m.size=len(data);m.mode=0o644;m.uid=m.gid=0;m.uname=m.gname='';m.mtime=0;tf.addfile(m,io.BytesIO(data))
 return out.getvalue()
def zip_bytes(data):
 out=io.BytesIO()
 with gzip.GzipFile(fileobj=out,mode='wb',filename='',mtime=0,compresslevel=9) as f:f.write(data)
 return out.getvalue()
tar=tar_bytes();gz=zip_bytes(tar);assert tar_bytes()==tar and zip_bytes(tar)==gz and gzip.decompress(gz)==tar
inventory=[]
with tarfile.open(fileobj=io.BytesIO(gz),mode='r:gz') as tf:
 for m in tf.getmembers():
  name=PurePosixPath(m.name);assert m.isfile() and not name.is_absolute() and '..' not in name.parts and name.parts[0]=='packet'
  assert (m.mode,m.mtime,m.uid,m.gid,m.uname,m.gname)==(0o644,0,0,0,'','')
  data=tf.extractfile(m).read();assert data==(PACKET/Path(*name.parts[1:])).read_bytes();inventory.append({'name':m.name,'bytes':len(data),'sha256':sha(data)})
assert not any(m['name'].endswith('/fixturegen.test') for m in inventory)
for item in inputs:assert info(Path(item['original']['path']))==item['original']
post=identity();assert pre==post
verification={'regular_safe_members_only':True,'member_count':len(inventory),'every_member_matches_payload':True,'tar_rebuild_byte_equal':True,'gzip_rebuild_byte_equal':True,'gzip_roundtrip_exact':True,'compiled_binary_bytes_omitted':True,'all_original_inputs_unchanged':True,'source_and_index_unchanged':True}
package={'qualified_source':QUALIFIED,'source_donor':DONOR,'donor_tree':TREE,'donor_parent':PARENT,'archive_sha256':sha(gz),'archive_bytes':len(gz),'uncompressed_tar_sha256':sha(tar),'uncompressed_tar_bytes':len(tar),'archive_member_count':len(inventory),'archive_members':inventory,'verification':verification,'pre_identity':pre,'post_identity':post,'omitted_binary':omission,'original_input_count':len(inputs),'QA_review_count':12,'publication_state':'untracked docs only; QA owns shared feature integration/push'}
DOC.mkdir(parents=True)
for name,data in {'README.md':README.encode(),'evidence.tar.gz':gz,'package.json':jb(package),'provenance.json':jb(provenance),'package-evidence.py':Path(__file__).read_bytes(),'adoption-proof.json':(ROOTS['source/adopted-dbe']/'adoption-proof.json').read_bytes(),'archive-verification.json':jb(verification)}.items():write(DOC/name,data)
write(DOC/'SHA256SUMS',''.join(sha(p.read_bytes())+'  '+p.name+'\n' for p in sorted(DOC.iterdir()) if p.is_file()).encode())
expected=[REL+'/'+p.name for p in sorted(DOC.iterdir())];assert git('ls-files','--others','--exclude-standard').decode().splitlines()==expected
assert identity()==pre
for item in inputs:assert info(Path(item['original']['path']))==item['original']
report={'state':'SOURCE_DONOR_CLEAN_DOCS_UNTRACKED_HOLD','source_donor':DONOR,'tree':TREE,'parent':PARENT,'worktree':str(W),'branch':'refactor/qa-controller-c-identity-6ba','docs_directory':str(DOC),'untracked_docs':expected,'staged_files':[],'archive_sha256':sha(gz),'archive_bytes':len(gz),'archive_member_count':len(inventory),'package_json_sha256':sha((DOC/'package.json').read_bytes()),'provenance_sha256':sha((DOC/'provenance.json').read_bytes()),'docs_SHA256SUMS_sha256':sha((DOC/'SHA256SUMS').read_bytes()),'original_inputs_unchanged':True,'omitted_binary_sha256':binary['sha256'],'omitted_binary_bytes':binary['bytes'],'tracked_and_index_diff_empty':True,'no_new_Go_runtime_push_cloud':True,'docs_file_inventory':[info(p) for p in sorted(DOC.iterdir())]}
write(D/'PACKAGING-REPORT.json',jb(report));print(json.dumps({k:v for k,v in report.items() if k!='docs_file_inventory'},indent=2))
